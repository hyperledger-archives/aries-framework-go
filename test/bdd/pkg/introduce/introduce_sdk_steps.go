/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/DATA-DOG/godog"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/client/introduce"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	introduceService "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/introduce"
	"github.com/hyperledger/aries-framework-go/test/bdd/agent"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	bddDIDExchange "github.com/hyperledger/aries-framework-go/test/bdd/pkg/didexchange"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/didresolver"
)

// SDKSteps is steps for introduce using client SDK
type SDKSteps struct {
	bddContext      *context.BDDContext
	didExchangeSDKS *bddDIDExchange.SDKSteps
	clients         map[string]*introduce.Client
	actions         map[string]chan service.DIDCommAction
	events          map[string]chan service.StateMsg
}

// NewIntroduceSDKSteps creates steps for introduce with SDK
func NewIntroduceSDKSteps(ctx *context.BDDContext) *SDKSteps {
	return &SDKSteps{
		bddContext: ctx,
		clients:    make(map[string]*introduce.Client),
		actions:    make(map[string]chan service.DIDCommAction),
		events:     make(map[string]chan service.StateMsg),
	}
}

// RegisterSteps registers agent steps
func (a *SDKSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^"([^"]*)" creates introduce client with an invitation$`, a.createIntroduceClientWithInvitation)
	s.Step(`^"([^"]*)" sends introduce proposal to the "([^"]*)" and "([^"]*)"$`, a.sendProposal)
	s.Step(`^"([^"]*)" sends introduce proposal to the "([^"]*)" with "([^"]*)" invitation$`, a.sendProposalWithInvitation)
	s.Step(`^"([^"]*)" sends introduce request to the "([^"]*)" asking about "([^"]*)"$`, a.sendRequest)
	s.Step(`^"([^"]*)" sends introduce proposal back to the "([^"]*)" and requested introduce$`, a.handleRequest)
	s.Step(`^"([^"]*)" sends introduce proposal back to the requester with pub invitation$`, a.handleRequestWithInvitation)
	s.Step(`^"([^"]*)" wants to know "([^"]*)" and sends introduce response with approve$`, a.checkAndContinue)
	s.Step(`^"([^"]*)" doesn't want to know "([^"]*)" and sends introduce response$`, a.checkAndStop)
	s.Step(`^"([^"]*)" continue with the introduce protocol$`, a.continueWithProtocol)
	s.Step(`^"([^"]*)" forwards`, a.continueWithProtocol)
	s.Step(`^"([^"]*)" stops the introduce protocol$`, a.stopProtocol)
	s.Step(`^"([^"]*)" checks the history of introduce protocol events "([^"]*)"`, a.checkHistoryEvents)
	s.Step(`^"([^"]*)" exchange DIDs with "([^"]*)"$`, a.createConnections)
	s.Step(`^"([^"]*)" and "([^"]*)" exchange DIDs$`, a.connectionEstablished)
}

func (a *SDKSteps) connectionEstablished(agent1, agent2 string) error {
	if err := a.didExchangeSDKS.ApproveRequest(agent1); err != nil {
		return err
	}

	if err := a.didExchangeSDKS.ApproveRequest(agent2); err != nil {
		return err
	}

	return a.didExchangeSDKS.WaitForPostEvent(agent2+","+agent1, "completed")
}

func (a *SDKSteps) createConnections(introducees, introducer string) error {
	const (
		inboundHost     = "localhost"
		inboundPort     = "random"
		endpointURL     = "${SIDETREE_URL}"
		acceptDidMethod = "sidetree"
	)

	participants := introducees + "," + introducer
	agentSDK := agent.NewSDKSteps(a.bddContext)

	err := agentSDK.CreateAgentWithHTTPDIDResolver(participants, inboundHost, inboundPort, endpointURL, acceptDidMethod)
	if err != nil {
		return err
	}

	if err := didresolver.CreateDIDDocument(a.bddContext, participants, acceptDidMethod); err != nil {
		return err
	}

	a.didExchangeSDKS = bddDIDExchange.NewDIDExchangeSDKSteps(a.bddContext)

	if err := a.didExchangeSDKS.WaitForPublicDID(participants, 10); err != nil {
		return err
	}

	if err := a.didExchangeSDKS.CreateDIDExchangeClient(participants); err != nil {
		return err
	}

	if err := a.didExchangeSDKS.RegisterPostMsgEvent(participants, "completed"); err != nil {
		return err
	}

	if err := a.didExchangeSDKS.CreateInvitationWithDID(introducer); err != nil {
		return err
	}

	for _, introducee := range strings.Split(introducees, ",") {
		if err := a.didExchangeSDKS.ReceiveInvitation(introducee, introducer); err != nil {
			return err
		}

		if err := a.connectionEstablished(introducee, introducer); err != nil {
			return err
		}
	}

	return a.createIntroduceClient(participants)
}

func (a *SDKSteps) createIntroduceClient(agents string) error {
	for _, agent := range strings.Split(agents, ",") {
		if err := a.createClient(agent, &didexchange.Invitation{}); err != nil {
			return err
		}
	}

	return nil
}

func (a *SDKSteps) createIntroduceClientWithInvitation(agentID string) error {
	inv, err := a.bddContext.DIDExchangeClients[agentID].CreateInvitation(agentID)
	if err != nil {
		return err
	}

	return a.createClient(agentID, inv)
}

func (a *SDKSteps) createClient(agentID string, inv *didexchange.Invitation) error {
	const stateMsgChanSize = 10

	client, err := introduce.New(a.bddContext.AgentCtx[agentID], inv.Invitation)
	if err != nil {
		return err
	}

	if a.clients[agentID] != nil {
		if err := a.clients[agentID].UnregisterActionEvent(a.actions[agentID]); err != nil {
			return err
		}

		if err := a.clients[agentID].UnregisterMsgEvent(a.events[agentID]); err != nil {
			return err
		}
	}

	a.clients[agentID] = client
	a.actions[agentID] = make(chan service.DIDCommAction, 1)
	a.events[agentID] = make(chan service.StateMsg, stateMsgChanSize)

	if err := client.RegisterMsgEvent(a.events[agentID]); err != nil {
		return err
	}

	return client.RegisterActionEvent(a.actions[agentID])
}

func (a *SDKSteps) checkHistoryEvents(agentID, events string) error {
	for _, stateID := range strings.Split(events, ",") {
		select {
		case e := <-a.events[agentID]:
			if stateID != e.StateID {
				return fmt.Errorf("history of events doesn't meet the expectation %q != %q", stateID, e.StateID)
			}
		case <-time.After(time.Second * 1):
			return fmt.Errorf("waited for %s: history of events doesn't meet the expectation", stateID)
		}
	}

	return a.stopServices()
}

func (a *SDKSteps) stopServices() error {
	for agent := range a.bddContext.AgentCtx {
		svc, err := a.bddContext.AgentCtx[agent].Service(introduceService.Introduce)
		if err != nil {
			return err
		}

		if err := svc.(interface{ Stop() error }).Stop(); err != nil {
			if !errors.Is(err, introduceService.ErrServerWasStopped) {
				return err
			}
		}

		if err := a.bddContext.AgentCtx[agent].StorageProvider().Close(); err != nil {
			return err
		}
	}

	return nil
}

func (a *SDKSteps) checkAndStop(agentID, introduceeID string) error {
	select {
	case e := <-a.actions[agentID]:
		proposal := &introduceService.Proposal{}
		if err := e.Message.Decode(proposal); err != nil {
			return err
		}

		if proposal.To.Name != introduceeID {
			return fmt.Errorf("%q doesn't want to know %q but got %q", agentID, introduceeID, proposal.To.Name)
		}

		e.Stop(errors.New("stop the protocol"))
	case <-time.After(time.Second * 1):
		return fmt.Errorf("timeout continueWithProtocol %s", agentID)
	}

	return nil
}

func (a *SDKSteps) handleRequest(agentID, introducee string) error {
	select {
	case e := <-a.actions[agentID]:
		request := &introduceService.Request{}
		if err := e.Message.Decode(request); err != nil {
			return err
		}

		conn, err := a.getConnection(agentID, request.PleaseIntroduceTo.Name)
		if err != nil {
			return err
		}

		recipient := &introduceService.Recipient{
			To:       &introduceService.To{Name: introducee},
			MyDID:    conn.MyDID,
			TheirDID: conn.TheirDID,
		}

		to := &introduceService.To{Name: request.PleaseIntroduceTo.Name}
		// nolint: govet
		if err := a.clients[agentID].HandleRequest(e.Message, to, recipient); err != nil {
			return err
		}

		thID, err := e.Message.ThreadID()
		if err != nil {
			return err
		}

		e.Continue(a.clients[agentID].InvitationEnvelope(thID))
	case <-time.After(time.Second * 1):
		return fmt.Errorf("timeout checkAndContinue %s", agentID)
	}

	return nil
}

func (a *SDKSteps) handleRequestWithInvitation(agentID string) error {
	select {
	case e := <-a.actions[agentID]:
		request := &introduceService.Request{}
		if err := e.Message.Decode(request); err != nil {
			return err
		}

		introduceTo := request.PleaseIntroduceTo.Name

		inv, err := a.bddContext.DIDExchangeClients[introduceTo].CreateInvitation(introduceTo)
		if err != nil {
			return err
		}

		to := &introduceService.To{Name: inv.Label}
		// nolint: govet
		if err := a.clients[agentID].HandleRequestWithInvitation(e.Message, inv.Invitation, to); err != nil {
			return err
		}

		thID, err := e.Message.ThreadID()
		if err != nil {
			return err
		}

		e.Continue(a.clients[agentID].InvitationEnvelope(thID))
	case <-time.After(time.Second * 1):
		return fmt.Errorf("timeout checkAndContinue %s", agentID)
	}

	return nil
}

func (a *SDKSteps) checkAndContinue(agentID, introduceeID string) error {
	select {
	case e := <-a.actions[agentID]:
		thID, err := e.Message.ThreadID()
		if err != nil {
			return err
		}

		proposal := &introduceService.Proposal{}
		if err := e.Message.Decode(proposal); err != nil {
			return err
		}

		if proposal.To.Name != introduceeID {
			return fmt.Errorf("%q wants to know %q but got %q", agentID, introduceeID, proposal.To.Name)
		}

		e.Continue(a.clients[agentID].InvitationEnvelope(thID))
	case <-time.After(time.Second * 1):
		return fmt.Errorf("timeout checkAndContinue %s", agentID)
	}

	return nil
}

func (a *SDKSteps) continueWithProtocol(agentID string) error {
	select {
	case e := <-a.actions[agentID]:
		thID, err := e.Message.ThreadID()
		if err != nil {
			return err
		}

		e.Continue(a.clients[agentID].InvitationEnvelope(thID))
	case <-time.After(time.Second * 1):
		return fmt.Errorf("timeout continueWithProtocol %s", agentID)
	}

	return nil
}

func (a *SDKSteps) stopProtocol(agentID string) error {
	select {
	case e := <-a.actions[agentID]:
		e.Stop(errors.New("stop the protocol"))
	case <-time.After(time.Second * 1):
		return fmt.Errorf("timeout stopProtocol %s", agentID)
	}

	return nil
}

func (a *SDKSteps) getConnection(agent1, agent2 string) (*didexchange.Connection, error) {
	connections, err := a.bddContext.DIDExchangeClients[agent1].QueryConnections(&didexchange.QueryConnectionsParams{})
	if err != nil {
		return nil, err
	}

	for i := range connections {
		if connections[i].TheirLabel == agent2 {
			return connections[i], nil
		}
	}

	return nil, errors.New("no connection between agents")
}

func (a *SDKSteps) sendProposal(introducer, introducee1, introducee2 string) error {
	conn1, err := a.getConnection(introducer, introducee1)
	if err != nil {
		return err
	}

	conn2, err := a.getConnection(introducer, introducee2)
	if err != nil {
		return err
	}

	return a.clients[introducer].SendProposal(&introduceService.Recipient{
		To:       &introduceService.To{Name: conn2.TheirLabel},
		MyDID:    conn1.MyDID,
		TheirDID: conn1.TheirDID,
	}, &introduceService.Recipient{
		To:       &introduceService.To{Name: conn1.TheirLabel},
		MyDID:    conn2.MyDID,
		TheirDID: conn2.TheirDID,
	})
}

func (a *SDKSteps) sendProposalWithInvitation(introducer, introducee1, introducee2 string) error {
	conn1, err := a.getConnection(introducer, introducee1)
	if err != nil {
		return err
	}

	inv, err := a.bddContext.DIDExchangeClients[introducee2].CreateInvitation(introducee2)
	if err != nil {
		return err
	}

	return a.clients[introducer].SendProposalWithInvitation(inv.Invitation, &introduceService.Recipient{
		To:       &introduceService.To{Name: introducee2},
		MyDID:    conn1.MyDID,
		TheirDID: conn1.TheirDID,
	})
}

func (a *SDKSteps) sendRequest(introducee1, introducer, introducee2 string) error {
	conn1, err := a.getConnection(introducee1, introducer)
	if err != nil {
		return err
	}

	to := &introduceService.PleaseIntroduceTo{To: introduceService.To{Name: introducee2}}

	return a.clients[introducee1].SendRequest(to, conn1.MyDID, conn1.TheirDID)
}
