/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/client/introduce"
	"github.com/hyperledger/aries-framework-go/pkg/client/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	protocol "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/introduce"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/test/bdd/agent"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	didexchangebdd "github.com/hyperledger/aries-framework-go/test/bdd/pkg/didexchange"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/didresolver"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/issuecredential"
	mediatorbdd "github.com/hyperledger/aries-framework-go/test/bdd/pkg/mediator"
	outofbandbdd "github.com/hyperledger/aries-framework-go/test/bdd/pkg/outofband"
)

const timeout = time.Second * 15

// SDKSteps is steps for introduce using client SDK.
type SDKSteps struct {
	bddContext      *context.BDDContext
	didExchangeSDKS *didexchangebdd.SDKSteps
	outofbandSDKS   *outofbandbdd.SDKSteps
	issueCredSDKS   *issuecredential.SDKSteps
	invitationID    string
	clients         map[string]*introduce.Client
	actions         map[string]chan service.DIDCommAction
	events          map[string]chan service.StateMsg
}

// NewIntroduceSDKSteps creates steps for introduce with SDK.
func NewIntroduceSDKSteps() *SDKSteps {
	return &SDKSteps{
		clients: make(map[string]*introduce.Client),
		actions: make(map[string]chan service.DIDCommAction),
		events:  make(map[string]chan service.StateMsg),
	}
}

// SetContext is called before every scenario is run with a fresh new context.
func (a *SDKSteps) SetContext(ctx *context.BDDContext) {
	a.bddContext = ctx
	a.didExchangeSDKS = didexchangebdd.NewDIDExchangeSDKSteps()
	a.didExchangeSDKS.SetContext(ctx)
	a.outofbandSDKS = outofbandbdd.NewOutOfBandSDKSteps()
	a.outofbandSDKS.SetContext(ctx)
	a.issueCredSDKS = issuecredential.NewIssueCredentialSDKSteps()
	a.issueCredSDKS.SetContext(ctx)
	a.clients = make(map[string]*introduce.Client)
	a.actions = make(map[string]chan service.DIDCommAction)
	a.events = make(map[string]chan service.StateMsg)
}

// RegisterSteps registers agent steps.
func (a *SDKSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^"([^"]*)" sends introduce proposal to the "([^"]*)" and "([^"]*)"$`, a.sendProposal)
	s.Step(`^"([^"]*)" sends introduce proposal to the "([^"]*)" with "([^"]*)" out-of-band invitation$`,
		a.sendProposalWithInvitation)
	s.Step(`^"([^"]*)" sends introduce request to the "([^"]*)" asking about "([^"]*)"$`, a.sendRequest)
	s.Step(`^"([^"]*)" sends introduce proposal back to the "([^"]*)" and requested introduce$`, a.handleRequest)
	s.Step(`^"([^"]*)" sends introduce proposal back to the requester with public out-of-band invitation$`,
		a.handleRequestWithInvitation)
	s.Step(`^"([^"]*)" wants to know "([^"]*)" and sends introduce response with approve$`, a.checkAndContinue)
	s.Step(`^"([^"]*)" wants to know "([^"]*)" and sends introduce response with approve and provides an out-of-band invitation$`, //nolint:lll
		a.checkAndContinueWithInvitation)
	s.Step(`^"([^"]*)" wants to know "([^"]*)" and sends introduce response with approve and provides an out-of-band invitation with an embedded "([^"]*)"$`, //nolint:lll
		a.checkAndContinueWithInvitationAndEmbeddedRequest)
	s.Step(`^"([^"]*)" doesn't want to know "([^"]*)" and sends introduce response$`, a.checkAndStop)
	s.Step(`^"([^"]*)" stops the introduce protocol$`, a.stopProtocol)
	s.Step(`^"([^"]*)" checks the history of introduce protocol events "([^"]*)"$`, a.checkHistoryEvents)
	s.Step(`^"([^"]*)" checks the history of introduce protocol events "([^"]*)" and stop$`,
		a.checkHistoryEventsAndStop)
	s.Step(`^"([^"]*)" exchange DIDs with "([^"]*)"$`, a.createConnections)
	s.Step(`^"([^"]*)" has did exchange connection with "([^"]*)"$`, a.connectionEstablished)
	s.Step(`^"([^"]*)" confirms route registration with "([^"]*)"$`, a.confirmRouteRegistration)
	s.Step(`^"([^"]*)" receives problem report message \(Introduce\)$`, a.receiveProblemReport)
}

func (a *SDKSteps) connectionEstablished(agent1, agent2 string) error {
	if err := a.didExchangeSDKS.ApproveRequest(agent2); err != nil {
		return err
	}

	err := a.didExchangeSDKS.WaitForPostEvent(agent2+","+agent1, "completed")
	if err != nil {
		return err
	}

	agent1connections, err := a.bddContext.DIDExchangeClients[agent1].QueryConnections(&didexchange.QueryConnectionsParams{
		ParentThreadID: a.invitationID,
	})
	if err != nil {
		return fmt.Errorf("%s connections: %w", agent1, err)
	}

	agent2connections, err := a.bddContext.DIDExchangeClients[agent2].QueryConnections(&didexchange.QueryConnectionsParams{
		InvitationID: a.invitationID,
	})
	if err != nil {
		return fmt.Errorf("%s connections: %w", agent2, err)
	}

	if len(agent1connections) == 0 || len(agent2connections) == 0 {
		return errors.New("connection was not established")
	}

	return err
}

func (a *SDKSteps) createConnections(introducees, introducer string) error {
	const (
		inboundHost     = "localhost"
		inboundPort     = "random"
		endpointURL     = "${SIDETREE_URL}"
		acceptDidMethod = "sidetree"
	)

	participants := introducees + "," + introducer
	agentSDK := agent.NewSDKSteps()
	agentSDK.SetContext(a.bddContext)

	err := agentSDK.CreateAgentWithHTTPDIDResolver(participants, inboundHost, inboundPort, endpointURL, acceptDidMethod)
	if err != nil {
		return err
	}

	if err := didresolver.CreateDIDDocument(a.bddContext, participants, ""); err != nil {
		return err
	}

	a.didExchangeSDKS = didexchangebdd.NewDIDExchangeSDKSteps()
	a.didExchangeSDKS.SetContext(a.bddContext)

	a.outofbandSDKS = outofbandbdd.NewOutOfBandSDKSteps()
	a.outofbandSDKS.SetContext(a.bddContext)

	if err := a.didExchangeSDKS.WaitForPublicDID(participants, 10); err != nil {
		return err
	}

	if err := a.createExternalClients(participants); err != nil {
		return err
	}

	if err := a.outofbandSDKS.CreateInvitationWithDID(introducer); err != nil {
		return err
	}

	for _, introducee := range strings.Split(introducees, ",") {
		if err := a.outofbandSDKS.ReceiveInvitation(introducee, introducer); err != nil {
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
		if err := a.createClient(agent); err != nil {
			return err
		}
	}

	return nil
}

func (a *SDKSteps) createClient(agentID string) error {
	const stateMsgChanSize = 14

	client, err := introduce.New(a.bddContext.AgentCtx[agentID])
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
		case <-time.After(timeout):
			return fmt.Errorf("%s waited for %s: history of events doesn't meet the expectation", agentID, stateID)
		}
	}

	return nil
}

func (a *SDKSteps) checkHistoryEventsAndStop(agentID, events string) error {
	for _, stateID := range strings.Split(events, ",") {
		select {
		case e := <-a.events[agentID]:
			if stateID != e.StateID {
				return fmt.Errorf("history of events doesn't meet the expectation %q != %q", stateID, e.StateID)
			}
		case <-time.After(timeout):
			return fmt.Errorf("%s waited for %s: history of events doesn't meet the expectation", agentID, stateID)
		}
	}

	// removes invitationID when the scenario is done
	a.invitationID = ""

	return nil
}

func (a *SDKSteps) checkAndStop(agentID, introduceeID string) error {
	select {
	case e := <-a.actions[agentID]:
		err := issuecredential.CheckProperties(e)
		if err != nil {
			return fmt.Errorf("check properties: %w", err)
		}

		proposal := &protocol.Proposal{}
		if err := e.Message.Decode(proposal); err != nil {
			return err
		}

		if proposal.To.Name != introduceeID {
			return fmt.Errorf("%q doesn't want to know %q but got %q", agentID, introduceeID, proposal.To.Name)
		}

		e.Stop(errors.New("stop the protocol"))
	case <-time.After(timeout):
		return fmt.Errorf("timeout checkAndStop %s", agentID)
	}

	return nil
}

func (a *SDKSteps) handleRequest(agentID, introducee string) error {
	select {
	case e := <-a.actions[agentID]:
		err := issuecredential.CheckProperties(e)
		if err != nil {
			return fmt.Errorf("check properties: %w", err)
		}

		request := &protocol.Request{}

		err = e.Message.Decode(request)
		if err != nil {
			return err
		}

		conn, err := a.getConnection(agentID, request.PleaseIntroduceTo.Name)
		if err != nil {
			return err
		}

		recipient := &introduce.Recipient{
			To:       &protocol.To{Name: introducee},
			MyDID:    conn.MyDID,
			TheirDID: conn.TheirDID,
		}

		to := &introduce.To{Name: request.PleaseIntroduceTo.Name}

		e.Continue(introduce.WithRecipients(to, recipient))
	case <-time.After(timeout):
		return fmt.Errorf("timeout checkAndContinue %s", agentID)
	}

	return nil
}

func (a *SDKSteps) handleRequestWithInvitation(agentID string) error {
	select {
	case e := <-a.actions[agentID]:
		err := issuecredential.CheckProperties(e)
		if err != nil {
			return fmt.Errorf("check properties: %w", err)
		}

		request := &protocol.Request{}

		err = e.Message.Decode(request)
		if err != nil {
			return err
		}

		introduceTo := request.PleaseIntroduceTo.Name

		req, err := a.newOOBInvitation(introduceTo)
		if err != nil {
			return err
		}

		to := &introduce.To{Name: req.Label}

		e.Continue(introduce.WithPublicOOBInvitation(req, to))
	case <-time.After(timeout):
		return fmt.Errorf("timeout checkAndContinue %s", agentID)
	}

	return nil
}

func (a *SDKSteps) checkAndContinue(agentID, introduceeID string) error {
	select {
	case e := <-a.actions[agentID]:
		err := issuecredential.CheckProperties(e)
		if err != nil {
			return fmt.Errorf("check properties: %w", err)
		}

		proposal := &protocol.Proposal{}
		if err := e.Message.Decode(proposal); err != nil {
			return err
		}

		if proposal.To.Name != introduceeID {
			return fmt.Errorf("%q wants to know %q but got %q", agentID, introduceeID, proposal.To.Name)
		}

		e.Continue(nil)

		go a.outofbandSDKS.ApproveOOBInvitation(agentID, &outofband.EventOptions{Label: agentID})
	case <-time.After(timeout):
		return fmt.Errorf("timeout checkAndContinue %s", agentID)
	}

	return nil
}

func (a *SDKSteps) checkAndContinueWithInvitation(agentID, introduceeID string) error {
	select {
	case e := <-a.actions[agentID]:
		err := issuecredential.CheckProperties(e)
		if err != nil {
			return fmt.Errorf("check properties: %w", err)
		}

		proposal := &protocol.Proposal{}

		err = e.Message.Decode(proposal)
		if err != nil {
			return err
		}

		if proposal.To.Name != introduceeID {
			return fmt.Errorf("%q wants to know %q but got %q", agentID, introduceeID, proposal.To.Name)
		}

		inv, err := a.newOOBInvitation(agentID)
		if err != nil {
			return err
		}

		e.Continue(introduce.WithOOBInvitation(inv))

		go a.outofbandSDKS.ApproveOOBInvitation(agentID, &outofband.EventOptions{Label: agentID})
	case <-time.After(timeout):
		return fmt.Errorf("timeout checkAndContinue %s", agentID)
	}

	return nil
}

func (a *SDKSteps) checkAndContinueWithInvitationAndEmbeddedRequest(agentID, introduceeID, request string) error {
	select {
	case e := <-a.actions[agentID]:
		err := issuecredential.CheckProperties(e)
		if err != nil {
			return fmt.Errorf("check properties: %w", err)
		}

		proposal := &protocol.Proposal{}

		err = e.Message.Decode(proposal)
		if err != nil {
			return err
		}

		if proposal.To.Name != introduceeID {
			return fmt.Errorf("%q wants to know %q but got %q", agentID, introduceeID, proposal.To.Name)
		}

		inv, err := a.newOOBInvitation(agentID, request)
		if err != nil {
			return err
		}

		e.Continue(introduce.WithOOBInvitation(inv))

		go a.outofbandSDKS.ApproveOOBInvitation(introduceeID, &outofband.EventOptions{Label: agentID})
	case <-time.After(timeout):
		return fmt.Errorf("timeout checkAndContinue %s", agentID)
	}

	return nil
}

func (a *SDKSteps) receiveProblemReport(agentID string) error {
	select {
	case e := <-a.actions[agentID]:
		err := issuecredential.CheckProperties(e)
		if err != nil {
			return fmt.Errorf("check properties: %w", err)
		}

		e.Continue(nil)
	case <-time.After(timeout):
		return fmt.Errorf("timeout stopProtocol %s", agentID)
	}

	return nil
}

func (a *SDKSteps) stopProtocol(agentID string) error {
	select {
	case e := <-a.actions[agentID]:
		err := issuecredential.CheckProperties(e)
		if err != nil {
			return fmt.Errorf("check properties: %w", err)
		}

		e.Stop(errors.New("stop the protocol"))
	case <-time.After(timeout):
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

	_, err = a.clients[introducer].SendProposal(&introduce.Recipient{
		To:       &protocol.To{Name: conn2.TheirLabel},
		MyDID:    conn1.MyDID,
		TheirDID: conn1.TheirDID,
	}, &introduce.Recipient{
		To:       &protocol.To{Name: conn1.TheirLabel},
		MyDID:    conn2.MyDID,
		TheirDID: conn2.TheirDID,
	})

	return err
}

func (a *SDKSteps) sendProposalWithInvitation(introducer, introducee1, introducee2 string) error {
	conn1, err := a.getConnection(introducer, introducee1)
	if err != nil {
		return err
	}

	req, err := a.newOOBInvitation(introducee2)
	if err != nil {
		return err
	}

	_, err = a.clients[introducer].SendProposalWithOOBInvitation(req, &introduce.Recipient{
		To:       &protocol.To{Name: introducee2},
		MyDID:    conn1.MyDID,
		TheirDID: conn1.TheirDID,
	})

	return err
}

func (a *SDKSteps) sendRequest(introducee1, introducer, introducee2 string) error {
	conn1, err := a.getConnection(introducee1, introducer)
	if err != nil {
		return err
	}

	to := &introduce.PleaseIntroduceTo{To: protocol.To{Name: introducee2}}

	_, err = a.clients[introducee1].SendRequest(to, conn1.MyDID, conn1.TheirDID)

	return err
}

//nolint:funlen,gocyclo
func (a *SDKSteps) newOOBInvitation(agentID string, requests ...interface{}) (*outofband.Invitation, error) {
	client, err := outofband.New(a.bddContext.AgentCtx[agentID])
	if err != nil {
		return nil, err
	}

	opts := []outofband.MessageOption{
		outofband.WithLabel(agentID),
	}

	if len(requests) > 0 {
		var attachments []*decorator.Attachment

		for _, r := range requests {
			if r != "route-request" {
				return nil, fmt.Errorf("unsupported request type: %s", r)
			}

			bytes, er := json.Marshal(&mediator.Request{
				ID:   uuid.New().String(),
				Type: mediator.RequestMsgType,
			})
			if er != nil {
				return nil, er
			}

			attachments = append(attachments, &decorator.Attachment{
				ID:          uuid.New().String(),
				Description: "test",
				Data: decorator.AttachmentData{
					Base64: base64.StdEncoding.EncodeToString(bytes),
				},
			})
		}

		opts = append(opts, outofband.WithAttachments(attachments...))
	}

	mtps := a.bddContext.AgentCtx[agentID].MediaTypeProfiles()
	didCommV2 := false

	for _, mtp := range mtps {
		switch mtp {
		case transport.MediaTypeDIDCommV2Profile, transport.MediaTypeAIP2RFC0587Profile:
			didCommV2 = true
		}

		if didCommV2 {
			break
		}
	}

	if !didCommV2 && len(mtps) == 0 {
		mtps = []string{transport.MediaTypeAIP2RFC0019Profile}
	}

	opts = append(opts, outofband.WithAccept(mtps...))

	inv, err := client.CreateInvitation(
		nil,
		opts...,
	)
	if err != nil {
		return nil, err
	}

	// sets invitationID for the running scenario
	a.invitationID = inv.ID

	return inv, nil
}

//  creates clients for other protocols (eg. out-of-band, did-exchange)
func (a *SDKSteps) createExternalClients(participants string) error {
	if err := a.didExchangeSDKS.CreateDIDExchangeClient(participants); err != nil {
		return err
	}

	if err := a.outofbandSDKS.CreateClients(participants); err != nil {
		return err
	}

	return a.didExchangeSDKS.RegisterPostMsgEvent(participants, "completed")
}

func (a *SDKSteps) confirmRouteRegistration(agentID, router string) error {
	routeSteps := mediatorbdd.NewRouteSDKSteps()
	routeSteps.SetContext(a.bddContext)

	go routeSteps.ApproveRequest(router, service.Empty{})

	expected, err := a.getConnection(agentID, router)
	if err != nil {
		return err
	}

	client, err := mediator.New(a.bddContext.AgentCtx[agentID])
	if err != nil {
		return err
	}

	var connections []string

	deadline := time.Now().Add(timeout)

	// TODO add protocol state msg event capability to routing service
	//  https://github.com/hyperledger/aries-framework-go/issues/1718
	for time.Now().Before(deadline) {
		connections, err = client.GetConnections()
		if err != nil {
			return err
		}

		for i := range connections {
			if expected.ConnectionID == connections[i] {
				return nil
			}
		}

		time.Sleep(250 * time.Millisecond) //nolint:gomnd
	}

	return fmt.Errorf("mismatch: %s has connectionID=%s with router %s but its routing IDs are %v",
		agentID, expected.ConnectionID, router, connections)
}
