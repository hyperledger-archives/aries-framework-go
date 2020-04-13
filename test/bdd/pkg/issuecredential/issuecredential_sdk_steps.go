/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import (
	"errors"
	"time"

	"github.com/cucumber/godog"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/client/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	verifiableStore "github.com/hyperledger/aries-framework-go/pkg/store/verifiable"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
)

const timeout = time.Second * 5

func getVCredential() *verifiable.Credential {
	const referenceNumber = 83294847

	var issued = time.Date(2010, time.January, 1, 19, 23, 24, 0, time.UTC)

	return &verifiable.Credential{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1"},
		ID: "http://example.edu/credentials/1872",
		Types: []string{
			"VerifiableCredential",
			"UniversityDegreeCredential"},
		Subject: struct {
			ID string
		}{ID: "SubjectID"},
		Issuer: verifiable.Issuer{
			ID:   "did:example:76e12ec712ebc6f1c221ebfeb1f",
			Name: "Example University",
		},
		Issued:  &issued,
		Schemas: []verifiable.TypedID{},
		CustomFields: map[string]interface{}{
			"referenceNumber": referenceNumber,
		},
	}
}

// SDKSteps is steps for the issuecredential using client SDK
type SDKSteps struct {
	bddContext *context.BDDContext
	clients    map[string]*issuecredential.Client
	actions    map[string]chan service.DIDCommAction
	events     map[string]chan service.StateMsg
}

// NewIssueCredentialSDKSteps creates steps for the issuecredential with SDK
func NewIssueCredentialSDKSteps() *SDKSteps {
	return &SDKSteps{
		clients: make(map[string]*issuecredential.Client),
		actions: make(map[string]chan service.DIDCommAction),
		events:  make(map[string]chan service.StateMsg),
	}
}

// SetContext is called before every scenario is run with a fresh new context
func (a *SDKSteps) SetContext(ctx *context.BDDContext) {
	a.bddContext = ctx
}

// RegisterSteps registers agent steps
func (a *SDKSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^"([^"]*)" requests credential from "([^"]*)"$`, a.sendsRequest)
	s.Step(`^"([^"]*)" accepts request and sends credential to the Holder$`, a.acceptRequest)
	s.Step(`^"([^"]*)" declines a request$`, a.declineRequest)
	s.Step(`^"([^"]*)" declines a proposal$`, a.declineProposal)
	s.Step(`^"([^"]*)" declines an offer$`, a.declineOffer)
	s.Step(`^"([^"]*)" declines the credential`, a.declineCredential)
	s.Step(`^"([^"]*)" waits for state "([^"]*)"$`, a.waitFor)
	s.Step(`^"([^"]*)" sends proposal credential to the "([^"]*)"`, a.sendsProposal)
	s.Step(`^"([^"]*)" accepts a proposal and sends an offer to the Holder`, a.acceptProposal)
	s.Step(`^"([^"]*)" sends an offer to the "([^"]*)"$`, a.sendsOffer)
	s.Step(`^"([^"]*)" accepts an offer and sends a request to the Issuer`, a.acceptOffer)
	s.Step(`^"([^"]*)" does not like the offer and sends a new proposal to the Issuer`, a.negotiateProposal)
	s.Step(`^"([^"]*)" accepts credential with name "([^"]*)"$`, a.acceptCredential)
	s.Step(`^"([^"]*)" checks that credential is being stored under "([^"]*)" name$`, a.checkCredential)
}

func (a *SDKSteps) waitFor(agent, name string) error {
	for {
		select {
		case e := <-a.events[agent]:
			if e.StateID == name {
				return nil
			}
		case <-time.After(timeout):
			return errors.New("timeout")
		}
	}
}

func (a *SDKSteps) checkCredential(agent, name string) error {
	if err := a.waitFor(agent, "done"); err != nil {
		return err
	}

	store, err := verifiableStore.New(a.bddContext.AgentCtx[agent])
	if err != nil {
		return err
	}

	ID, err := store.GetCredentialIDByName(name)
	if err != nil {
		return err
	}

	_, err = store.GetCredential(ID)

	return err
}

func (a *SDKSteps) sendsOffer(agent1, agent2 string) error {
	conn, err := a.getConnection(agent1, agent2)
	if err != nil {
		return err
	}

	return a.clients[agent1].SendOffer(&issuecredential.OfferCredential{}, conn.MyDID, conn.TheirDID)
}

func (a *SDKSteps) sendsProposal(agent1, agent2 string) error {
	conn, err := a.getConnection(agent1, agent2)
	if err != nil {
		return err
	}

	return a.clients[agent1].SendProposal(&issuecredential.ProposeCredential{}, conn.MyDID, conn.TheirDID)
}

func (a *SDKSteps) sendsRequest(agent1, agent2 string) error {
	conn, err := a.getConnection(agent1, agent2)
	if err != nil {
		return err
	}

	return a.clients[agent1].SendRequest(&issuecredential.RequestCredential{}, conn.MyDID, conn.TheirDID)
}

func (a *SDKSteps) acceptProposal(agent string) error {
	PIID, err := a.getActionID(agent)
	if err != nil {
		return err
	}

	return a.clients[agent].AcceptProposal(PIID, &issuecredential.OfferCredential{})
}

func (a *SDKSteps) declineCredential(agent string) error {
	PIID, err := a.getActionID(agent)
	if err != nil {
		return err
	}

	return a.clients[agent].DeclineCredential(PIID, "decline")
}

func (a *SDKSteps) declineOffer(agent string) error {
	PIID, err := a.getActionID(agent)
	if err != nil {
		return err
	}

	return a.clients[agent].DeclineOffer(PIID, "decline")
}

func (a *SDKSteps) declineProposal(agent string) error {
	PIID, err := a.getActionID(agent)
	if err != nil {
		return err
	}

	return a.clients[agent].DeclineProposal(PIID, "decline")
}

func (a *SDKSteps) declineRequest(agent string) error {
	PIID, err := a.getActionID(agent)
	if err != nil {
		return err
	}

	return a.clients[agent].DeclineRequest(PIID, "decline")
}

func (a *SDKSteps) acceptRequest(agent string) error {
	PIID, err := a.getActionID(agent)
	if err != nil {
		return err
	}

	return a.clients[agent].AcceptRequest(PIID, &issuecredential.IssueCredential{
		CredentialsAttach: []decorator.Attachment{
			{Data: decorator.AttachmentData{JSON: getVCredential()}},
		},
	})
}

func (a *SDKSteps) getActionID(agent string) (string, error) {
	select {
	case e := <-a.actions[agent]:
		return e.Message.ThreadID()
	case <-time.After(timeout):
		return "", errors.New("timeout")
	}
}

func (a *SDKSteps) negotiateProposal(agent string) error {
	PIID, err := a.getActionID(agent)
	if err != nil {
		return err
	}

	return a.clients[agent].NegotiateProposal(PIID, &issuecredential.ProposeCredential{})
}

func (a *SDKSteps) acceptOffer(agent string) error {
	PIID, err := a.getActionID(agent)
	if err != nil {
		return err
	}

	return a.clients[agent].AcceptOffer(PIID)
}

func (a *SDKSteps) acceptCredential(agent, name string) error {
	PIID, err := a.getActionID(agent)
	if err != nil {
		return err
	}

	return a.clients[agent].AcceptCredential(PIID, name)
}

func (a *SDKSteps) createClient(agentID string) error {
	if a.clients[agentID] != nil {
		return nil
	}

	const stateMsgChanSize = 12

	client, err := issuecredential.New(a.bddContext.AgentCtx[agentID])
	if err != nil {
		return err
	}

	a.clients[agentID] = client
	a.actions[agentID] = make(chan service.DIDCommAction, 1)
	a.events[agentID] = make(chan service.StateMsg, stateMsgChanSize)

	if err := client.RegisterMsgEvent(a.events[agentID]); err != nil {
		return err
	}

	return client.RegisterActionEvent(a.actions[agentID])
}

func (a *SDKSteps) getConnection(agent1, agent2 string) (*didexchange.Connection, error) {
	if err := a.createClient(agent1); err != nil {
		return nil, err
	}

	if err := a.createClient(agent2); err != nil {
		return nil, err
	}

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
