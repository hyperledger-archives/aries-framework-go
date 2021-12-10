/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cucumber/godog"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/client/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	verifiableStore "github.com/hyperledger/aries-framework-go/pkg/store/verifiable"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
)

const (
	timeout              = time.Second * 5
	webRedirectStatusKey = "status"
	webRedirectURLKey    = "url"
)

func getVCredential() *verifiable.Credential {
	const referenceNumber = 83294847

	issued := time.Date(2010, time.January, 1, 19, 23, 24, 0, time.UTC)

	return &verifiable.Credential{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1",
		},
		ID: "http://example.edu/credentials/1872",
		Types: []string{
			"VerifiableCredential",
			"UniversityDegreeCredential",
		},
		Subject: struct {
			ID string
		}{ID: "SubjectID"},
		Issuer: verifiable.Issuer{
			ID:           "did:example:76e12ec712ebc6f1c221ebfeb1f",
			CustomFields: verifiable.CustomFields{"name": "Example University"},
		},
		Issued:  util.NewTime(issued),
		Schemas: []verifiable.TypedID{},
		CustomFields: map[string]interface{}{
			"referenceNumber": referenceNumber,
		},
	}
}

// SDKSteps is steps for the issuecredential using client SDK.
type SDKSteps struct {
	bddContext *context.BDDContext
	clients    map[string]*issuecredential.Client
	actions    map[string]chan service.DIDCommAction
	events     map[string]chan service.StateMsg
}

// NewIssueCredentialSDKSteps creates steps for the issuecredential with SDK.
func NewIssueCredentialSDKSteps() *SDKSteps {
	return &SDKSteps{
		clients: make(map[string]*issuecredential.Client),
		actions: make(map[string]chan service.DIDCommAction),
		events:  make(map[string]chan service.StateMsg),
	}
}

// SetContext is called before every scenario is run with a fresh new context.
func (a *SDKSteps) SetContext(ctx *context.BDDContext) {
	a.bddContext = ctx
}

// RegisterSteps registers agent steps.
// nolint:lll
func (a *SDKSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^"([^"]*)" requests credential from "([^"]*)"$`, a.sendsRequest)
	s.Step(`^"([^"]*)" requests credential V3 from "([^"]*)"$`, a.sendsRequestV3)
	s.Step(`^"([^"]*)" accepts request and sends credential to the Holder$`, a.AcceptRequest)
	s.Step(`^"([^"]*)" accepts request and sends credential to the Holder and requests redirect to "([^"]*)"$`, a.AcceptRequestWithRedirect)
	s.Step(`^"([^"]*)" accepts request V3 and sends credential to the Holder$`, a.AcceptRequestV3)
	s.Step(`^"([^"]*)" declines a request$`, a.declineRequest)
	s.Step(`^"([^"]*)" declines a request and requests redirect to "([^"]*)"$`, a.declineRequestWithRedirect)
	s.Step(`^"([^"]*)" declines a proposal$`, a.declineProposal)
	s.Step(`^"([^"]*)" declines a proposal and requests redirect to "([^"]*)"$`, a.declineProposalWithRedirect)
	s.Step(`^"([^"]*)" declines an offer$`, a.declineOffer)
	s.Step(`^"([^"]*)" declines the credential`, a.declineCredential)
	s.Step(`^"([^"]*)" receives problem report message \(Issue Credential\)$`, a.receiveProblemReport)
	s.Step(`^"([^"]*)" waits for state "([^"]*)"$`, a.waitFor)
	s.Step(`^"([^"]*)" sends proposal credential to the "([^"]*)"$`, a.sendsProposal)
	s.Step(`^"([^"]*)" sends proposal credential V3 to the "([^"]*)"$`, a.sendsProposalV3)
	s.Step(`^"([^"]*)" accepts a proposal and sends an offer to the Holder$`, a.acceptProposal)
	s.Step(`^"([^"]*)" accepts a proposal V3 and sends an offer to the Holder$`, a.acceptProposalV3)
	s.Step(`^"([^"]*)" sends an offer to the "([^"]*)"$`, a.SendsOffer)
	s.Step(`^"([^"]*)" sends an offer V3 to the "([^"]*)"$`, a.SendsOfferV3)
	s.Step(`^"([^"]*)" accepts an offer and sends a request to the Issuer$`, a.AcceptOffer)
	s.Step(`^"([^"]*)" does not like the offer and sends a new proposal to the Issuer$`, a.negotiateProposal)
	s.Step(`^"([^"]*)" does not like the offer V3 and sends a new proposal to the Issuer$`, a.negotiateProposalV3)
	s.Step(`^"([^"]*)" accepts credential with name "([^"]*)"$`, a.AcceptCredentialByName)
	s.Step(`^"([^"]*)" accepts credential but skips agent storage$`, a.AcceptCredentialBySkippingStore)
	s.Step(`^"([^"]*)" checks that credential is being stored under "([^"]*)" name$`, a.CheckCredential)
	s.Step(`^"([^"]*)" receives issue credential event "([^"]*)" with status "([^"]*)" and redirect "([^"]*)"$`,
		a.validateProtocolStatus)
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

// CheckCredential verifies the agent holds a credential with the given name.
func (a *SDKSteps) CheckCredential(agent, name string) error {
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

// SendsOffer sends an offer from agent1 to agent2.
func (a *SDKSteps) SendsOffer(agent1, agent2 string) error {
	conn, err := a.getConnection(agent1, agent2)
	if err != nil {
		return err
	}

	piid, err := a.clients[agent1].SendOffer(&issuecredential.OfferCredential{}, conn.Record)
	if err != nil {
		return fmt.Errorf("send offer: %w", err)
	}

	if piid == "" {
		return errors.New("piid is empty")
	}

	return nil
}

// SendsOfferV3 sends an offer from agent1 to agent2.
func (a *SDKSteps) SendsOfferV3(agent1, agent2 string) error {
	conn, err := a.getConnection(agent1, agent2)
	if err != nil {
		return err
	}

	conn.DIDCommVersion = service.V2

	piid, err := a.clients[agent1].SendOffer(&issuecredential.OfferCredential{}, conn.Record)
	if err != nil {
		return fmt.Errorf("send offer: %w", err)
	}

	if piid == "" {
		return errors.New("piid is empty")
	}

	return nil
}

func (a *SDKSteps) sendsProposal(agent1, agent2 string) error {
	conn, err := a.getConnection(agent1, agent2)
	if err != nil {
		return err
	}

	piid, err := a.clients[agent1].SendProposal(&issuecredential.ProposeCredential{}, conn.Record)
	if err != nil {
		return fmt.Errorf("send proposal: %w", err)
	}

	if piid == "" {
		return errors.New("piid is empty")
	}

	return nil
}

func (a *SDKSteps) sendsProposalV3(agent1, agent2 string) error {
	conn, err := a.getConnection(agent1, agent2)
	if err != nil {
		return err
	}

	conn.DIDCommVersion = service.V2

	piid, err := a.clients[agent1].SendProposal(&issuecredential.ProposeCredential{}, conn.Record)
	if err != nil {
		return fmt.Errorf("send proposal: %w", err)
	}

	if piid == "" {
		return errors.New("piid is empty")
	}

	return nil
}

func (a *SDKSteps) sendsRequest(agent1, agent2 string) error {
	conn, err := a.getConnection(agent1, agent2)
	if err != nil {
		return err
	}

	piid, err := a.clients[agent1].SendRequest(&issuecredential.RequestCredential{}, conn.Record)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}

	if piid == "" {
		return errors.New("piid is empty")
	}

	return nil
}

func (a *SDKSteps) sendsRequestV3(agent1, agent2 string) error {
	conn, err := a.getConnection(agent1, agent2)
	if err != nil {
		return err
	}

	conn.DIDCommVersion = service.V2

	piid, err := a.clients[agent1].SendRequest(&issuecredential.RequestCredential{}, conn.Record)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}

	if piid == "" {
		return errors.New("piid is empty")
	}

	return nil
}

func (a *SDKSteps) acceptProposal(agent string) error {
	PIID, err := a.getActionID(agent)
	if err != nil {
		return err
	}

	return a.clients[agent].AcceptProposal(PIID, &issuecredential.OfferCredential{})
}

func (a *SDKSteps) acceptProposalV3(agent string) error {
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
	return a.declineProposalWithRedirect(agent, "")
}

func (a *SDKSteps) declineProposalWithRedirect(agent, redirect string) error {
	PIID, err := a.getActionID(agent)
	if err != nil {
		return err
	}

	return a.clients[agent].DeclineProposal(PIID, "decline",
		issuecredential.RequestRedirect(redirect))
}

func (a *SDKSteps) declineRequest(agent string) error {
	return a.declineRequestWithRedirect(agent, "")
}

func (a *SDKSteps) declineRequestWithRedirect(agent, redirect string) error {
	PIID, err := a.getActionID(agent)
	if err != nil {
		return err
	}

	return a.clients[agent].DeclineRequest(PIID, "decline",
		issuecredential.RequestRedirect(redirect))
}

// AcceptRequest makes agent accept a request-credential message.
func (a *SDKSteps) AcceptRequest(agent string) error {
	return a.AcceptRequestWithRedirect(agent, "")
}

// AcceptRequestWithRedirect makes agent accept a request-credential message.
func (a *SDKSteps) AcceptRequestWithRedirect(agent, redirect string) error {
	PIID, err := a.getActionID(agent)
	if err != nil {
		return err
	}

	return a.clients[agent].AcceptRequest(PIID, &issuecredential.IssueCredential{
		Attachments: []decorator.GenericAttachment{
			{Data: decorator.AttachmentData{JSON: getVCredential()}},
		},
		WebRedirect: &decorator.WebRedirect{
			Status: "OK",
			URL:    redirect,
		},
	})
}

// AcceptRequestV3 makes agent accept a request-credential message.
func (a *SDKSteps) AcceptRequestV3(agent string) error {
	PIID, err := a.getActionID(agent)
	if err != nil {
		return err
	}

	return a.clients[agent].AcceptRequest(PIID, &issuecredential.IssueCredential{
		Attachments: []decorator.GenericAttachment{
			{Data: decorator.AttachmentData{JSON: getVCredential()}},
		},
	})
}

type prop interface {
	MyDID() string
	TheirDID() string
}

// CheckProperties checks properties.
func CheckProperties(action service.DIDCommAction) error {
	properties, ok := action.Properties.(prop)
	if !ok {
		return errors.New("no properties")
	}

	if properties.MyDID() == "" {
		return errors.New("myDID is empty")
	}

	if properties.TheirDID() == "" {
		return errors.New("theirDID is empty")
	}

	return nil
}

func (a *SDKSteps) getActionID(agent string) (string, error) {
	select {
	case e := <-a.actions[agent]:
		if err := CheckProperties(e); err != nil {
			return "", fmt.Errorf("check properties: %w", err)
		}

		return e.Properties.All()["piid"].(string), nil
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

func (a *SDKSteps) negotiateProposalV3(agent string) error {
	PIID, err := a.getActionID(agent)
	if err != nil {
		return err
	}

	return a.clients[agent].NegotiateProposal(PIID, &issuecredential.ProposeCredential{})
}

func (a *SDKSteps) receiveProblemReport(agent string) error {
	PIID, err := a.getActionID(agent)
	if err != nil {
		return err
	}

	return a.clients[agent].AcceptProblemReport(PIID)
}

// AcceptOffer makes agent accept an offer-credential message.
func (a *SDKSteps) AcceptOffer(agent string) error {
	PIID, err := a.getActionID(agent)
	if err != nil {
		return err
	}

	return a.clients[agent].AcceptOffer(PIID, &issuecredential.RequestCredential{})
}

// AcceptCredentialByName makes agent accept a credential and save it with the given name.
func (a *SDKSteps) AcceptCredentialByName(agent, name string) error {
	return a.AcceptCredential(agent, name, false)
}

// AcceptCredentialBySkippingStore makes agent accept a credential and but doesn't save in agent's verifable store.
func (a *SDKSteps) AcceptCredentialBySkippingStore(agent string) error {
	return a.AcceptCredential(agent, "", true)
}

// AcceptCredential makes agent accept a credential and save it with the given name.
func (a *SDKSteps) AcceptCredential(agent, name string, skipStore bool) error {
	PIID, err := a.getActionID(agent)
	if err != nil {
		return err
	}

	options := []issuecredential.AcceptCredentialOptions{issuecredential.AcceptByFriendlyNames(name)}
	if skipStore {
		options = append(options, issuecredential.AcceptBySkippingStorage())
	}

	return a.clients[agent].AcceptCredential(PIID, options...)
}

// CreateManyClients expects 'many' to be a comma-delimited string of agent names, and a
// new client will be created for each.
func (a *SDKSteps) CreateManyClients(many string) error {
	agents := strings.Split(many, ",")

	for i := range agents {
		err := a.CreateClient(agents[i])
		if err != nil {
			return fmt.Errorf("failed to create client for '%s': %w", agents[i], err)
		}
	}

	return nil
}

// CreateClient creates a client with the given id.
func (a *SDKSteps) CreateClient(agentID string) error {
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
	if err := a.CreateClient(agent1); err != nil {
		return nil, err
	}

	if err := a.CreateClient(agent2); err != nil {
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

func (a *SDKSteps) validateProtocolStatus(agent, stateID, status, redirect string) error {
	for {
		select {
		case e := <-a.events[agent]:
			if stateID != e.StateID {
				continue
			}

			properties := e.Properties.All()

			redirectStatus, ok := properties[webRedirectStatusKey]
			if !ok || redirectStatus != status {
				return fmt.Errorf("expected redirect status [%s], but found [%s] ", status, redirectStatus)
			}

			redirectURL, ok := properties[webRedirectURLKey]
			if !ok || redirectURL != redirect {
				return fmt.Errorf("expected redirect url [%s], but found [%s] ", redirect, redirectURL)
			}

			return nil
		case <-time.After(timeout):
			return fmt.Errorf("waited for %s: history of events doesn't meet the expectation", stateID)
		}
	}
}
