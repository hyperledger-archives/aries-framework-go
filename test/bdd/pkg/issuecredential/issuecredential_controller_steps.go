/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"

	"github.com/cucumber/godog"

	client "github.com/hyperledger/aries-framework-go/pkg/client/issuecredential"
	didexcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/didexchange"
	issuecredentialcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	didexsteps "github.com/hyperledger/aries-framework-go/test/bdd/pkg/didexchange"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/util"
)

const (
	operationID       = "/issuecredential"
	sendRequest       = operationID + "/send-request"
	sendOffer         = operationID + "/send-offer"
	sendProposal      = operationID + "/send-proposal"
	acceptProposal    = operationID + "/%s/accept-proposal"
	negotiateProposal = operationID + "/%s/negotiate-proposal"
	acceptOffer       = operationID + "/%s/accept-offer"
	acceptRequest     = operationID + "/%s/accept-request"
	acceptCredential  = operationID + "/%s/accept-credential"
)

// ControllerSteps is steps for issuecredential with controller.
type ControllerSteps struct {
	bddContext *context.BDDContext
	did        map[string]string
	nameToPIID map[string]string
}

// NewIssueCredentialControllerSteps creates steps for issuecredential with controller.
func NewIssueCredentialControllerSteps() *ControllerSteps {
	return &ControllerSteps{nameToPIID: map[string]string{}}
}

// SetContext sets every scenario with a fresh context.
func (s *ControllerSteps) SetContext(ctx *context.BDDContext) {
	s.bddContext = ctx
}

// RegisterSteps registers agent steps
// nolint:lll
func (s *ControllerSteps) RegisterSteps(gs *godog.Suite) {
	gs.Step(`^"([^"]*)" has established connection with "([^"]*)" through IssueCredential controller$`, s.establishConnection)
	gs.Step(`^"([^"]*)" requests credential from "([^"]*)" through IssueCredential controller$`, s.requestCredential)
	gs.Step(`^"([^"]*)" sends an offer to the "([^"]*)" through IssueCredential controller$`, s.sendOffer)
	gs.Step(`^"([^"]*)" sends proposal credential to the "([^"]*)" through IssueCredential controller$`, s.sendProposal)
	gs.Step(`^"([^"]*)" accepts a proposal and sends an offer to the Holder through IssueCredential controller$`, s.acceptProposal)
	gs.Step(`^"([^"]*)" does not like the offer and sends a new proposal to the Issuer through IssueCredential controller$`, s.negotiateProposal)
	gs.Step(`^"([^"]*)" accepts an offer and sends a request to the Issuer through IssueCredential controller$`, s.acceptOffer)
	gs.Step(`^"([^"]*)" accepts request and sends credential to the Holder through IssueCredential controller$`, s.acceptRequest)
	gs.Step(`^"([^"]*)" accepts credential with name "([^"]*)" through IssueCredential controller$`, s.acceptCredential)
	gs.Step(`^"([^"]*)" checks that issued credential is being stored under "([^"]*)" name$`, s.validateCredential)
}

func (s *ControllerSteps) establishConnection(holder, issuer string) error {
	ds := didexsteps.NewDIDExchangeControllerSteps()
	ds.SetContext(s.bddContext)

	err := ds.EstablishConnection(holder, issuer)
	if err != nil {
		return fmt.Errorf("unable to establish connection between [%s] and [%s]: %w", holder, issuer, err)
	}

	connID, ok := ds.ConnectionIDs()[holder]
	if !ok {
		return fmt.Errorf("unable to find connection for agent [%s]", holder)
	}

	controllerURL, ok := s.bddContext.GetControllerURL(holder)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", holder)
	}

	var response didexcmd.QueryConnectionResponse

	connectionsURL := fmt.Sprintf("%s/connections/%s", controllerURL, connID)

	err = util.SendHTTP(http.MethodGet, connectionsURL, nil, &response)
	if err != nil {
		return fmt.Errorf("failed to query connections: %w", err)
	}

	s.did = make(map[string]string)
	s.did[holder] = response.Result.MyDID
	s.did[issuer] = response.Result.TheirDID

	return nil
}

func (s *ControllerSteps) requestCredential(holder, issuer string) error {
	url, ok := s.bddContext.GetControllerURL(holder)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", holder)
	}

	return postToURL(url+sendRequest, issuecredentialcmd.SendRequestArgs{
		MyDID:             s.did[holder],
		TheirDID:          s.did[issuer],
		RequestCredential: &client.RequestCredential{},
	})
}

func (s *ControllerSteps) sendOffer(issuer, holder string) error {
	url, ok := s.bddContext.GetControllerURL(issuer)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", issuer)
	}

	return postToURL(url+sendOffer, issuecredentialcmd.SendOfferArgs{
		MyDID:           s.did[issuer],
		TheirDID:        s.did[holder],
		OfferCredential: &client.OfferCredential{},
	})
}

func (s *ControllerSteps) sendProposal(holder, issuer string) error {
	url, ok := s.bddContext.GetControllerURL(holder)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", holder)
	}

	return postToURL(url+sendProposal, issuecredentialcmd.SendProposalArgs{
		MyDID:             s.did[holder],
		TheirDID:          s.did[issuer],
		ProposeCredential: &client.ProposeCredential{},
	})
}

func (s *ControllerSteps) acceptProposal(issuer string) error {
	url, ok := s.bddContext.GetControllerURL(issuer)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", issuer)
	}

	piid, err := s.actionPIID(issuer)
	if err != nil {
		return err
	}

	return postToURL(url+fmt.Sprintf(acceptProposal, piid), issuecredentialcmd.AcceptProposalArgs{
		OfferCredential: &client.OfferCredential{},
	})
}

func (s *ControllerSteps) negotiateProposal(holder string) error {
	url, ok := s.bddContext.GetControllerURL(holder)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", holder)
	}

	piid, err := s.actionPIID(holder)
	if err != nil {
		return err
	}

	return postToURL(url+fmt.Sprintf(negotiateProposal, piid), issuecredentialcmd.NegotiateProposalArgs{
		ProposeCredential: &client.ProposeCredential{},
	})
}

func (s *ControllerSteps) acceptOffer(holder string) error {
	url, ok := s.bddContext.GetControllerURL(holder)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", holder)
	}

	piid, err := s.actionPIID(holder)
	if err != nil {
		return err
	}

	return postToURL(url+fmt.Sprintf(acceptOffer, piid), nil)
}

func (s *ControllerSteps) acceptRequest(issuer string) error {
	url, ok := s.bddContext.GetControllerURL(issuer)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", issuer)
	}

	piid, err := s.actionPIID(issuer)
	if err != nil {
		return err
	}

	return postToURL(url+fmt.Sprintf(acceptRequest, piid), issuecredentialcmd.AcceptRequestArgs{
		IssueCredential: &client.IssueCredential{
			CredentialsAttach: []decorator.Attachment{
				{Data: decorator.AttachmentData{JSON: getVCredential()}},
			},
		},
	})
}

func (s *ControllerSteps) acceptCredential(holder, credential string) error {
	url, ok := s.bddContext.GetControllerURL(holder)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", holder)
	}

	piid, err := s.actionPIID(holder)
	if err != nil {
		return err
	}

	s.nameToPIID[credential] = piid

	return postToURL(url+fmt.Sprintf(acceptCredential, piid), issuecredentialcmd.AcceptCredentialArgs{
		Names: []string{credential},
	})
}

func (s *ControllerSteps) validateCredential(holder, credential string) error {
	msg, err := util.PullEventsFromWebSocket(s.bddContext, holder,
		util.FilterTopic("issue-credential_states"),
		util.FilterStateID("done"),
		util.FilterPIID(s.nameToPIID[credential]),
	)
	if err != nil {
		return fmt.Errorf("pull events from WebSocket: %w", err)
	}

	if !reflect.DeepEqual(msg.Message.Properties["names"], []interface{}{credential}) {
		return fmt.Errorf("properties: expected names [%s], got %v", credential,
			msg.Message.Properties["names"])
	}

	url, ok := s.bddContext.GetControllerURL(holder)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", holder)
	}

	return util.SendHTTP(http.MethodGet, fmt.Sprintf("%s/verifiable/credential/name/%s", url, credential), nil, nil)
}

func (s *ControllerSteps) actionPIID(agentID string) (string, error) {
	msg, err := util.PullEventsFromWebSocket(s.bddContext, agentID, util.FilterTopic("issue-credential_actions"))
	if err != nil {
		return "", fmt.Errorf("pull events from WebSocket: %w", err)
	}

	return msg.Message.Properties["piid"].(string), nil
}

func postToURL(url string, payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	return util.SendHTTP(http.MethodPost, url, body, nil)
}
