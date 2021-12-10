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
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/connection"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	didexsteps "github.com/hyperledger/aries-framework-go/test/bdd/pkg/didexchange"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/util"
)

const (
	operationID         = "/issuecredential"
	operationIDV3       = operationID + "/v3"
	sendRequest         = operationID + "/send-request"
	sendRequestV3       = operationIDV3 + "/send-request"
	sendOffer           = operationID + "/send-offer"
	sendOfferV3         = operationIDV3 + "/send-offer"
	sendProposal        = operationID + "/send-proposal"
	sendProposalV3      = operationIDV3 + "/send-proposal"
	acceptProposal      = operationID + "/%s/accept-proposal"
	acceptProposalV3    = operationIDV3 + "/%s/accept-proposal"
	negotiateProposal   = operationID + "/%s/negotiate-proposal"
	negotiateProposalV3 = operationIDV3 + "/%s/negotiate-proposal"
	acceptOffer         = operationID + "/%s/accept-offer"
	acceptRequest       = operationID + "/%s/accept-request"
	acceptRequestV3     = operationIDV3 + "/%s/accept-request"
	acceptCredential    = operationID + "/%s/accept-credential"
	declineProposal     = operationID + "/%s/decline-proposal"
	declineRequest      = operationID + "/%s/decline-request"
	acceptProblemReport = operationID + "/%s/accept-problem-report"
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
	gs.Step(`^"([^"]*)" has established connection with "([^"]*)" through IssueCredential controller$`, s.EstablishConnection)
	gs.Step(`^"([^"]*)" has established DIDComm V2 connection with "([^"]*)" through IssueCredential controller$`, s.EstablishDIDCommV2Connection)
	gs.Step(`^"([^"]*)" requests credential from "([^"]*)" through IssueCredential controller$`, s.requestCredential)
	gs.Step(`^"([^"]*)" requests credential V3 from "([^"]*)" through IssueCredential controller$`, s.requestCredentialV3)
	gs.Step(`^"([^"]*)" sends an offer to the "([^"]*)" through IssueCredential controller$`, s.sendOffer)
	gs.Step(`^"([^"]*)" sends an offer V3 to the "([^"]*)" through IssueCredential controller$`, s.sendOfferV3)
	gs.Step(`^"([^"]*)" sends proposal credential to the "([^"]*)" through IssueCredential controller$`, s.sendProposal)
	gs.Step(`^"([^"]*)" sends proposal credential V3 to the "([^"]*)" through IssueCredential controller$`, s.sendProposalV3)
	gs.Step(`^"([^"]*)" accepts a proposal and sends an offer to the Holder through IssueCredential controller$`, s.acceptProposal)
	gs.Step(`^"([^"]*)" accepts a proposal V3 and sends an offer to the Holder through IssueCredential controller$`, s.acceptProposalV3)
	gs.Step(`^"([^"]*)" declines the proposal and requests redirect "([^"]*)" through IssueCredential controller$`, s.declineProposalWithRedirect)
	gs.Step(`^"([^"]*)" does not like the offer and sends a new proposal to the Issuer through IssueCredential controller$`, s.negotiateProposal)
	gs.Step(`^"([^"]*)" does not like the offer V3 and sends a new proposal to the Issuer through IssueCredential controller$`, s.negotiateProposalV3)
	gs.Step(`^"([^"]*)" accepts an offer and sends a request to the Issuer through IssueCredential controller$`, s.acceptOffer)
	gs.Step(`^"([^"]*)" accepts request and sends credential to the Holder through IssueCredential controller$`, s.acceptRequest)
	gs.Step(`^"([^"]*)" accepts request and sends credential to the Holder with redirect "([^"]*)" through IssueCredential controller$`, s.acceptRequestWithRedirect)
	gs.Step(`^"([^"]*)" declines the request and requests redirect "([^"]*)" through IssueCredential controller$`, s.declineRequestWithRedirect)
	gs.Step(`^"([^"]*)" accepts request V3 and sends credential to the Holder through IssueCredential controller$`, s.acceptRequestV3)
	gs.Step(`^"([^"]*)" accepts credential with name "([^"]*)" through IssueCredential controller$`, s.acceptCredential)
	gs.Step(`^"([^"]*)" checks that issued credential is being stored under "([^"]*)" name$`, s.validateCredential)
	gs.Step(`^"([^"]*)" accepts a problem report through IssueCredential controller$`, s.acceptProblemReport)
	gs.Step(`^"([^"]*)" validates issue credential state "([^"]*)" and redirect "([^"]*)" with status "([^"]*)" through IssueCredential controller$`, s.validateState)
}

// Options for sending and accepting messages.
type Options struct {
	Proposal   *client.ProposeCredentialV2
	ProposalV3 *client.ProposeCredentialV3
	Request    *client.RequestCredentialV2
	RequestV3  *client.RequestCredentialV3
	Offer      *client.OfferCredentialV2
	OfferV3    *client.OfferCredentialV3
}

// Option will configure Options.
type Option func(*Options)

// WithProposal sets the proposal to send.
func WithProposal(p *client.ProposeCredentialV2) Option {
	return func(o *Options) {
		o.Proposal = p
	}
}

// WithRequest sets the request to send or reply with.
func WithRequest(r *client.RequestCredentialV2) Option {
	return func(o *Options) {
		o.Request = r
	}
}

// WithOffer sets the offer to send or reply with.
func WithOffer(of *client.OfferCredentialV2) Option {
	return func(o *Options) {
		o.Offer = of
	}
}

// EstablishConnection will connect the two agents together.
func (s *ControllerSteps) EstablishConnection(holder, issuer string) error {
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

// EstablishDIDCommV2Connection will connect the two agents together with a DIDComm V2 connection.
func (s *ControllerSteps) EstablishDIDCommV2Connection(holder, issuer string) error {
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

	cs := connection.NewControllerSteps()
	cs.SetContext(s.bddContext)

	err = cs.SetConnectionToDIDCommV2(holder, connID)
	if err != nil {
		return fmt.Errorf("unable to set connection to DIDComm V2: %w", err)
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
	return s.RequestCredentialWithOpts(holder, issuer)
}

func (s *ControllerSteps) requestCredentialV3(holder, issuer string) error {
	return s.RequestCredentialV3WithOpts(holder, issuer)
}

// RequestCredentialWithOpts will send a default (empty) request unless one is provided using WithRequest.
func (s *ControllerSteps) RequestCredentialWithOpts(holder, issuer string, options ...Option) error {
	opts := &Options{
		Request: &client.RequestCredentialV2{},
	}

	for i := range options {
		options[i](opts)
	}

	url, ok := s.bddContext.GetControllerURL(holder)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", holder)
	}

	return postToURL(url+sendRequest, issuecredentialcmd.SendRequestArgsV2{
		MyDID:             s.did[holder],
		TheirDID:          s.did[issuer],
		RequestCredential: opts.Request,
	})
}

// RequestCredentialV3WithOpts will send a default (empty) request unless one is provided using WithRequest.
func (s *ControllerSteps) RequestCredentialV3WithOpts(holder, issuer string, options ...Option) error {
	opts := &Options{
		RequestV3: &client.RequestCredentialV3{},
	}

	for i := range options {
		options[i](opts)
	}

	url, ok := s.bddContext.GetControllerURL(holder)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", holder)
	}

	return postToURL(url+sendRequestV3, issuecredentialcmd.SendRequestArgsV3{
		MyDID:             s.did[holder],
		TheirDID:          s.did[issuer],
		RequestCredential: opts.RequestV3,
	})
}

func (s *ControllerSteps) sendOffer(issuer, holder string) error {
	return s.SendOfferWithOpts(issuer, holder)
}

func (s *ControllerSteps) sendOfferV3(issuer, holder string) error {
	return s.SendOfferV3WithOpts(issuer, holder)
}

// SendOfferWithOpts will send a default (empty) offer unless one is provided using WithOffer.
func (s *ControllerSteps) SendOfferWithOpts(issuer, holder string, options ...Option) error {
	opts := &Options{
		Offer: &client.OfferCredentialV2{},
	}

	for i := range options {
		options[i](opts)
	}

	url, ok := s.bddContext.GetControllerURL(issuer)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", issuer)
	}

	return postToURL(url+sendOffer, issuecredentialcmd.SendOfferArgsV2{
		MyDID:           s.did[issuer],
		TheirDID:        s.did[holder],
		OfferCredential: opts.Offer,
	})
}

// SendOfferV3WithOpts will send a default (empty) offer unless one is provided using WithOffer.
func (s *ControllerSteps) SendOfferV3WithOpts(issuer, holder string, options ...Option) error {
	opts := &Options{
		OfferV3: &client.OfferCredentialV3{},
	}

	for i := range options {
		options[i](opts)
	}

	url, ok := s.bddContext.GetControllerURL(issuer)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", issuer)
	}

	return postToURL(url+sendOfferV3, issuecredentialcmd.SendOfferArgsV3{
		MyDID:           s.did[issuer],
		TheirDID:        s.did[holder],
		OfferCredential: opts.OfferV3,
	})
}

func (s *ControllerSteps) sendProposal(holder, issuer string) error {
	return s.SendProposalWithOpts(holder, issuer)
}

func (s *ControllerSteps) sendProposalV3(holder, issuer string) error {
	return s.SendProposalV3WithOpts(holder, issuer)
}

// SendProposalWithOpts sends a default (empty) proposal unless one is provided using WithProposal.
func (s *ControllerSteps) SendProposalWithOpts(holder, issuer string, options ...Option) error {
	opts := &Options{
		Proposal: &client.ProposeCredentialV2{},
	}

	for i := range options {
		options[i](opts)
	}

	url, ok := s.bddContext.GetControllerURL(holder)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", holder)
	}

	return postToURL(url+sendProposal, issuecredentialcmd.SendProposalArgsV2{
		MyDID:             s.did[holder],
		TheirDID:          s.did[issuer],
		ProposeCredential: opts.Proposal,
	})
}

// SendProposalV3WithOpts sends a default (empty) proposal unless one is provided using WithProposal.
func (s *ControllerSteps) SendProposalV3WithOpts(holder, issuer string, options ...Option) error {
	opts := &Options{
		ProposalV3: &client.ProposeCredentialV3{},
	}

	for i := range options {
		options[i](opts)
	}

	url, ok := s.bddContext.GetControllerURL(holder)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", holder)
	}

	return postToURL(url+sendProposalV3, issuecredentialcmd.SendProposalArgsV3{
		MyDID:             s.did[holder],
		TheirDID:          s.did[issuer],
		ProposeCredential: opts.ProposalV3,
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

	return postToURL(url+fmt.Sprintf(acceptProposal, piid), issuecredentialcmd.AcceptProposalArgsV2{
		OfferCredential: &client.OfferCredentialV2{},
	})
}

func (s *ControllerSteps) acceptProposalV3(issuer string) error {
	url, ok := s.bddContext.GetControllerURL(issuer)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", issuer)
	}

	piid, err := s.actionPIID(issuer)
	if err != nil {
		return err
	}

	return postToURL(url+fmt.Sprintf(acceptProposalV3, piid), issuecredentialcmd.AcceptProposalArgsV3{
		OfferCredential: &client.OfferCredentialV3{},
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

	return postToURL(url+fmt.Sprintf(negotiateProposal, piid), issuecredentialcmd.NegotiateProposalArgsV2{
		ProposeCredential: &client.ProposeCredentialV2{},
	})
}

func (s *ControllerSteps) negotiateProposalV3(holder string) error {
	url, ok := s.bddContext.GetControllerURL(holder)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", holder)
	}

	piid, err := s.actionPIID(holder)
	if err != nil {
		return err
	}

	return postToURL(url+fmt.Sprintf(negotiateProposalV3, piid), issuecredentialcmd.NegotiateProposalArgsV3{
		ProposeCredential: &client.ProposeCredentialV3{},
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

	return s.AcceptOfferPIID(url, piid)
}

// AcceptOfferPIID invokes the endpoint on the url for accepting an offer with the piid.
func (s *ControllerSteps) AcceptOfferPIID(url, piid string) error {
	return postToURL(url+fmt.Sprintf(acceptOffer, piid), nil)
}

func (s *ControllerSteps) acceptRequest(issuer string) error {
	return s.acceptRequestWithRedirect(issuer, "")
}

func (s *ControllerSteps) acceptRequestWithRedirect(issuer, redirect string) error {
	url, ok := s.bddContext.GetControllerURL(issuer)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", issuer)
	}

	piid, err := s.actionPIID(issuer)
	if err != nil {
		return err
	}

	return postToURL(url+fmt.Sprintf(acceptRequest, piid), issuecredentialcmd.AcceptRequestArgsV2{
		IssueCredential: &client.IssueCredentialV2{
			CredentialsAttach: []decorator.Attachment{
				{Data: decorator.AttachmentData{JSON: getVCredential()}},
			},
			WebRedirect: &decorator.WebRedirect{
				Status: "OK",
				URL:    redirect,
			},
		},
	})
}

func (s *ControllerSteps) declineRequestWithRedirect(issuer, redirect string) error {
	url, ok := s.bddContext.GetControllerURL(issuer)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", issuer)
	}

	piid, err := s.actionPIID(issuer)
	if err != nil {
		return err
	}

	return postToURL(url+fmt.Sprintf(declineRequest, piid), issuecredentialcmd.DeclineRequestArgs{
		RedirectURL: redirect,
	})
}

func (s *ControllerSteps) declineProposalWithRedirect(issuer, redirect string) error {
	url, ok := s.bddContext.GetControllerURL(issuer)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", issuer)
	}

	piid, err := s.actionPIID(issuer)
	if err != nil {
		return err
	}

	return postToURL(url+fmt.Sprintf(declineProposal, piid), issuecredentialcmd.DeclineProposalArgs{
		RedirectURL: redirect,
	})
}

func (s *ControllerSteps) acceptProblemReport(agent string) error {
	url, ok := s.bddContext.GetControllerURL(agent)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", agent)
	}

	piid, err := s.actionPIID(agent)
	if err != nil {
		return err
	}

	return postToURL(url+fmt.Sprintf(acceptProblemReport, piid), issuecredentialcmd.AcceptProblemReportArgs{})
}

func (s *ControllerSteps) acceptRequestV3(issuer string) error {
	url, ok := s.bddContext.GetControllerURL(issuer)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", issuer)
	}

	piid, err := s.actionPIID(issuer)
	if err != nil {
		return err
	}

	return postToURL(url+fmt.Sprintf(acceptRequestV3, piid), issuecredentialcmd.AcceptRequestArgsV3{
		IssueCredential: &client.IssueCredentialV3{
			Attachments: []decorator.AttachmentV2{
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

	return s.AcceptCredentialPIID(credential, url, piid)
}

// AcceptCredentialPIID invokes the accept-credential endpoint on the url with the given piid and name.
func (s *ControllerSteps) AcceptCredentialPIID(name, url, piid string) error {
	s.nameToPIID[name] = piid

	return postToURL(url+fmt.Sprintf(acceptCredential, piid), issuecredentialcmd.AcceptCredentialArgs{
		Names: []string{name},
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

func (s *ControllerSteps) validateState(agent, state, redirect, status string) error {
	msg, err := util.PullEventsFromWebSocket(s.bddContext, agent,
		util.FilterTopic("issue-credential_states"),
		util.FilterStateID(state),
	)
	if err != nil {
		return fmt.Errorf("pull events from WebSocket: %w", err)
	}

	if redirect != msg.Message.Properties["url"] {
		return fmt.Errorf("failed redirect URL validation, expected[%s]: found[%s]",
			redirect, msg.Message.Properties["url"])
	}

	if status != msg.Message.Properties["status"] {
		return fmt.Errorf("failed status validation, expected[%s]: found[%s]",
			status, msg.Message.Properties["status"])
	}

	return nil
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
