/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/gorilla/mux"

	client "github.com/hyperledger/aries-framework-go/pkg/client/issuecredential"
	command "github.com/hyperledger/aries-framework-go/pkg/controller/command/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
)

const (
	operationID       = "/issuecredential"
	actions           = operationID + "/actions"
	sendOffer         = operationID + "/send-offer"
	sendProposal      = operationID + "/send-proposal"
	sendRequest       = operationID + "/send-request"
	acceptProposal    = operationID + "/{piid}/accept-proposal"
	declineProposal   = operationID + "/{piid}/decline-proposal"
	acceptOffer       = operationID + "/{piid}/accept-offer"
	declineOffer      = operationID + "/{piid}/decline-offer"
	negotiateProposal = operationID + "/{piid}/negotiate-proposal"
	acceptRequest     = operationID + "/{piid}/accept-request"
	declineRequest    = operationID + "/{piid}/decline-request"
	acceptCredential  = operationID + "/{piid}/accept-credential"
	declineCredential = operationID + "/{piid}/decline-credential"
)

// Operation is controller REST service controller for issue credential
type Operation struct {
	command  *command.Command
	handlers []rest.Handler
}

// New returns new issue credential rest client protocol instance
func New(ctx client.Provider) (*Operation, error) {
	cmd, err := command.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("issue credential command : %w", err)
	}

	o := &Operation{command: cmd}
	o.registerHandler()

	return o, nil
}

// GetRESTHandlers get all controller API handler available for this protocol service
func (c *Operation) GetRESTHandlers() []rest.Handler {
	return c.handlers
}

// registerHandler register handlers to be exposed from this protocol service as REST API endpoints
func (c *Operation) registerHandler() {
	// Add more protocol endpoints here to expose them as controller API endpoints
	c.handlers = []rest.Handler{
		cmdutil.NewHTTPHandler(actions, http.MethodGet, c.Actions),
		cmdutil.NewHTTPHandler(sendOffer, http.MethodPost, c.SendOffer),
		cmdutil.NewHTTPHandler(sendProposal, http.MethodPost, c.SendProposal),
		cmdutil.NewHTTPHandler(sendRequest, http.MethodPost, c.SendRequest),
		cmdutil.NewHTTPHandler(acceptProposal, http.MethodPost, c.AcceptProposal),
		cmdutil.NewHTTPHandler(declineProposal, http.MethodPost, c.DeclineProposal),
		cmdutil.NewHTTPHandler(acceptOffer, http.MethodPost, c.AcceptOffer),
		cmdutil.NewHTTPHandler(declineOffer, http.MethodPost, c.DeclineOffer),
		cmdutil.NewHTTPHandler(negotiateProposal, http.MethodPost, c.NegotiateProposal),
		cmdutil.NewHTTPHandler(acceptRequest, http.MethodPost, c.AcceptRequest),
		cmdutil.NewHTTPHandler(declineRequest, http.MethodPost, c.DeclineRequest),
		cmdutil.NewHTTPHandler(acceptCredential, http.MethodPost, c.AcceptCredential),
		cmdutil.NewHTTPHandler(declineCredential, http.MethodPost, c.DeclineCredential),
	}
}

// Actions swagger:route GET /issuecredential/actions issue-credential issueCredentialActions
//
// Returns pending actions that have not yet to be executed or cancelled.
//
// Responses:
//    default: genericError
//        200: issueCredentialActionsResponse
func (c *Operation) Actions(rw http.ResponseWriter, _ *http.Request) {
	rest.Execute(c.command.Actions, rw, nil)
}

// SendOffer swagger:route POST /issuecredential/send-offer issue-credential issueCredentialSendOffer
//
// Sends an offer.
//
// Responses:
//    default: genericError
//        200: issueCredentialSendOfferResponse
func (c *Operation) SendOffer(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(c.command.SendOffer, rw, req.Body)
}

// SendProposal swagger:route POST /issuecredential/send-proposal issue-credential issueCredentialSendProposal
//
// Sends a proposal.
//
// Responses:
//    default: genericError
//        200: issueCredentialSendProposalResponse
func (c *Operation) SendProposal(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(c.command.SendProposal, rw, req.Body)
}

// SendRequest swagger:route POST /issuecredential/send-request issue-credential issueCredentialSendRequest
//
// Sends a request.
//
// Responses:
//    default: genericError
//        200: issueCredentialSendRequestResponse
func (c *Operation) SendRequest(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(c.command.SendRequest, rw, req.Body)
}

// AcceptProposal swagger:route POST /issuecredential/{piid}/accept-proposal issue-credential issueCredentialAcceptProposal
//
// Accepts a proposal.
//
// Responses:
//    default: genericError
//        200: issueCredentialAcceptProposalResponse
func (c *Operation) AcceptProposal(rw http.ResponseWriter, req *http.Request) { // nolint: dupl
	var buf bytes.Buffer

	if req.Body != nil {
		// nolint: errcheck
		_, _ = io.Copy(&buf, req.Body)
	}

	if !isJSONMap(buf.Bytes()) {
		rest.SendHTTPStatusError(rw,
			http.StatusBadRequest,
			command.InvalidRequestErrorCode,
			errors.New("offer credential payload was not provided"),
		)

		return
	}

	rest.Execute(c.command.AcceptProposal, rw, bytes.NewBufferString(fmt.Sprintf(`{
		"piid":%q,
		"offer_credential": %s
	}`, mux.Vars(req)["piid"], buf.String())))
}

// DeclineProposal swagger:route POST /issuecredential/{piid}/decline-proposal issue-credential issueCredentialDeclineProposal
//
// Declines a proposal.
//
// Responses:
//    default: genericError
//        200: issueCredentialDeclineProposalResponse
func (c *Operation) DeclineProposal(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(c.command.DeclineProposal, rw, bytes.NewBufferString(fmt.Sprintf(`{
		"piid":%q,
		"reason":%q
	}`, mux.Vars(req)["piid"], req.URL.Query().Get("reason"))))
}

// AcceptOffer swagger:route POST /issuecredential/{piid}/accept-offer issue-credential issueCredentialAcceptOffer
//
// Accepts an offer.
//
// Responses:
//    default: genericError
//        200: issueCredentialAcceptOfferResponse
func (c *Operation) AcceptOffer(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(c.command.AcceptOffer, rw, bytes.NewBufferString(fmt.Sprintf(`{
		"piid":%q
	}`, mux.Vars(req)["piid"])))
}

// DeclineOffer swagger:route POST /issuecredential/{piid}/decline-offer issue-credential issueCredentialDeclineOffer
//
// Declines an offer.
//
// Responses:
//    default: genericError
//        200: issueCredentialDeclineOfferResponse
func (c *Operation) DeclineOffer(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(c.command.DeclineOffer, rw, bytes.NewBufferString(fmt.Sprintf(`{
		"piid":%q,
		"reason":%q
	}`, mux.Vars(req)["piid"], req.URL.Query().Get("reason"))))
}

// NegotiateProposal swagger:route POST /issuecredential/{piid}/negotiate-proposal issue-credential issueCredentialNegotiateProposal
//
// Is used when the Holder wants to negotiate about an offer he received.
//
// Responses:
//    default: genericError
//        200: issueCredentialNegotiateProposalResponse
func (c *Operation) NegotiateProposal(rw http.ResponseWriter, req *http.Request) { // nolint: dupl
	var buf bytes.Buffer

	if req.Body != nil {
		// nolint: errcheck
		_, _ = io.Copy(&buf, req.Body)
	}

	if !isJSONMap(buf.Bytes()) {
		rest.SendHTTPStatusError(rw,
			http.StatusBadRequest,
			command.InvalidRequestErrorCode,
			errors.New("propose credential payload was not provided"),
		)

		return
	}

	rest.Execute(c.command.NegotiateProposal, rw, bytes.NewBufferString(fmt.Sprintf(`{
		"piid":%q,
		"propose_credential": %s
	}`, mux.Vars(req)["piid"], buf.String())))
}

// AcceptRequest swagger:route POST /issuecredential/{piid}/accept-request issue-credential issueCredentialAcceptRequest
//
// Accepts a request.
//
// Responses:
//    default: genericError
//        200: issueCredentialAcceptRequestResponse
func (c *Operation) AcceptRequest(rw http.ResponseWriter, req *http.Request) { // nolint: dupl
	var buf bytes.Buffer

	if req.Body != nil {
		// nolint: errcheck
		_, _ = io.Copy(&buf, req.Body)
	}

	if !isJSONMap(buf.Bytes()) {
		rest.SendHTTPStatusError(rw,
			http.StatusBadRequest,
			command.InvalidRequestErrorCode,
			errors.New("issue credential payload was not provided"),
		)

		return
	}

	rest.Execute(c.command.AcceptRequest, rw, bytes.NewBufferString(fmt.Sprintf(`{
		"piid":%q,
		"issue_credential": %s
	}`, mux.Vars(req)["piid"], buf.String())))
}

// DeclineRequest swagger:route POST /issuecredential/{piid}/decline-request issue-credential issueCredentialDeclineRequest
//
// Declines a request.
//
// Responses:
//    default: genericError
//        200: issueCredentialDeclineRequestResponse
func (c *Operation) DeclineRequest(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(c.command.DeclineRequest, rw, bytes.NewBufferString(fmt.Sprintf(`{
		"piid":%q,
		"reason":%q
	}`, mux.Vars(req)["piid"], req.URL.Query().Get("reason"))))
}

// AcceptCredential swagger:route POST /issuecredential/{piid}/accept-credential issue-credential issueCredentialAcceptCredential
//
// Accepts a credential.
//
// Responses:
//    default: genericError
//        200: issueCredentialAcceptCredentialResponse
func (c *Operation) AcceptCredential(rw http.ResponseWriter, req *http.Request) { // nolint: dupl
	var buf bytes.Buffer

	if req.Body != nil {
		// nolint: errcheck
		_, _ = io.Copy(&buf, req.Body)
	}

	if !isJSONArray(buf.Bytes()) {
		rest.SendHTTPStatusError(rw,
			http.StatusBadRequest,
			command.InvalidRequestErrorCode,
			errors.New("names payload was not provided"),
		)

		return
	}

	rest.Execute(c.command.AcceptCredential, rw, bytes.NewBufferString(fmt.Sprintf(`{
		"piid":%q,
		"names": %s
	}`, mux.Vars(req)["piid"], buf.String())))
}

// DeclineCredential swagger:route POST /issuecredential/{piid}/decline-credential issue-credential issueCredentialDeclineCredential
//
// Declines a credential.
//
// Responses:
//    default: genericError
//        200: issueCredentialDeclineCredentialResponse
func (c *Operation) DeclineCredential(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(c.command.DeclineCredential, rw, bytes.NewBufferString(fmt.Sprintf(`{
		"piid":%q,
		"reason":%q
	}`, mux.Vars(req)["piid"], req.URL.Query().Get("reason"))))
}

func isJSONMap(data []byte) bool {
	var v struct{}
	return isJSON(data, &v)
}

func isJSON(data []byte, v interface{}) bool {
	return json.Unmarshal(data, &v) == nil
}

func isJSONArray(data []byte) bool {
	var v []interface{}
	return isJSON(data, &v)
}
