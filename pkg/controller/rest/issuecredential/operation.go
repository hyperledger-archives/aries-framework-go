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
	"strings"

	"github.com/gorilla/mux"

	"github.com/hyperledger/aries-framework-go/pkg/client/issuecredential/rfc0593"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
)

// constants for issue credential endpoints.
const (
	OperationID         = "/issuecredential"
	OperationIDV3       = OperationID + "/v3"
	Actions             = OperationID + "/actions"
	SendOffer           = OperationID + "/send-offer"
	SendOfferV3         = OperationIDV3 + "/send-offer"
	SendProposal        = OperationID + "/send-proposal"
	SendProposalV3      = OperationIDV3 + "/send-proposal"
	SendRequest         = OperationID + "/send-request"
	SendRequestV3       = OperationIDV3 + "/send-request"
	AcceptProposal      = OperationID + "/{piid}/accept-proposal"
	AcceptProposalV3    = OperationIDV3 + "/{piid}/accept-proposal"
	DeclineProposal     = OperationID + "/{piid}/decline-proposal"
	AcceptOffer         = OperationID + "/{piid}/accept-offer"
	DeclineOffer        = OperationID + "/{piid}/decline-offer"
	NegotiateProposal   = OperationID + "/{piid}/negotiate-proposal"
	NegotiateProposalV3 = OperationIDV3 + "/{piid}/negotiate-proposal"
	AcceptRequest       = OperationID + "/{piid}/accept-request"
	AcceptRequestV3     = OperationIDV3 + "/{piid}/accept-request"
	DeclineRequest      = OperationID + "/{piid}/decline-request"
	AcceptCredential    = OperationID + "/{piid}/accept-credential"
	DeclineCredential   = OperationID + "/{piid}/decline-credential"
	AcceptProblemReport = OperationID + "/{piid}/accept-problem-report"
)

// Operation is controller REST service controller for issue credential.
type Operation struct {
	command  *issuecredential.Command
	handlers []rest.Handler
}

// New returns new issue credential rest client protocol instance.
func New(ctx issuecredential.Provider, notifier command.Notifier, enableRFC0593 rfc0593.Provider) (*Operation, error) {
	var options []issuecredential.Option

	if enableRFC0593 != nil {
		options = append(options, issuecredential.WithAutoExecuteRFC0593(enableRFC0593))
	}

	cmd, err := issuecredential.New(ctx, notifier, options...)
	if err != nil {
		return nil, fmt.Errorf("issue credential command : %w", err)
	}

	o := &Operation{command: cmd}
	o.registerHandler()

	return o, nil
}

// GetRESTHandlers get all controller API handler available for this protocol service.
func (c *Operation) GetRESTHandlers() []rest.Handler {
	return c.handlers
}

// registerHandler register handlers to be exposed from this protocol service as REST API endpoints.
func (c *Operation) registerHandler() {
	// Add more protocol endpoints here to expose them as controller API endpoints
	c.handlers = []rest.Handler{
		cmdutil.NewHTTPHandler(Actions, http.MethodGet, c.Actions),
		cmdutil.NewHTTPHandler(SendOffer, http.MethodPost, c.SendOffer),
		cmdutil.NewHTTPHandler(SendOfferV3, http.MethodPost, c.SendOffer),
		cmdutil.NewHTTPHandler(SendProposal, http.MethodPost, c.SendProposal),
		cmdutil.NewHTTPHandler(SendProposalV3, http.MethodPost, c.SendProposal),
		cmdutil.NewHTTPHandler(SendRequest, http.MethodPost, c.SendRequest),
		cmdutil.NewHTTPHandler(SendRequestV3, http.MethodPost, c.SendRequest),
		cmdutil.NewHTTPHandler(AcceptProposal, http.MethodPost, c.AcceptProposal),
		cmdutil.NewHTTPHandler(AcceptProposalV3, http.MethodPost, c.AcceptProposal),
		cmdutil.NewHTTPHandler(DeclineProposal, http.MethodPost, c.DeclineProposal),
		cmdutil.NewHTTPHandler(AcceptOffer, http.MethodPost, c.AcceptOffer),
		cmdutil.NewHTTPHandler(DeclineOffer, http.MethodPost, c.DeclineOffer),
		cmdutil.NewHTTPHandler(NegotiateProposal, http.MethodPost, c.NegotiateProposal),
		cmdutil.NewHTTPHandler(NegotiateProposalV3, http.MethodPost, c.NegotiateProposal),
		cmdutil.NewHTTPHandler(AcceptRequest, http.MethodPost, c.AcceptRequest),
		cmdutil.NewHTTPHandler(AcceptRequestV3, http.MethodPost, c.AcceptRequest),
		cmdutil.NewHTTPHandler(DeclineRequest, http.MethodPost, c.DeclineRequest),
		cmdutil.NewHTTPHandler(AcceptCredential, http.MethodPost, c.AcceptCredential),
		cmdutil.NewHTTPHandler(DeclineCredential, http.MethodPost, c.DeclineCredential),
		cmdutil.NewHTTPHandler(AcceptProblemReport, http.MethodPost, c.AcceptProblemReport),
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
	if ok, r := toCommandRequest(rw, req, true); ok {
		rest.Execute(c.command.SendOffer, rw, r)
	}
}

// SendProposal swagger:route POST /issuecredential/send-proposal issue-credential issueCredentialSendProposal
//
// Sends a proposal.
//
// Responses:
//    default: genericError
//        200: issueCredentialSendProposalResponse
func (c *Operation) SendProposal(rw http.ResponseWriter, req *http.Request) {
	if ok, r := toCommandRequest(rw, req, true); ok {
		rest.Execute(c.command.SendProposal, rw, r)
	}
}

// SendRequest swagger:route POST /issuecredential/send-request issue-credential issueCredentialSendRequest
//
// Sends a request.
//
// Responses:
//    default: genericError
//        200: issueCredentialSendRequestResponse
func (c *Operation) SendRequest(rw http.ResponseWriter, req *http.Request) {
	if ok, r := toCommandRequest(rw, req, true); ok {
		rest.Execute(c.command.SendRequest, rw, r)
	}
}

// AcceptProposal swagger:route POST /issuecredential/{piid}/accept-proposal issue-credential issueCredentialAcceptProposal
//
// Accepts a proposal.
//
// Responses:
//    default: genericError
//        200: issueCredentialAcceptProposalResponse
func (c *Operation) AcceptProposal(rw http.ResponseWriter, req *http.Request) {
	if ok, r := toCommandRequest(rw, req, true); ok {
		rest.Execute(c.command.AcceptProposal, rw, r)
	}
}

// DeclineProposal swagger:route POST /issuecredential/{piid}/decline-proposal issue-credential issueCredentialDeclineProposal
//
// Declines a proposal.
//
// Responses:
//    default: genericError
//        200: issueCredentialDeclineProposalResponse
func (c *Operation) DeclineProposal(rw http.ResponseWriter, req *http.Request) {
	if ok, r := toCommandRequest(rw, req, false); ok {
		rest.Execute(c.command.DeclineProposal, rw, r)
	}
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

// AcceptProblemReport swagger:route POST /issuecredential/{piid}/accept-problem-report issue-credential issueCredentialAcceptProblemReport
//
// Accepts a problem report.
//
// Responses:
//    default: genericError
//        200: issueCredentialAcceptProblemReportResponse
func (c *Operation) AcceptProblemReport(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(c.command.AcceptProblemReport, rw, bytes.NewBufferString(fmt.Sprintf(`{
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
	if ok, r := toCommandRequest(rw, req, false); ok {
		rest.Execute(c.command.DeclineOffer, rw, r)
	}
}

// NegotiateProposal swagger:route POST /issuecredential/{piid}/negotiate-proposal issue-credential issueCredentialNegotiateProposal
//
// Is used when the Holder wants to negotiate about an offer he received.
//
// Responses:
//    default: genericError
//        200: issueCredentialNegotiateProposalResponse
func (c *Operation) NegotiateProposal(rw http.ResponseWriter, req *http.Request) {
	if ok, r := toCommandRequest(rw, req, true); ok {
		rest.Execute(c.command.NegotiateProposal, rw, r)
	}
}

// AcceptRequest swagger:route POST /issuecredential/{piid}/accept-request issue-credential issueCredentialAcceptRequest
//
// Accepts a request.
//
// Responses:
//    default: genericError
//        200: issueCredentialAcceptRequestResponse
func (c *Operation) AcceptRequest(rw http.ResponseWriter, req *http.Request) {
	if ok, r := toCommandRequest(rw, req, true); ok {
		rest.Execute(c.command.AcceptRequest, rw, r)
	}
}

// DeclineRequest swagger:route POST /issuecredential/{piid}/decline-request issue-credential issueCredentialDeclineRequest
//
// Declines a request.
//
// Responses:
//    default: genericError
//        200: issueCredentialDeclineRequestResponse
func (c *Operation) DeclineRequest(rw http.ResponseWriter, req *http.Request) {
	if ok, r := toCommandRequest(rw, req, false); ok {
		rest.Execute(c.command.DeclineRequest, rw, r)
	}
}

// AcceptCredential swagger:route POST /issuecredential/{piid}/accept-credential issue-credential issueCredentialAcceptCredential
//
// Accepts a credential.
//
// Responses:
//    default: genericError
//        200: issueCredentialAcceptCredentialResponse
func (c *Operation) AcceptCredential(rw http.ResponseWriter, req *http.Request) {
	if ok, r := toCommandRequest(rw, req, true); ok {
		rest.Execute(c.command.AcceptCredential, rw, r)
	}
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

func toCommandRequest(rw http.ResponseWriter, req *http.Request, payloadRequired bool) (bool, io.Reader) {
	var buf bytes.Buffer

	if req.Body != nil {
		// nolint: errcheck
		_, _ = io.Copy(&buf, req.Body)
	}

	if payloadRequired && !isJSONMap(buf.Bytes()) {
		rest.SendHTTPStatusError(rw,
			http.StatusBadRequest,
			issuecredential.InvalidRequestErrorCode,
			errors.New("payload was not provided"),
		)

		return false, nil
	}

	ending := fmt.Sprintf(`"piid":%q}`, mux.Vars(req)["piid"])

	var payload string

	switch strings.TrimSpace(buf.String()) {
	case "", "{}":
		payload = "{" + ending
	default:
		payload = buf.String()[:buf.Len()-1] + "," + ending
	}

	return true, bytes.NewBufferString(payload)
}

func isJSONMap(data []byte) bool {
	var v struct{}
	return isJSON(data, &v)
}

func isJSON(data []byte, v interface{}) bool {
	return json.Unmarshal(data, &v) == nil
}
