/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	client "github.com/hyperledger/aries-framework-go/pkg/client/introduce"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/introduce"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
)

// constants for operation introduce.
const (
	OperationID                       = "/introduce"
	Actions                           = OperationID + "/actions"
	SendProposal                      = OperationID + "/send-proposal"
	SendProposalWithOOBRequest        = OperationID + "/send-proposal-with-oob-request"
	SendRequest                       = OperationID + "/send-request"
	AcceptProposalWithOOBRequest      = OperationID + "/{piid}/accept-proposal-with-oob-request"
	AcceptProposal                    = OperationID + "/{piid}/accept-proposal"
	AcceptRequestWithPublicOOBRequest = OperationID + "/{piid}/accept-request-with-public-oob-request"
	AcceptRequestWithRecipients       = OperationID + "/{piid}/accept-request-with-recipients"
	DeclineProposal                   = OperationID + "/{piid}/decline-proposal"
	DeclineRequest                    = OperationID + "/{piid}/decline-request"
	AcceptProblemReport               = OperationID + "/{piid}/accept-problem-report"
)

// Operation is controller REST service controller for the introduce.
type Operation struct {
	command  *introduce.Command
	handlers []rest.Handler
}

// New returns new introduce rest client protocol instance.
func New(ctx client.Provider, notifier command.Notifier) (*Operation, error) {
	cmd, err := introduce.New(ctx, notifier)
	if err != nil {
		return nil, fmt.Errorf("introduce command : %w", err)
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
		cmdutil.NewHTTPHandler(SendProposal, http.MethodPost, c.SendProposal),
		cmdutil.NewHTTPHandler(SendProposalWithOOBRequest, http.MethodPost, c.SendProposalWithOOBRequest),
		cmdutil.NewHTTPHandler(SendRequest, http.MethodPost, c.SendRequest),
		cmdutil.NewHTTPHandler(AcceptProposalWithOOBRequest, http.MethodPost, c.AcceptProposalWithOOBRequest),
		cmdutil.NewHTTPHandler(AcceptProposal, http.MethodPost, c.AcceptProposal),
		cmdutil.NewHTTPHandler(AcceptRequestWithPublicOOBRequest, http.MethodPost, c.AcceptRequestWithPublicOOBRequest),
		cmdutil.NewHTTPHandler(AcceptRequestWithRecipients, http.MethodPost, c.AcceptRequestWithRecipients),
		cmdutil.NewHTTPHandler(DeclineProposal, http.MethodPost, c.DeclineProposal),
		cmdutil.NewHTTPHandler(DeclineRequest, http.MethodPost, c.DeclineRequest),
		cmdutil.NewHTTPHandler(AcceptProblemReport, http.MethodPost, c.AcceptProblemReport),
	}
}

// Actions swagger:route GET /introduce/actions introduce introduceActions
//
// Returns pending actions that have not yet to be executed or cancelled.
//
// Responses:
//    default: genericError
//        200: introduceActionsResponse
func (c *Operation) Actions(rw http.ResponseWriter, _ *http.Request) {
	rest.Execute(c.command.Actions, rw, nil)
}

// SendProposal swagger:route POST /introduce/send-proposal introduce introduceSendProposal
//
// Sends a proposal.
//
// Responses:
//    default: genericError
//        200: introduceSendProposalResponse
func (c *Operation) SendProposal(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(c.command.SendProposal, rw, req.Body)
}

// SendProposalWithOOBRequest swagger:route POST /introduce/send-proposal-with-oob-request introduce introduceSendProposalWithOOBRequest
//
// Sends a proposal with OOBRequest.
//
// Responses:
//    default: genericError
//        200: introduceSendProposalWithOOBRequestResponse
func (c *Operation) SendProposalWithOOBRequest(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(c.command.SendProposalWithOOBRequest, rw, req.Body)
}

// SendRequest swagger:route POST /introduce/send-request introduce introduceSendRequest
//
// Sends a request.
//
// Responses:
//    default: genericError
//        200: introduceSendRequestResponse
func (c *Operation) SendRequest(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(c.command.SendRequest, rw, req.Body)
}

// AcceptProposalWithOOBRequest swagger:route POST /introduce/{piid}/accept-proposal-with-oob-request introduce introduceAcceptProposalWithOOBRequest
//
// Accepts a proposal with OOBRequest.
//
// Responses:
//    default: genericError
//        200: introduceAcceptProposalWithOOBRequestResponse
func (c *Operation) AcceptProposalWithOOBRequest(rw http.ResponseWriter, req *http.Request) {
	if ok, r := toCommandRequest(rw, req); ok {
		rest.Execute(c.command.AcceptProposalWithOOBRequest, rw, r)
	}
}

// AcceptProposal swagger:route POST /introduce/{piid}/accept-proposal introduce introduceAcceptProposal
//
// Accepts a proposal.
//
// Responses:
//    default: genericError
//        200: introduceAcceptProposalResponse
func (c *Operation) AcceptProposal(rw http.ResponseWriter, req *http.Request) {
	payload := fmt.Sprintf(`{"piid":%q}`, mux.Vars(req)["piid"])
	rest.Execute(c.command.AcceptProposal, rw, bytes.NewBufferString(payload))
}

// AcceptRequestWithPublicOOBRequest swagger:route POST /introduce/{piid}/accept-request-with-public-oob-request introduce introduceAcceptRequestWithPublicOOBRequest
//
// Accept a request with public OOBRequest.
//
// Responses:
//    default: genericError
//        200: introduceAcceptRequestWithPublicOOBRequestResponse
func (c *Operation) AcceptRequestWithPublicOOBRequest(rw http.ResponseWriter, req *http.Request) {
	if ok, r := toCommandRequest(rw, req); ok {
		rest.Execute(c.command.AcceptRequestWithPublicOOBRequest, rw, r)
	}
}

// AcceptRequestWithRecipients swagger:route POST /introduce/{piid}/accept-request-with-recipients introduce introduceAcceptRequestWithRecipients
//
// Accept a request with recipients.
//
// Responses:
//    default: genericError
//        200: introduceAcceptRequestWithRecipientsResponse
func (c *Operation) AcceptRequestWithRecipients(rw http.ResponseWriter, req *http.Request) {
	if ok, r := toCommandRequest(rw, req); ok {
		rest.Execute(c.command.AcceptRequestWithRecipients, rw, r)
	}
}

// DeclineProposal swagger:route POST /introduce/{piid}/decline-proposal introduce introduceDeclineProposal
//
// Declines a proposal.
//
// Responses:
//    default: genericError
//        200: introduceDeclineProposalResponse
func (c *Operation) DeclineProposal(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(c.command.DeclineProposal, rw, bytes.NewBufferString(fmt.Sprintf(`{
		"piid":%q,
		"reason":%q
	}`, mux.Vars(req)["piid"], req.URL.Query().Get("reason"))))
}

// DeclineRequest swagger:route POST /introduce/{piid}/decline-request introduce introduceDeclineRequest
//
// Declines a request.
//
// Responses:
//    default: genericError
//        200: introduceDeclineRequestResponse
func (c *Operation) DeclineRequest(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(c.command.DeclineRequest, rw, bytes.NewBufferString(fmt.Sprintf(`{
		"piid":%q,
		"reason":%q
	}`, mux.Vars(req)["piid"], req.URL.Query().Get("reason"))))
}

// AcceptProblemReport swagger:route POST /introduce/{piid}/accept-problem-report introduce introduceAcceptProblemReport
//
// Accepts a problem report.
//
// Responses:
//    default: genericError
//        200: introduceAcceptProblemReportResponse
func (c *Operation) AcceptProblemReport(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(c.command.AcceptProblemReport, rw, bytes.NewBufferString(fmt.Sprintf(`{
		"piid":%q
	}`, mux.Vars(req)["piid"])))
}

func toCommandRequest(rw http.ResponseWriter, req *http.Request) (bool, io.Reader) {
	var buf bytes.Buffer

	if req.Body != nil {
		// nolint: errcheck
		_, _ = io.Copy(&buf, req.Body)
	}

	if !isJSONMap(buf.Bytes()) {
		rest.SendHTTPStatusError(rw,
			http.StatusBadRequest,
			introduce.InvalidRequestErrorCode,
			errors.New("payload was not provided"),
		)

		return false, nil
	}

	ending := fmt.Sprintf(`"piid":%q}`, mux.Vars(req)["piid"])

	payload := strings.TrimSpace(buf.String())
	if payload == "{}" {
		payload = "{" + ending
	} else {
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
