/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/gorilla/mux"

	client "github.com/hyperledger/aries-framework-go/pkg/client/presentproof"
	command "github.com/hyperledger/aries-framework-go/pkg/controller/command/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
)

const (
	operationID                  = "/presentproof"
	actions                      = operationID + "/actions"
	sendRequestPresentation      = operationID + "/send-request-presentation"
	sendProposePresentation      = operationID + "/send-propose-presentation"
	acceptRequestPresentation    = operationID + "/{piid}/accept-request-presentation"
	negotiateRequestPresentation = operationID + "/{piid}/negotiate-request-presentation"
	declineRequestPresentation   = operationID + "/{piid}/decline-request-presentation"
	acceptProposePresentation    = operationID + "/{piid}/accept-propose-presentation"
	declineProposePresentation   = operationID + "/{piid}/decline-propose-presentation"
	acceptPresentation           = operationID + "/{piid}/accept-presentation"
	declinePresentation          = operationID + "/{piid}/decline-presentation"
)

// Operation is controller REST service controller for present proof
type Operation struct {
	command  *command.Command
	handlers []rest.Handler
}

// New returns new present proof rest client protocol instance
func New(ctx client.Provider) (*Operation, error) {
	cmd, err := command.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("present proof command : %w", err)
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
		cmdutil.NewHTTPHandler(sendRequestPresentation, http.MethodPost, c.SendRequestPresentation),
		cmdutil.NewHTTPHandler(sendProposePresentation, http.MethodPost, c.SendProposePresentation),
		cmdutil.NewHTTPHandler(acceptRequestPresentation, http.MethodPost, c.AcceptRequestPresentation),
		cmdutil.NewHTTPHandler(negotiateRequestPresentation, http.MethodPost, c.NegotiateRequestPresentation),
		cmdutil.NewHTTPHandler(declineRequestPresentation, http.MethodPost, c.DeclineRequestPresentation),
		cmdutil.NewHTTPHandler(acceptProposePresentation, http.MethodPost, c.AcceptProposePresentation),
		cmdutil.NewHTTPHandler(declineProposePresentation, http.MethodPost, c.DeclineProposePresentation),
		cmdutil.NewHTTPHandler(acceptPresentation, http.MethodPost, c.AcceptPresentation),
		cmdutil.NewHTTPHandler(declinePresentation, http.MethodPost, c.DeclinePresentation),
	}
}

// Actions swagger:route GET /presentproof/actions present-proof presentProofActions
//
// Returns pending actions that have not yet to be executed or cancelled.
//
// Responses:
//    default: genericError
//        200: presentProofActionsResponse
func (c *Operation) Actions(rw http.ResponseWriter, _ *http.Request) {
	rest.Execute(c.command.Actions, rw, nil)
}

// SendRequestPresentation swagger:route POST /presentproof/send-request-presentation present-proof presentProofSendRequestPresentation
//
// Sends a request presentation.
//
// Responses:
//    default: genericError
//        200: presentProofSendRequestPresentationResponse
func (c *Operation) SendRequestPresentation(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(c.command.SendRequestPresentation, rw, req.Body)
}

// SendProposePresentation swagger:route POST /presentproof/send-propose-presentation present-proof presentProofSendProposePresentation
//
// Sends a propose presentation.
//
// Responses:
//    default: genericError
//        200: presentProofSendProposePresentationResponse
func (c *Operation) SendProposePresentation(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(c.command.SendProposePresentation, rw, req.Body)
}

// AcceptRequestPresentation swagger:route POST /presentproof/{piid}/accept-request-presentation present-proof presentProofAcceptRequestPresentation
//
// Accepts a request presentation.
//
// Responses:
//    default: genericError
//        200: presentProofAcceptRequestPresentationResponse
func (c *Operation) AcceptRequestPresentation(rw http.ResponseWriter, req *http.Request) { // nolint: dupl
	var buf bytes.Buffer

	if req.Body != nil {
		// nolint: errcheck
		_, _ = io.Copy(&buf, req.Body)
	}

	if !isJSONMap(buf.Bytes()) {
		rest.SendHTTPStatusError(rw,
			http.StatusBadRequest,
			command.InvalidRequestErrorCode,
			errors.New("presentation payload was not provided"),
		)

		return
	}

	rest.Execute(c.command.AcceptRequestPresentation, rw, bytes.NewBufferString(fmt.Sprintf(`{
		"piid":%q,
		"presentation": %s
	}`, mux.Vars(req)["piid"], buf.String())))
}

// AcceptProposePresentation swagger:route POST /presentproof/{piid}/accept-propose-presentation present-proof presentProofAcceptProposePresentation
//
// Accepts a propose presentation.
//
// Responses:
//    default: genericError
//        200: presentProofAcceptProposePresentationResponse
func (c *Operation) AcceptProposePresentation(rw http.ResponseWriter, req *http.Request) { // nolint: dupl
	var buf bytes.Buffer

	if req.Body != nil {
		// nolint: errcheck
		_, _ = io.Copy(&buf, req.Body)
	}

	if !isJSONMap(buf.Bytes()) {
		rest.SendHTTPStatusError(rw,
			http.StatusBadRequest,
			command.InvalidRequestErrorCode,
			errors.New("request presentation payload was not provided"),
		)

		return
	}

	rest.Execute(c.command.AcceptProposePresentation, rw, bytes.NewBufferString(fmt.Sprintf(`{
		"piid":%q,
		"request_presentation": %s
	}`, mux.Vars(req)["piid"], buf.String())))
}

// AcceptPresentation swagger:route POST /presentproof/{piid}/accept-presentation present-proof presentProofAcceptPresentation
//
// Accepts a presentation.
//
// Responses:
//    default: genericError
//        200: presentProofAcceptPresentationResponse
func (c *Operation) AcceptPresentation(rw http.ResponseWriter, req *http.Request) { // nolint: dupl
	rest.Execute(c.command.AcceptPresentation, rw, bytes.NewBufferString(fmt.Sprintf(`{
		"piid":%q
	}`, mux.Vars(req)["piid"])))
}

// NegotiateRequestPresentation swagger:route POST /presentproof/{piid}/negotiate-request-presentation present-proof presentProofNegotiateRequestPresentation
//
// Is used by the Prover to counter a presentation request they received with a proposal.
//
// Responses:
//    default: genericError
//        200: presentProofNegotiateRequestPresentationResponse
func (c *Operation) NegotiateRequestPresentation(rw http.ResponseWriter, req *http.Request) { // nolint: dupl
	var buf bytes.Buffer

	if req.Body != nil {
		// nolint: errcheck
		_, _ = io.Copy(&buf, req.Body)
	}

	if !isJSONMap(buf.Bytes()) {
		rest.SendHTTPStatusError(rw,
			http.StatusBadRequest,
			command.InvalidRequestErrorCode,
			errors.New("propose presentation payload was not provided"),
		)

		return
	}

	rest.Execute(c.command.NegotiateRequestPresentation, rw, bytes.NewBufferString(fmt.Sprintf(`{
		"piid":%q,
		"propose_presentation": %s
	}`, mux.Vars(req)["piid"], buf.String())))
}

// DeclineRequestPresentation swagger:route POST /presentproof/{piid}/decline-request-presentation present-proof presentProofDeclineRequestPresentation
//
// Declines a request presentation.
//
// Responses:
//    default: genericError
//        200: presentProofDeclineRequestPresentationResponse
func (c *Operation) DeclineRequestPresentation(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(c.command.DeclineRequestPresentation, rw, bytes.NewBufferString(fmt.Sprintf(`{
		"piid":%q,
		"reason":%q
	}`, mux.Vars(req)["piid"], req.URL.Query().Get("reason"))))
}

// DeclineProposePresentation swagger:route POST /presentproof/{piid}/decline-propose-presentation present-proof presentProofDeclineProposePresentation
//
// Declines a propose presentation.
//
// Responses:
//    default: genericError
//        200: presentProofDeclineProposePresentationResponse
func (c *Operation) DeclineProposePresentation(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(c.command.DeclineProposePresentation, rw, bytes.NewBufferString(fmt.Sprintf(`{
		"piid":%q,
		"reason":%q
	}`, mux.Vars(req)["piid"], req.URL.Query().Get("reason"))))
}

// DeclinePresentation swagger:route POST /presentproof/{piid}/decline-presentation present-proof presentProofDeclinePresentation
//
// Declines a presentation.
//
// Responses:
//    default: genericError
//        200: presentProofDeclinePresentationResponse
func (c *Operation) DeclinePresentation(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(c.command.DeclinePresentation, rw, bytes.NewBufferString(fmt.Sprintf(`{
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
