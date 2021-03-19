/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofband

import (
	"bytes"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"

	client "github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
)

// constants for the OutOfBand protocol operations.
const (
	OperationID      = "/outofband"
	CreateInvitation = OperationID + "/create-invitation"
	AcceptRequest    = OperationID + "/accept-request"
	AcceptInvitation = OperationID + "/accept-invitation"
	Actions          = OperationID + "/actions"
	ActionContinue   = OperationID + "/{piid}/action-continue"
	ActionStop       = OperationID + "/{piid}/action-stop"
)

// Operation is controller REST service controller for outofband.
type Operation struct {
	command  *outofband.Command
	handlers []rest.Handler
}

// New returns new outofband rest client protocol instance.
func New(ctx client.Provider, notifier command.Notifier) (*Operation, error) {
	cmd, err := outofband.New(ctx, notifier)
	if err != nil {
		return nil, fmt.Errorf("outofband command : %w", err)
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
		cmdutil.NewHTTPHandler(CreateInvitation, http.MethodPost, c.CreateInvitation),
		cmdutil.NewHTTPHandler(AcceptInvitation, http.MethodPost, c.AcceptInvitation),
		cmdutil.NewHTTPHandler(Actions, http.MethodGet, c.Actions),
		cmdutil.NewHTTPHandler(ActionContinue, http.MethodPost, c.ActionContinue),
		cmdutil.NewHTTPHandler(ActionStop, http.MethodPost, c.ActionStop),
	}
}

// Actions swagger:route GET /outofband/actions outofband outofbandActions
//
// Returns pending actions that have not yet to be executed or cancelled.
//
// Responses:
//    default: genericError
//        200: outofbandActionsResponse
func (c *Operation) Actions(rw http.ResponseWriter, _ *http.Request) {
	rest.Execute(c.command.Actions, rw, nil)
}

// ActionContinue swagger:route POST /outofband/{piid}/action-continue outofband outofbandActionContinue
//
// Allows continuing with the protocol after an action event was triggered.
//
// Responses:
//    default: genericError
//        200: outofbandActionContinueResponse
func (c *Operation) ActionContinue(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(c.command.ActionContinue, rw, bytes.NewBufferString(fmt.Sprintf(`{
		"piid":%q,
		"label": %q,
		"router_connections": %q
	}`, mux.Vars(req)["piid"], req.URL.Query().Get("label"), req.URL.Query().Get("router_connections"))))
}

// ActionStop swagger:route POST /outofband/{piid}/action-stop outofband outofbandActionStop
//
// Stops the protocol after an action event was triggered.
//
// Responses:
//    default: genericError
//        200: outofbandActionStopResponse
func (c *Operation) ActionStop(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(c.command.ActionStop, rw, bytes.NewBufferString(fmt.Sprintf(`{
		"piid":%q,
		"reason": %q
	}`, mux.Vars(req)["piid"], req.URL.Query().Get("reason"))))
}

// CreateInvitation swagger:route POST /outofband/create-invitation outofband outofbandCreateInvitation
//
// Creates an invitation.
//
// Responses:
//    default: genericError
//        200: outofbandCreateInvitationResponse
func (c *Operation) CreateInvitation(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(c.command.CreateInvitation, rw, req.Body)
}

// AcceptInvitation swagger:route POST /outofband/accept-invitation outofband outofbandAcceptInvitation
//
// Accepts an invitation.
//
// Responses:
//    default: genericError
//        200: outofbandAcceptInvitationResponse
func (c *Operation) AcceptInvitation(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(c.command.AcceptInvitation, rw, req.Body)
}
