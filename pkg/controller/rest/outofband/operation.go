/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofband

import (
	"fmt"
	"net/http"

	client "github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	command "github.com/hyperledger/aries-framework-go/pkg/controller/command/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
)

const (
	operationID      = "/outofband"
	createRequest    = operationID + "/create-request"
	createInvitation = operationID + "/create-invitation"
	acceptRequest    = operationID + "/accept-request"
	acceptInvitation = operationID + "/accept-invitation"
)

// Operation is controller REST service controller for outofband
type Operation struct {
	command  *command.Command
	handlers []rest.Handler
}

// New returns new outofband rest client protocol instance
func New(ctx client.Provider) (*Operation, error) {
	cmd, err := command.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("outofband command : %w", err)
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
		cmdutil.NewHTTPHandler(createRequest, http.MethodPost, c.CreateRequest),
		cmdutil.NewHTTPHandler(createInvitation, http.MethodPost, c.CreateInvitation),
		cmdutil.NewHTTPHandler(acceptRequest, http.MethodPost, c.AcceptRequest),
		cmdutil.NewHTTPHandler(acceptInvitation, http.MethodPost, c.AcceptInvitation),
	}
}

// CreateRequest swagger:route POST /outofband/create-request outofband outofbandCreateRequest
//
// Creates a request.
//
// Responses:
//    default: genericError
//        200: outofbandCreateRequestResponse
func (c *Operation) CreateRequest(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(c.command.CreateRequest, rw, req.Body)
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

// AcceptRequest swagger:route POST /outofband/accept-request outofband outofbandAcceptRequest
//
// Accepts a request.
//
// Responses:
//    default: genericError
//        200: outofbandAcceptRequestResponse
func (c *Operation) AcceptRequest(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(c.command.AcceptRequest, rw, req.Body)
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
