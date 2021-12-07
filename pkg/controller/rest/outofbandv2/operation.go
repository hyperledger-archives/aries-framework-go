/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofbandv2

import (
	"fmt"
	"net/http"

	client "github.com/hyperledger/aries-framework-go/pkg/client/outofbandv2"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/outofbandv2"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
)

// constants for the OutOfBandv2 protocol operations.
const (
	OperationID      = "/outofband/2.0"
	CreateInvitation = OperationID + "/create-invitation"
	AcceptInvitation = OperationID + "/accept-invitation"
)

// Operation is controller REST service controller for outofband.
type Operation struct {
	command  *outofbandv2.Command
	handlers []rest.Handler
}

// New returns new outofbandv2 rest client protocol instance.
func New(ctx client.Provider) (*Operation, error) {
	cmd, err := outofbandv2.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("outofband/2.0 command : %w", err)
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
	}
}

// CreateInvitation swagger:route POST /outofband/2.0/create-invitation outofbandv2 outofbandV2CreateInvitation
//
// Creates an invitation.
//
// Responses:
//    default: genericError
//        200: outofbandV2CreateInvitationResponse
func (c *Operation) CreateInvitation(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(c.command.CreateInvitation, rw, req.Body)
}

// AcceptInvitation swagger:route POST /outofband/2.0/accept-invitation outofbandv2 outofbandV2AcceptInvitation
//
// Accepts an invitation.
//
// Responses:
//    default: genericError
//        200: outofbandV2AcceptInvitationResponse
func (c *Operation) AcceptInvitation(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(c.command.AcceptInvitation, rw, req.Body)
}
