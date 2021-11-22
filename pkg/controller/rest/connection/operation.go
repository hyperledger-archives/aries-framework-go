/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connection

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command/connection"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/didrotate"
)

// constants for connection management endpoints.
const (
	OperationID   = "/connections"
	RotateDIDPath = OperationID + "/{id}/rotate-did"
)

type provider interface {
	DIDRotator() *didrotate.DIDRotator
}

// Operation is the REST controller for connection management.
type Operation struct {
	command  *connection.Command
	handlers []rest.Handler
}

// New returns new connection management rest client protocol instance.
func New(p provider) *Operation {
	cmd := connection.New(p)

	op := &Operation{
		command: cmd,
	}

	op.registerHandler()

	return op
}

// GetRESTHandlers get all controller API handlers available for this service.
func (c *Operation) GetRESTHandlers() []rest.Handler {
	return c.handlers
}

// registerHandler register handlers to be exposed from this service as REST API endpoints.
func (c *Operation) registerHandler() {
	c.handlers = []rest.Handler{
		cmdutil.NewHTTPHandler(RotateDIDPath, http.MethodPost, c.RotateDID),
	}
}

// RotateDID swagger:route POST /connections/{id}/rotate-did connections rotateDID
//
// Rotates the agent's DID in the given connection.
//
// Responses:
//    default: genericError
//        200: rotateDIDResponse
func (c *Operation) RotateDID(rw http.ResponseWriter, req *http.Request) {
	id, found := getIDFromRequest(rw, req)
	if !found {
		return
	}

	rest.Execute(c.command.RotateDIDGivenConnIDCmd(id), rw, req.Body)
}

// getIDFromRequest returns ID from request.
func getIDFromRequest(rw http.ResponseWriter, req *http.Request) (string, bool) {
	id := mux.Vars(req)["id"]
	if id == "" {
		rest.SendHTTPStatusError(rw, http.StatusBadRequest, connection.InvalidRequestErrorCode,
			fmt.Errorf("empty connection ID"))
		return "", false
	}

	return id, true
}
