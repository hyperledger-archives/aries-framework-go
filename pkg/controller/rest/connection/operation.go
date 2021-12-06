/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connection

import (
	"bytes"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command/connection"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/didrotate"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/store/did"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// constants for connection management endpoints.
const (
	OperationID            = "/connections"
	RotateDIDPath          = OperationID + "/{id}/rotate-did"
	CreateConnectionV2Path = OperationID + "/create-v2"
	SetConnectionToV2Path  = OperationID + "/{id}/use-v2"
)

type provider interface {
	VDRegistry() vdr.Registry
	DIDRotator() *didrotate.DIDRotator
	StorageProvider() storage.Provider
	ProtocolStateStorageProvider() storage.Provider
	DIDConnectionStore() did.ConnectionStore
}

// Operation is the REST controller for connection management.
type Operation struct {
	command  *connection.Command
	handlers []rest.Handler
}

// New returns new connection management rest client protocol instance.
func New(p provider) (*Operation, error) {
	cmd, err := connection.New(p)
	if err != nil {
		return nil, err
	}

	op := &Operation{
		command: cmd,
	}

	op.registerHandler()

	return op, nil
}

// GetRESTHandlers get all controller API handlers available for this service.
func (c *Operation) GetRESTHandlers() []rest.Handler {
	return c.handlers
}

// registerHandler register handlers to be exposed from this service as REST API endpoints.
func (c *Operation) registerHandler() {
	c.handlers = []rest.Handler{
		cmdutil.NewHTTPHandler(RotateDIDPath, http.MethodPost, c.RotateDID),
		cmdutil.NewHTTPHandler(SetConnectionToV2Path, http.MethodPost, c.SetConnectionToDIDCommV2),
		cmdutil.NewHTTPHandler(CreateConnectionV2Path, http.MethodPost, c.CreateConnectionV2),
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

// CreateConnectionV2 swagger:route POST /connections/create-v2 connections createConnectionV2
//
// Creates a DIDComm v2 connection record with the given DIDs.
//
// Responses:
//    default: genericError
//        200: createConnectionV2Response
func (c *Operation) CreateConnectionV2(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(c.command.CreateConnectionV2, rw, req.Body)
}

// SetConnectionToDIDCommV2 sets the didcomm version of the given connection to V2.
func (c *Operation) SetConnectionToDIDCommV2(rw http.ResponseWriter, req *http.Request) {
	id, found := getIDFromRequest(rw, req)
	if !found {
		return
	}

	request := fmt.Sprintf(`{"id":"%s"}`, id)

	rest.Execute(c.command.SetConnectionToDIDCommV2, rw, bytes.NewBufferString(request))
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
