/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdr

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// constants for the VDR operations.
const (
	VDROperationID    = "/vdr"
	vdrDIDPath        = VDROperationID + "/did"
	SaveDIDPath       = vdrDIDPath
	GetDIDPath        = vdrDIDPath + "/{id}"
	ResolveDIDPath    = vdrDIDPath + "/resolve/{id}"
	CreateDIDPath     = vdrDIDPath + "/create"
	GetDIDRecordsPath = vdrDIDPath + "/records"
)

// provider contains dependencies for the common controller operations
// and is typically created by using aries.Context().
type provider interface {
	VDRegistry() vdrapi.Registry
	StorageProvider() storage.Provider
}

// Operation contains basic common operations provided by controller REST API.
type Operation struct {
	handlers []rest.Handler
	command  *vdr.Command
}

// New returns new common operations rest client instance.
func New(ctx provider) (*Operation, error) {
	cmd, err := vdr.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("new vdr : %w", err)
	}

	o := &Operation{command: cmd}
	o.registerHandler()

	return o, nil
}

// GetRESTHandlers get all controller API handler available for this service.
func (o *Operation) GetRESTHandlers() []rest.Handler {
	return o.handlers
}

// registerHandler register handlers to be exposed from this protocol service as REST API endpoints.
func (o *Operation) registerHandler() {
	// Add more protocol endpoints here to expose them as controller API endpoints
	o.handlers = []rest.Handler{
		cmdutil.NewHTTPHandler(SaveDIDPath, http.MethodPost, o.SaveDID),
		cmdutil.NewHTTPHandler(ResolveDIDPath, http.MethodGet, o.ResolveDID),
		cmdutil.NewHTTPHandler(CreateDIDPath, http.MethodPost, o.CreateDID),
		cmdutil.NewHTTPHandler(GetDIDRecordsPath, http.MethodGet, o.GetDIDRecords),
		cmdutil.NewHTTPHandler(GetDIDPath, http.MethodGet, o.GetDID),
	}
}

// CreateDID swagger:route POST /vdr/did/create vdr createDIDReq
//
// Create a did document.
//
// Responses:
//    default: genericError
//        200: documentRes
func (o *Operation) CreateDID(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.CreateDID, rw, req.Body)
}

// SaveDID swagger:route POST /vdr/did vdr saveDIDReq
//
// Saves a did document with the friendly name.
//
// Responses:
//    default: genericError
func (o *Operation) SaveDID(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.SaveDID, rw, req.Body)
}

// GetDID swagger:route GET /vdr/did/{id} vdr getDIDReq
//
// Gets did document with the friendly name.
//
// Responses:
//    default: genericError
//        200: documentRes
func (o *Operation) GetDID(rw http.ResponseWriter, req *http.Request) {
	id := mux.Vars(req)["id"]

	decodedID, err := base64.StdEncoding.DecodeString(id)
	if err != nil {
		rest.SendHTTPStatusError(rw, http.StatusBadRequest, vdr.InvalidRequestErrorCode, fmt.Errorf("invalid id"))
		return
	}

	request := fmt.Sprintf(`{"id":"%s"}`, string(decodedID))

	rest.Execute(o.command.GetDID, rw, bytes.NewBufferString(request))
}

// ResolveDID swagger:route GET /vdr/did/resolve/{id} vdr resolveDIDReq
//
// Resolve did
//
// Responses:
//    default: genericError
//        200: resolveDIDRes
func (o *Operation) ResolveDID(rw http.ResponseWriter, req *http.Request) {
	id := mux.Vars(req)["id"]

	decodedID, err := base64.StdEncoding.DecodeString(id)
	if err != nil {
		rest.SendHTTPStatusError(rw, http.StatusBadRequest, vdr.InvalidRequestErrorCode, fmt.Errorf("invalid id"))
		return
	}

	request := fmt.Sprintf(`{"id":"%s"}`, string(decodedID))

	rest.Execute(o.command.ResolveDID, rw, bytes.NewBufferString(request))
}

// GetDIDRecords swagger:route GET /vdr/did/records vdr getDIDRecords
//
// Retrieves the did records
//
// Responses:
//    default: genericError
//        200: didRecordResult
func (o *Operation) GetDIDRecords(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.GetDIDRecords, rw, req.Body)
}
