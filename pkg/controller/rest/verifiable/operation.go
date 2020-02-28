/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	verifiableOperationID    = "/verifiable"
	varifiableCredentialPath = verifiableOperationID + "/credential"
	validateCredentialPath   = varifiableCredentialPath + "/validate"
	saveCredentialPath       = varifiableCredentialPath
	getCredentialPath        = varifiableCredentialPath + "/{id}"
	getCredentialByNamePath  = varifiableCredentialPath + "/name" + "/{name}"
	getCredentialsPath       = verifiableOperationID + "/credentials"
)

// provider contains dependencies for the verifiable command and is typically created by using aries.Context().
type provider interface {
	StorageProvider() storage.Provider
}

// Operation contains basic common operations provided by controller REST API
type Operation struct {
	handlers []rest.Handler
	command  *verifiable.Command
}

// New returns new common operations rest client instance
func New(p provider) (*Operation, error) {
	cmd, err := verifiable.New(p)
	if err != nil {
		return nil, fmt.Errorf("new vc store : %w", err)
	}

	o := &Operation{command: cmd}
	o.registerHandler()

	return o, nil
}

// GetRESTHandlers get all controller API handler available for this service
func (o *Operation) GetRESTHandlers() []rest.Handler {
	return o.handlers
}

// registerHandler register handlers to be exposed from this protocol service as REST API endpoints
func (o *Operation) registerHandler() {
	o.handlers = []rest.Handler{
		cmdutil.NewHTTPHandler(validateCredentialPath, http.MethodPost, o.ValidateCredential),
		cmdutil.NewHTTPHandler(saveCredentialPath, http.MethodPost, o.SaveCredential),
		cmdutil.NewHTTPHandler(getCredentialPath, http.MethodGet, o.GetCredential),
		cmdutil.NewHTTPHandler(getCredentialByNamePath, http.MethodGet, o.GetCredentialByName),
		cmdutil.NewHTTPHandler(getCredentialsPath, http.MethodGet, o.GetCredentials),
	}
}

// ValidateCredential swagger:route POST /verifiable/credential/validate verifiable validateCredentialReq
//
// Validates the verifiable credential.
//
// Responses:
//    default: genericError
//        200: emptyRes
func (o *Operation) ValidateCredential(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.ValidateCredential, rw, req.Body)
}

// SaveCredential swagger:route POST /verifiable/credential verifiable saveCredentialReq
//
// Saves the verifiable credential.
//
// Responses:
//    default: genericError
//        200: emptyRes
func (o *Operation) SaveCredential(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.SaveCredential, rw, req.Body)
}

// GetCredential swagger:route GET /verifiable/credential/{id} verifiable getCredentialReq
//
// Retrieves the verifiable credential.
//
// Responses:
//    default: genericError
//        200: credentialRes
func (o *Operation) GetCredential(rw http.ResponseWriter, req *http.Request) {
	id := mux.Vars(req)["id"]

	decodedID, err := base64.StdEncoding.DecodeString(id)
	if err != nil {
		rest.SendHTTPStatusError(rw, http.StatusBadRequest, verifiable.InvalidRequestErrorCode, err)
		return
	}

	request := fmt.Sprintf(`{"id":"%s"}`, string(decodedID))

	rest.Execute(o.command.GetCredential, rw, bytes.NewBufferString(request))
}

// GetCredentialByName swagger:route GET /verifiable/credential/name/{name} verifiable getCredentialByNameReq
//
// Retrieves the verifiable credential by name.
//
// Responses:
//    default: genericError
//        200: credentialRecord
func (o *Operation) GetCredentialByName(rw http.ResponseWriter, req *http.Request) {
	name := mux.Vars(req)["name"]

	request := fmt.Sprintf(`{"name":"%s"}`, name)

	rest.Execute(o.command.GetCredentialByName, rw, bytes.NewBufferString(request))
}

// GetCredentials swagger:route GET /verifiable/credentials verifiable getCredentials
//
// Retrieves the verifiable credentials.
//
// Responses:
//    default: genericError
//        200: credentialRecordResult
func (o *Operation) GetCredentials(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.GetCredentials, rw, req.Body)
}
