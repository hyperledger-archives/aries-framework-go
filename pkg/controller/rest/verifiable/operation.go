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
	"github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	ariescrypto "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// constants for the Verifiable protocol.
const (
	// roots.
	VerifiableOperationID      = "/verifiable"
	verifiableCredentialPath   = VerifiableOperationID + "/credential"
	verifiablePresentationPath = VerifiableOperationID + "/presentation"

	// credential paths.
	ValidateCredentialPath     = verifiableCredentialPath + "/validate"
	SaveCredentialPath         = verifiableCredentialPath
	GetCredentialPath          = verifiableCredentialPath + "/{id}"
	GetCredentialByNamePath    = verifiableCredentialPath + "/name" + "/{name}"
	GetCredentialsPath         = VerifiableOperationID + "/credentials"
	SignCredentialsPath        = VerifiableOperationID + "/signcredential"
	DeriveCredentialPath       = VerifiableOperationID + "/derivecredential"
	RemoveCredentialByNamePath = verifiableCredentialPath + "/remove/name" + "/{name}"

	// presentation paths.
	GeneratePresentationPath     = verifiablePresentationPath + "/generate"
	GeneratePresentationByIDPath = verifiablePresentationPath + "/generatebyid"
	SavePresentationPath         = verifiablePresentationPath
	GetPresentationPath          = verifiablePresentationPath + "/{id}"
	GetPresentationsPath         = VerifiableOperationID + "/presentations"
	RemovePresentationByNamePath = verifiablePresentationPath + "/remove/name" + "/{name}"
)

// provider contains dependencies for the verifiable command and is typically created by using aries.Context().
type provider interface {
	StorageProvider() storage.Provider
	VDRegistry() vdr.Registry
	KMS() kms.KeyManager
	Crypto() ariescrypto.Crypto
	JSONLDDocumentLoader() ld.DocumentLoader
}

// Operation contains basic common operations provided by controller REST API.
type Operation struct {
	handlers []rest.Handler
	command  *verifiable.Command
}

// New returns new common operations rest client instance.
func New(p provider) (*Operation, error) {
	cmd, err := verifiable.New(p)
	if err != nil {
		return nil, fmt.Errorf("verfiable new: %w", err)
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
	o.handlers = []rest.Handler{
		cmdutil.NewHTTPHandler(ValidateCredentialPath, http.MethodPost, o.ValidateCredential),
		cmdutil.NewHTTPHandler(SaveCredentialPath, http.MethodPost, o.SaveCredential),
		cmdutil.NewHTTPHandler(GetCredentialPath, http.MethodGet, o.GetCredential),
		cmdutil.NewHTTPHandler(GetCredentialByNamePath, http.MethodGet, o.GetCredentialByName),
		cmdutil.NewHTTPHandler(GetCredentialsPath, http.MethodGet, o.GetCredentials),
		cmdutil.NewHTTPHandler(SignCredentialsPath, http.MethodPost, o.SignCredential),
		cmdutil.NewHTTPHandler(DeriveCredentialPath, http.MethodPost, o.DeriveCredential),
		cmdutil.NewHTTPHandler(GeneratePresentationPath, http.MethodPost, o.GeneratePresentation),
		cmdutil.NewHTTPHandler(GeneratePresentationByIDPath, http.MethodPost, o.GeneratePresentationByID),
		cmdutil.NewHTTPHandler(SavePresentationPath, http.MethodPost, o.SavePresentation),
		cmdutil.NewHTTPHandler(GetPresentationPath, http.MethodGet, o.GetPresentation),
		cmdutil.NewHTTPHandler(GetPresentationsPath, http.MethodGet, o.GetPresentations),
		cmdutil.NewHTTPHandler(RemoveCredentialByNamePath, http.MethodPost, o.RemoveCredentialByName),
		cmdutil.NewHTTPHandler(RemovePresentationByNamePath, http.MethodPost, o.RemovePresentationByName),
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

// SavePresentation swagger:route POST /verifiable/presentation verifiable savePresentationReq
//
// Saves the verifiable presentation.
//
// Responses:
//    default: genericError
//        200: emptyRes
func (o *Operation) SavePresentation(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.SavePresentation, rw, req.Body)
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

// GetPresentation swagger:route GET /verifiable/presentation/{id} verifiable getPresentationReq
//
// Retrieves the verifiable presentation.
//
// Responses:
//    default: genericError
//        200: presentationRes
func (o *Operation) GetPresentation(rw http.ResponseWriter, req *http.Request) {
	id := mux.Vars(req)["id"]

	decodedID, err := base64.StdEncoding.DecodeString(id)
	if err != nil {
		rest.SendHTTPStatusError(rw, http.StatusBadRequest, verifiable.InvalidRequestErrorCode, err)
		return
	}

	request := fmt.Sprintf(`{"id":"%s"}`, string(decodedID))

	rest.Execute(o.command.GetPresentation, rw, bytes.NewBufferString(request))
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

// SignCredential swagger:route POST /verifiable/signcredential verifiable signCredentialReq
//
// Signs given credential.
//
// Responses:
//    default: genericError
//        200: signCredentialRes
func (o *Operation) SignCredential(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.SignCredential, rw, req.Body)
}

// DeriveCredential swagger:route POST /verifiable/derivecredential verifiable deriveCredentialReq
//
// Derives a given verifiable credential for selective disclosure.
//
// Responses:
//    default: genericError
//        200: deriveCredentialRes
func (o *Operation) DeriveCredential(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.DeriveCredential, rw, req.Body)
}

// GetPresentations swagger:route GET /verifiable/presentations verifiable
//
// Retrieves the verifiable credentials.
//
// Responses:
//    default: genericError
//        200: presentationRecordResult
func (o *Operation) GetPresentations(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.GetPresentations, rw, req.Body)
}

// GeneratePresentation swagger:route POST /verifiable/presentation/generate verifiable generatePresentationReq
//
// Generates the verifiable presentation from a verifiable credential.
//
// Responses:
//    default: genericError
//        200: presentationRes
func (o *Operation) GeneratePresentation(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.GeneratePresentation, rw, req.Body)
}

// GeneratePresentationByID swagger:route POST /verifiable/presentation/generatebyid verifiable generatePresentationByIDReq
//
// Generates the verifiable presentation from a stored verifiable credential.
//
// Responses:
//    default: genericError
//        200: presentationRes
func (o *Operation) GeneratePresentationByID(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.GeneratePresentationByID, rw, req.Body)
}

// RemoveCredentialByName swagger:route POST /verifiable/credential/remove/name/{name} verifiable removeCredentialByNameReq
//
// Removes a verifiable credential by name.
//
// Responses:
//    default: genericError
//        200: emptyResponse
func (o *Operation) RemoveCredentialByName(rw http.ResponseWriter, req *http.Request) {
	name := mux.Vars(req)["name"]

	request := fmt.Sprintf(`{"name":"%s"}`, name)

	rest.Execute(o.command.RemoveCredentialByName, rw, bytes.NewBufferString(request))
}

// RemovePresentationByName swagger:route POST /verifiable/presentation/remove/name/{name} verifiable removePresentationByNameReq
//
// Removes a verifiable presentation by name.
//
// Responses:
//    default: genericError
//        200: emptyResponse
func (o *Operation) RemovePresentationByName(rw http.ResponseWriter, req *http.Request) {
	name := mux.Vars(req)["name"]

	request := fmt.Sprintf(`{"name":"%s"}`, name)

	rest.Execute(o.command.RemovePresentationByName, rw, bytes.NewBufferString(request))
}
