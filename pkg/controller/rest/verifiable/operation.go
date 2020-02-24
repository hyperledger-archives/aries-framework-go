/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"fmt"
	"net/http"

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
		cmdutil.NewHTTPHandler(saveCredentialPath, http.MethodPost, o.ValidateCredential),
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
