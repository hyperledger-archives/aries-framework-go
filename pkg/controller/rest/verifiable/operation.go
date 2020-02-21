/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
)

const (
	verifiableOperationID  = "/verifiable"
	validateCredentialPath = verifiableOperationID + "/validateCredential"
)

// Operation contains basic common operations provided by controller REST API
type Operation struct {
	handlers []rest.Handler
	command  *verifiable.Command
}

// New returns new common operations rest client instance
func New() *Operation {
	o := &Operation{command: verifiable.New()}
	o.registerHandler()

	return o
}

// GetRESTHandlers get all controller API handler available for this service
func (o *Operation) GetRESTHandlers() []rest.Handler {
	return o.handlers
}

// registerHandler register handlers to be exposed from this protocol service as REST API endpoints
func (o *Operation) registerHandler() {
	o.handlers = []rest.Handler{
		cmdutil.NewHTTPHandler(validateCredentialPath, http.MethodPost, o.ValidateCredential),
	}
}

// ValidateCredential swagger:route POST /verifiable/validateCredential verifiable validateCredentialReq
//
// Validates the verifiable credential.
//
// Responses:
//    default: genericError
//        200: validateCredentialRes
func (o *Operation) ValidateCredential(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.ValidateCredential, rw, req.Body)
}
