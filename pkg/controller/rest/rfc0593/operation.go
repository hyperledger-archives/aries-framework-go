/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rfc0593

import (
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/client/issuecredential/rfc0593"
	cmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/rfc0593"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
)

const (
	// OperationID is this operation's base path.
	OperationID = "/rfc0593"
	// GetCredentialSpec is the endpoint for extracting credential specs.
	GetCredentialSpec = OperationID + "/get-spec"
	// IssueCredential is the endpoint for credential issuance.
	IssueCredential = OperationID + "/issue-credential"
	// VerifyCredential is the endpoint for credential verification.
	VerifyCredential = OperationID + "/verify-credential"
)

// Operation implements REST operations for RFC0593.
type Operation struct {
	cmd *cmd.Command
}

// New returns a new Operation.
func New(p rfc0593.Provider) *Operation {
	return &Operation{
		cmd: cmd.New(p),
	}
}

// GetRESTHandlers returns all handlers for Operation.
func (o *Operation) GetRESTHandlers() []rest.Handler {
	return []rest.Handler{
		cmdutil.NewHTTPHandler(GetCredentialSpec, http.MethodPost, o.GetCredentialSpec),
		cmdutil.NewHTTPHandler(IssueCredential, http.MethodPost, o.IssueCredential),
		cmdutil.NewHTTPHandler(VerifyCredential, http.MethodPost, o.VerifyCredential),
	}
}

// GetCredentialSpec swagger:route POST /rfc0593/get-spec get-spec getCredentialSpecRequest
//
// Extracts an RFC0593 credential spec from an applicable issue-credential message.
//
// Responses:
//    default: genericError
//        200: getCredentialSpecResponse
func (o *Operation) GetCredentialSpec(w http.ResponseWriter, r *http.Request) {
	rest.Execute(o.cmd.GetCredentialSpec, w, r.Body)
}

// IssueCredential swagger:route POST /rfc0593/issue-credential issue-credential issueCredentialRequest
//
// Issues a credential based on a RFC0593 credential spec.
//
// Responses:
//    default: genericError
//        200: issueCredentialResponse
func (o *Operation) IssueCredential(w http.ResponseWriter, r *http.Request) {
	rest.Execute(o.cmd.IssueCredential, w, r.Body)
}

// VerifyCredential swagger:route POST /rfc0593/verify-credential verify-credential verifyCredentialRequest
//
// Verifies a credential against a credential spec.
//
// Responses:
//    default: genericError
//        200: verifyCredentialResponse
func (o *Operation) VerifyCredential(w http.ResponseWriter, r *http.Request) {
	rest.Execute(o.cmd.VerifyCredential, w, r.Body)
}
