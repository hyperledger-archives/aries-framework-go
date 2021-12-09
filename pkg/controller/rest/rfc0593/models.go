/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rfc0593

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/pkg/client/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/client/issuecredential/rfc0593"
)

// getCredentialSpecRequest model
//
// swagger:parameters getCredentialSpecRequest
type getCredentialSpecRequest struct { // nolint:deadcode,unused
	// in: body
	Body struct {
		Message json.RawMessage `json:"message"`
	}
}

// getCredentialSpecResponse model
//
// swagger:response getCredentialSpecResponse
type getCredentialSpecResponse struct { // nolint:deadcode,unused
	// in: body
	Body struct {
		Spec *rfc0593.CredentialSpec `json:"spec"`
	}
}

// issueCredentialRequest model
//
// swagger:parameters issueCredentialRequest
type issueCredentialRequest struct { // nolint:deadcode,unused
	// in: body
	Body struct {
		Spec rfc0593.CredentialSpec `json:"spec"`
	}
}

// issueCredentialResponse model
//
// swagger:response issueCredentialResponse
type issueCredentialResponse struct { // nolint:deadcode,unused
	// in: body
	Body struct {
		IssueCredential *issuecredential.IssueCredentialV2 `json:"issue_credential"`
	}
}

// verifyCredentialRequest model
//
// swagger:parameters verifyCredentialRequest
type verifyCredentialRequest struct { // nolint:deadcode,unused
	// in: body
	Body struct {
		Credential json.RawMessage        `json:"credential"`
		Spec       rfc0593.CredentialSpec `json:"spec"`
	}
}

// verifyCredentialResponse model
//
// swagger:response verifyCredentialResponse
type verifyCredentialResponse struct { // nolint:deadcode,unused
	// in: body
	Body struct{}
}
