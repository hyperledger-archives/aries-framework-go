/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rfc0593

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/pkg/client/issuecredential/rfc0593"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
)

// GetCredentialSpecArgs model.
type GetCredentialSpecArgs struct {
	Message json.RawMessage `json:"message"`
}

// GetCredentialSpecResponse model.
type GetCredentialSpecResponse struct {
	Spec *rfc0593.CredentialSpec `json:"spec"`
}

// IssueCredentialArgs model.
type IssueCredentialArgs struct {
	Spec rfc0593.CredentialSpec `json:"spec"`
}

// IssueCredentialResponse model.
type IssueCredentialResponse struct {
	IssueCredential *issuecredential.IssueCredentialV2 `json:"issue_credential"`
}

// VerifyCredentialArgs model.
type VerifyCredentialArgs struct {
	Credential json.RawMessage        `json:"credential"`
	Spec       rfc0593.CredentialSpec `json:"spec"`
}
