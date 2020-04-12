/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/pkg/store/verifiable"
)

// Credential is model for verifiable credential.
type Credential struct {
	VerifiableCredential string `json:"verifiableCredential,omitempty"`
}

// PresentationRequest is model for verifiable presentation request.
type PresentationRequest struct {
	VerifiableCredential string          `json:"verifiableCredential,omitempty"`
	DidDoc               json.RawMessage `json:"doc,omitempty"`
}

// CredentialExt is model for verifiable credential with fields related to command features.
type CredentialExt struct {
	Credential
	Name string `json:"name,omitempty"`
}

// IDArg model
//
// This is used for querying/removing by ID from input json.
//
type IDArg struct {
	// ID
	ID string `json:"id"`

	// DID ID
	DID string `json:"did"`
}

// NameArg model
//
// This is used for querying by name from input json.
//
type NameArg struct {
	// Name
	Name string `json:"name"`
}

// CredentialRecordResult holds the credential records.
type CredentialRecordResult struct {
	// Result
	Result []*verifiable.CredentialRecord `json:"result,omitempty"`
}

// Presentation is model for verifiable presentation.
type Presentation struct {
	VerifiablePresentation string `json:"verifiablePresentation,omitempty"`
}
