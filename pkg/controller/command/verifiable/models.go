/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"github.com/hyperledger/aries-framework-go/pkg/store/verifiable"
)

// Credential is model for verifiable credential.
type Credential struct {
	VerifiableCredential string `json:"verifiableCredential,omitempty"`
}

// PresentationRequest is model for verifiable presentation request.
type PresentationRequest struct {
	// TODO  Update VC from string to json raw message #1643
	VerifiableCredentials []string `json:"verifiableCredential,omitempty"`
	DID                   string   `json:"did,omitempty"`
	ProofOptions
}

// IDArg model
//
// This is used for querying/removing by ID from input json.
//
type IDArg struct {
	// ID
	ID string `json:"id"`
}

// ProofOptions is model to allow the dynamic proofing options by the user.
type ProofOptions struct {
	// TODO Add more proof options as mentioned in this pr
	// https://github.com/hyperledger/aries-framework-go/issues/1644#issue-601483491
	VerificationMethod string `json:"verifiableMethod,omitempty"`
}

// CredentialExt is model for verifiable credential with fields related to command features.
type CredentialExt struct {
	Credential
	Name string `json:"name,omitempty"`
}

// PresentationRequestByID model
//
// This is used for querying/removing by ID from input json.
//
type PresentationRequestByID struct {
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
	// TODO Update VP from string to json raw message #1643
	VerifiablePresentation string `json:"verifiablePresentation,omitempty"`
}
