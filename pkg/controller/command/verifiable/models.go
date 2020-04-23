/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/store/verifiable"
)

// Credential is model for verifiable credential.
type Credential struct {
	VerifiableCredential string `json:"verifiableCredential,omitempty"`
}

// PresentationRequest is model for verifiable presentation request.
type PresentationRequest struct {
	VerifiableCredentials []json.RawMessage `json:"verifiableCredential,omitempty"`
	Presentation          json.RawMessage   `json:"presentation,omitempty"`
	DID                   string            `json:"did,omitempty"`
	*ProofOptions
	// SkipVerify can be used to skip verification of `VerifiableCredentials` provided.
	SkipVerify bool `json:"skipVerify,omitempty"`
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
	// VerificationMethod is the URI of the verificationMethod used for the proof.
	VerificationMethod string `json:"verifiableMethod,omitempty"`
	// ProofPurpose is purpose of the proof. If omitted "assertionMethod" will be used.
	ProofPurpose string `json:"proofPurpose,omitempty"`
	// Created date of the proof. If omitted current system time will be used.
	Created *time.Time `json:"created,omitempty"`
	// Domain is operational domain of a digital proof.
	Domain string `json:"domain,omitempty"`
	// Challenge is a random or pseudo-random value option authentication
	Challenge string `json:"challenge,omitempty"`
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
