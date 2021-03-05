/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"time"

	docverifiable "github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
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
	KID string `json:"kid,omitempty"`
	// VerificationMethod is the URI of the verificationMethod used for the proof.
	VerificationMethod      string                                 `json:"verificationMethod,omitempty"`
	SignatureRepresentation *docverifiable.SignatureRepresentation `json:"signatureRepresentation,omitempty"`
	// Created date of the proof. If omitted current system time will be used.
	Created *time.Time `json:"created,omitempty"`
	// Domain is operational domain of a digital proof.
	Domain string `json:"domain,omitempty"`
	// Challenge is a random or pseudo-random value option authentication
	Challenge string `json:"challenge,omitempty"`
	// SignatureType signature type used for signing
	SignatureType string `json:"signatureType,omitempty"`
	// proofPurpose is purpose of the proof.
	proofPurpose string
}

// CredentialExt is model for verifiable credential with fields related to command features.
type CredentialExt struct {
	Credential
	Name string `json:"name,omitempty"`
}

// SignCredentialRequest is adding proof to given credential.
type SignCredentialRequest struct {
	Credential json.RawMessage `json:"credential,omitempty"`
	DID        string          `json:"did,omitempty"`
	*ProofOptions
}

// SignCredentialResponse is model for sign credential response.
type SignCredentialResponse struct {
	VerifiableCredential json.RawMessage `json:"verifiableCredential,omitempty"`
}

// PresentationExt is model for presentation with fields related to command features.
type PresentationExt struct {
	Presentation
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

	// SignatureType
	SignatureType string `json:"signatureType"`
}

// NameArg model
//
// This is used for querying by name from input json.
//
type NameArg struct {
	// Name
	Name string `json:"name"`
}

// RecordResult holds the credential records.
type RecordResult struct {
	// Result
	Result []*verifiable.Record `json:"result,omitempty"`
}

// Presentation is model for verifiable presentation.
type Presentation struct {
	VerifiablePresentation json.RawMessage `json:"verifiablePresentation,omitempty"`
}

// RemoveCredentialByNameResponse is a response model for removing a vc by name
// from the verifiable store.
type RemoveCredentialByNameResponse struct{}

// RemovePresentationByNameResponse is a response model for removing a vp by name
// from the verifiable store.
type RemovePresentationByNameResponse struct{}

// DeriveCredentialRequest is request for deriving credential.
type DeriveCredentialRequest struct {
	// Raw Credential from which a new credential will be derived
	Credential json.RawMessage `json:"credential,omitempty"`
	// Frame is JSON-LD frame used for selective disclosure.
	Frame map[string]interface{} `json:"frame,omitempty"`
	// Nonce to prove uniqueness or freshness of the proof.
	Nonce string `json:"nonce,omitempty"`
	// SkipVerify can be used to skip verification of `Credential` provided.
	SkipVerify bool `json:"skipVerify,omitempty"`
}
