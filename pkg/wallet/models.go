/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"encoding/json"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

// QueryParams model
//
// Parameters for querying vc wallet contents.
//
type QueryParams struct {
	// Type of the query.
	// Allowed values  'QueryByExample', 'QueryByFrame', 'PresentationExchange'
	Type string

	// Wallet content query.
	Query json.RawMessage
}

// ProofOptions model
//
// Options for adding linked data proofs to a verifiable credential or a verifiable presentation.
// To be used as options for issue/prove wallet features.
//
type ProofOptions struct {
	// Controller is a DID to be for signing. This option is required for issue/prove wallet features.
	Controller string `json:"controller,omitempty"`
	// VerificationMethod is the URI of the verificationMethod used for the proof.
	// Optional, by default Controller public key matching 'assertion' for issue or 'authentication' for prove functions.
	VerificationMethod string `json:"verificationMethod,omitempty"`
	// Created date of the proof.
	// Optional, current system time will be used.
	Created *time.Time `json:"created,omitempty"`
	// Domain is operational domain of a digital proof.
	// Optional, by default domain will not be part of proof.
	Domain string `json:"domain,omitempty"`
	// Challenge is a random or pseudo-random value option authentication.
	// Optional, by default challenge will not be part of proof.
	Challenge string `json:"challenge,omitempty"`
	// ProofType is signature type used for signing.
	// Optional, by default proof will be generated in Ed25519Signature2018 format.
	ProofType string `json:"proofType,omitempty"`
	// ProofRepresentation is type of proof data expected, (Refer verifiable.SignatureProofValue)
	// Optional, by default proof will be represented as 'verifiable.SignatureProofValue'.
	ProofRepresentation *verifiable.SignatureRepresentation `json:"proofRepresentation,omitempty"`
}

// DeriveOptions model containing options for deriving a credential.
//
type DeriveOptions struct {
	// Frame is JSON-LD frame used for selective disclosure.
	Frame map[string]interface{} `json:"frame,omitempty"`
	// Nonce to prove uniqueness or freshness of the proof.
	Nonce string `json:"nonce,omitempty"`
}
