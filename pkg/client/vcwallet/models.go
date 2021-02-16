/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcwallet

import (
	"encoding/json"
	"time"
)

// QueryParams model
//
// Parameters for querying vc wallet contents.
//
type QueryParams struct {
	// Type of the query.
	// Allowed values 'QueryByFrame', 'PresentationExchange'
	Type string

	// Wallet content query.
	Query json.RawMessage
}

// ProofOptions model
//
// Options for adding linked data proofs to a verifiable credential or a verifiable presentation.
//
type ProofOptions struct {
	// VerificationMethod is the URI of the verificationMethod used for the proof.
	VerificationMethod string `json:"verificationMethod,omitempty"`
	// ProofPurpose is purpose of the proof.
	ProofPurpose string `json:"proofPurpose,omitempty"`
	// Controller is a DID to be for signing.
	Controller string `json:"controller,omitempty"`
	// Created date of the proof. If omitted current system time will be used.
	Created *time.Time `json:"created,omitempty"`
	// Domain is operational domain of a digital proof.
	Domain string `json:"domain,omitempty"`
	// Challenge is a random or pseudo-random value option authentication
	Challenge string `json:"challenge,omitempty"`
	// ProofType is signature type used for signing
	ProofType string `json:"proofType,omitempty"`
}
