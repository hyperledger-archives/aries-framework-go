/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

import (
	"time"

	"github.com/hyperledger/aries-framework-go/component/models/did"
)

const (
	// DataIntegrityProof is the type property on proofs created using data
	// integrity cryptographic suites.
	DataIntegrityProof = "DataIntegrityProof"
)

// KeyManager manages keys and their storage for the aries framework.
type KeyManager interface {
	// Get key handle for the given keyID
	// Returns:
	//  - handle instance (to private key)
	//  - error if failure
	Get(keyID string) (interface{}, error)
}

// VerificationMethod implements the data integrity verification method model:
// https://www.w3.org/TR/vc-data-integrity/#verification-methods
type VerificationMethod = did.VerificationMethod

// Proof implements the data integrity proof model:
// https://www.w3.org/TR/vc-data-integrity/#proofs
type Proof struct {
	ID                 string `json:"id,omitempty"`
	Type               string `json:"type"`
	CryptoSuite        string `json:"cryptosuite,omitempty"`
	ProofPurpose       string `json:"proofPurpose"`
	VerificationMethod string `json:"verificationMethod"`
	Created            string `json:"created,omitempty"`
	Domain             string `json:"domain,omitempty"`
	Challenge          string `json:"challenge,omitempty"`
	ProofValue         string `json:"proofValue"`
	PreviousProof      string `json:"previousProof,omitempty"`
}

// ProofOptions provides options for signing or verifying a data integrity proof.
type ProofOptions struct {
	Purpose              string
	VerificationMethodID string
	VerificationMethod   *VerificationMethod
	ProofType            string
	SuiteType            string
	Domain               string
	Challenge            string
	Created              time.Time
	MaxAge               int64
	CustomFields         map[string]interface{}
}

// DateTimeFormat is the date-time format used by the data integrity
// specification, which matches RFC3339.
// https://www.w3.org/TR/xmlschema11-2/#dateTime
const DateTimeFormat = time.RFC3339
