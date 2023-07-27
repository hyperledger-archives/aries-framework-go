/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

import "time"

// TODO integrate VerificationMethod model with the did doc VM model
//  (can we just use did.VerificationMethod directly)?

// VerificationMethod implements the data integrity verification method model:
// https://www.w3.org/TR/vc-data-integrity/#verification-methods
type VerificationMethod struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Controller string `json:"controller"`
	Fields     map[string]interface{}
}

// Proof implements the data integrity proof model:
// https://www.w3.org/TR/vc-data-integrity/#proofs
type Proof struct {
	ID                 string `json:"id,omitempty"`
	Type               string `json:"type"`
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
	Purpose            string
	VerificationMethod *VerificationMethod
	SuiteType          string
	Domain             string
	Challenge          string
	MaxAge             int64
	CustomFields       map[string]interface{}
}

// DateTimeFormat is the date-time format used by the data integrity
// specification, which matches RFC3339.
// https://www.w3.org/TR/xmlschema11-2/#dateTime
const DateTimeFormat = time.RFC3339
