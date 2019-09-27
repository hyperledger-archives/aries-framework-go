/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package proof

import (
	"encoding/base64"
	"time"
)

const (
	// jsonldType is key for proof type
	jsonldType = "type"
	// jsonldCreator is key for creator
	jsonldCreator = "creator"
	// jsonldCreated is key for time proof created
	jsonldCreated = "created"
	// jsonldDomain is key for domain name
	jsonldDomain = "domain"
	// jsonldNonce is key for nonce
	jsonldNonce = "nonce"
	// jsonldProofValue is key for proof value
	jsonldProofValue = "proofValue"
)

// Proof is cryptographic proof of the integrity of the DID Document
type Proof struct {
	Type       string
	Created    *time.Time
	Creator    string
	ProofValue []byte
	Domain     string
	Nonce      []byte
}

// NewProof creates new proof
func NewProof(emap map[string]interface{}) (*Proof, error) {
	created := stringEntry(emap[jsonldCreated])

	timeValue, err := time.Parse(time.RFC3339, created)
	if err != nil {
		return nil, err
	}

	proofValue, err := base64.RawURLEncoding.DecodeString(stringEntry(emap[jsonldProofValue]))
	if err != nil {
		return nil, err
	}

	nonce, err := base64.RawURLEncoding.DecodeString(stringEntry(emap[jsonldNonce]))
	if err != nil {
		return nil, err
	}

	return &Proof{
		Type:       stringEntry(emap[jsonldType]),
		Created:    &timeValue,
		Creator:    stringEntry(emap[jsonldCreator]),
		ProofValue: proofValue,
		Domain:     stringEntry(emap[jsonldDomain]),
		Nonce:      nonce,
	}, nil
}

// stringEntry
func stringEntry(entry interface{}) string {
	if entry == nil {
		return ""
	}
	return entry.(string)
}

// JSONLdObject returns map that represents JSON LD Object
func (p *Proof) JSONLdObject() map[string]interface{} {
	emap := make(map[string]interface{})
	emap[jsonldType] = p.Type
	emap[jsonldCreator] = p.Creator
	emap[jsonldCreated] = p.Created.Format(time.RFC3339)
	emap[jsonldProofValue] = base64.RawURLEncoding.EncodeToString(p.ProofValue)
	emap[jsonldDomain] = p.Domain
	emap[jsonldNonce] = base64.RawURLEncoding.EncodeToString(p.Nonce)

	return emap
}
