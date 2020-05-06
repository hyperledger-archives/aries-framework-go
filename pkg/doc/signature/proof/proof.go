/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package proof

import (
	"encoding/base64"
	"errors"

	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
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
	// jsonldProofPurpose is a purpose of proof
	jsonldProofPurpose = "proofPurpose"
	// jsonldJWSProof is key for JWS proof
	jsonldJWS = "jws"
	// jsonldVerificationMethod is a key for verification method
	jsonldVerificationMethod = "verificationMethod"
	// jsonldChallenge is a key for challenge
	jsonldChallenge = "challenge"
)

// Proof is cryptographic proof of the integrity of the DID Document
type Proof struct {
	Type                    string
	Created                 *util.TimeWithTrailingZeroMsec
	Creator                 string
	VerificationMethod      string
	ProofValue              []byte
	JWS                     string
	ProofPurpose            string
	Domain                  string
	Nonce                   []byte
	Challenge               string
	SignatureRepresentation SignatureRepresentation
}

// NewProof creates new proof
func NewProof(emap map[string]interface{}) (*Proof, error) {
	created := stringEntry(emap[jsonldCreated])

	timeValue, err := util.ParseTimeWithTrailingZeroMsec(created)
	if err != nil {
		return nil, err
	}

	var (
		proofValue  []byte
		proofHolder SignatureRepresentation
		jws         string
	)

	if generalProof, ok := emap[jsonldProofValue]; ok {
		proofValue, err = base64.RawURLEncoding.DecodeString(stringEntry(generalProof))
		if err != nil {
			return nil, err
		}

		proofHolder = SignatureProofValue
	} else if jwsProof, ok := emap[jsonldJWS]; ok {
		jws = stringEntry(jwsProof)
		proofHolder = SignatureJWS
	}

	if len(proofValue) == 0 && jws == "" {
		return nil, errors.New("signature is not defined")
	}

	nonce, err := base64.RawURLEncoding.DecodeString(stringEntry(emap[jsonldNonce]))
	if err != nil {
		return nil, err
	}

	return &Proof{
		Type:                    stringEntry(emap[jsonldType]),
		Created:                 timeValue,
		Creator:                 stringEntry(emap[jsonldCreator]),
		VerificationMethod:      stringEntry(emap[jsonldVerificationMethod]),
		ProofValue:              proofValue,
		SignatureRepresentation: proofHolder,
		JWS:                     jws,
		ProofPurpose:            stringEntry(emap[jsonldProofPurpose]),
		Domain:                  stringEntry(emap[jsonldDomain]),
		Nonce:                   nonce,
		Challenge:               stringEntry(emap[jsonldChallenge]),
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

	if p.Creator != "" {
		emap[jsonldCreator] = p.Creator
	}

	if p.VerificationMethod != "" {
		emap[jsonldVerificationMethod] = p.VerificationMethod
	}

	if p.Created != nil {
		emap[jsonldCreated] = p.Created.Format(p.Created.GetFormat())
	}

	if len(p.ProofValue) > 0 {
		emap[jsonldProofValue] = base64.RawURLEncoding.EncodeToString(p.ProofValue)
	}

	if len(p.JWS) > 0 {
		emap[jsonldJWS] = p.JWS
	}

	if p.Domain != "" {
		emap[jsonldDomain] = p.Domain
	}

	if len(p.Nonce) > 0 {
		emap[jsonldNonce] = base64.RawURLEncoding.EncodeToString(p.Nonce)
	}

	if p.ProofPurpose != "" {
		emap[jsonldProofPurpose] = p.ProofPurpose
	}

	if p.Challenge != "" {
		emap[jsonldChallenge] = p.Challenge
	}

	return emap
}

// PublicKeyID provides ID of public key to be used to independently verify the proof.
// "verificationMethod" field is checked first. If not empty, its value is returned.
// Otherwise, "creator" field is returned if not empty. Otherwise, error is returned.
func (p *Proof) PublicKeyID() (string, error) {
	if p.VerificationMethod != "" {
		return p.VerificationMethod, nil
	}

	if p.Creator != "" {
		return p.Creator, nil
	}

	return "", errors.New("no public key ID")
}
