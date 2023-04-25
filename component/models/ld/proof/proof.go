/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package proof

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/multiformats/go-multibase"

	afgotime "github.com/hyperledger/aries-framework-go/component/models/util/time"
)

const (
	// jsonldType is key for proof type.
	jsonldType = "type"
	// jsonldCreator is key for creator.
	jsonldCreator = "creator"
	// jsonldCreated is key for time proof created.
	jsonldCreated = "created"
	// jsonldDomain is key for domain name.
	jsonldDomain = "domain"
	// jsonldNonce is key for nonce.
	jsonldNonce = "nonce"
	// jsonldProofValue is key for proof value.
	jsonldProofValue = "proofValue"
	// jsonldProofPurpose is a purpose of proof.
	jsonldProofPurpose = "proofPurpose"
	// jsonldJWSProof is key for JWS proof.
	jsonldJWS = "jws"
	// jsonldVerificationMethod is a key for verification method.
	jsonldVerificationMethod = "verificationMethod"
	// jsonldChallenge is a key for challenge.
	jsonldChallenge = "challenge"
	// jsonldCapabilityChain is a key for capabilityChain.
	jsonldCapabilityChain = "capabilityChain"

	ed25519Signature2020 = "Ed25519Signature2020"
)

// Proof is cryptographic proof of the integrity of the DID Document.
type Proof struct {
	Type                    string
	Created                 *afgotime.TimeWrapper
	Creator                 string
	VerificationMethod      string
	ProofValue              []byte
	JWS                     string
	ProofPurpose            string
	Domain                  string
	Nonce                   []byte
	Challenge               string
	SignatureRepresentation SignatureRepresentation
	// CapabilityChain must be an array. Each element is either a string or an object.
	CapabilityChain []interface{}
}

// NewProof creates new proof.
func NewProof(emap map[string]interface{}) (*Proof, error) {
	created := stringEntry(emap[jsonldCreated])

	timeValue, err := afgotime.ParseTimeWrapper(created)
	if err != nil {
		return nil, err
	}

	var (
		proofValue  []byte
		proofHolder SignatureRepresentation
		jws         string
	)

	if generalProof, ok := emap[jsonldProofValue]; ok {
		proofValue, err = DecodeProofValue(stringEntry(generalProof), stringEntry(emap[jsonldType]))
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

	nonce, err := decodeBase64(stringEntry(emap[jsonldNonce]))
	if err != nil {
		return nil, err
	}

	capabilityChain, err := decodeCapabilityChain(emap)
	if err != nil {
		return nil, fmt.Errorf("failed to decode capabilityChain: %w", err)
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
		CapabilityChain:         capabilityChain,
	}, nil
}

func decodeCapabilityChain(proof map[string]interface{}) ([]interface{}, error) {
	var capabilityChain []interface{}

	untyped, found := proof[jsonldCapabilityChain]
	if found {
		var ok bool

		capabilityChain, ok = untyped.([]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid format for capabilityChain - must be an array: %+v", untyped)
		}
	}

	return capabilityChain, nil
}

func decodeBase64(s string) ([]byte, error) {
	allEncodings := []*base64.Encoding{
		base64.RawURLEncoding, base64.StdEncoding, base64.RawStdEncoding,
	}

	for _, encoding := range allEncodings {
		value, err := encoding.DecodeString(s)
		if err == nil {
			return value, nil
		}
	}

	return nil, errors.New("unsupported encoding")
}

// DecodeProofValue decodes proofValue basing on proof type.
func DecodeProofValue(s, proofType string) ([]byte, error) {
	if proofType == ed25519Signature2020 {
		_, value, err := multibase.Decode(s)
		if err == nil {
			return value, nil
		}

		return nil, errors.New("unsupported encoding")
	}

	return decodeBase64(s)
}

// stringEntry.
func stringEntry(entry interface{}) string {
	if entry == nil {
		return ""
	}

	if strVal, ok := entry.(string); ok {
		return strVal
	}

	return ""
}

// JSONLdObject returns map that represents JSON LD Object.
func (p *Proof) JSONLdObject() map[string]interface{} { // nolint:gocyclo
	emap := make(map[string]interface{})
	emap[jsonldType] = p.Type

	if p.Creator != "" {
		emap[jsonldCreator] = p.Creator
	}

	if p.VerificationMethod != "" {
		emap[jsonldVerificationMethod] = p.VerificationMethod
	}

	if p.Created != nil {
		emap[jsonldCreated] = p.Created.FormatToString()
	}

	if len(p.ProofValue) > 0 {
		emap[jsonldProofValue] = EncodeProofValue(p.ProofValue, p.Type)
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

	if p.CapabilityChain != nil {
		emap[jsonldCapabilityChain] = p.CapabilityChain
	}

	return emap
}

// EncodeProofValue decodes proofValue basing on proof type.
func EncodeProofValue(proofValue []byte, proofType string) string {
	if proofType == ed25519Signature2020 {
		encoded, _ := multibase.Encode(multibase.Base58BTC, proofValue) //nolint: errcheck
		return encoded
	}

	return base64.RawURLEncoding.EncodeToString(proofValue)
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
