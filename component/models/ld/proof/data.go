/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package proof

import (
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/component/models/ld/processor"
)

const jsonldContext = "@context"

// signatureSuite encapsulates signature suite methods required for normalizing document.
type signatureSuite interface {

	// GetCanonicalDocument will return normalized/canonical version of the document
	GetCanonicalDocument(doc map[string]interface{}, opts ...processor.Opts) ([]byte, error)

	// GetDigest returns document digest
	GetDigest(doc []byte) []byte

	// CompactProof indicates weather to compact the proof doc before canonization
	CompactProof() bool
}

// SignatureRepresentation defines a representation of signature value.
type SignatureRepresentation int

const (
	// SignatureProofValue uses "proofValue" field in a Proof to put/read a digital signature.
	SignatureProofValue SignatureRepresentation = iota

	// SignatureJWS uses "jws" field in a Proof as an element for representation of detached JSON Web Signatures.
	SignatureJWS
)

// CreateVerifyData creates data that is used to generate or verify a digital signature.
// It depends on the signature value holder type.
// In case of "proofValue", the standard Create Verify Hash algorithm is used.
// In case of "jws", verify data is built as JSON Web Signature (JWS) with detached payload.
func CreateVerifyData(suite signatureSuite, jsonldDoc map[string]interface{}, proof *Proof,
	opts ...processor.Opts) ([]byte, error) {
	switch proof.SignatureRepresentation {
	case SignatureProofValue:
		return CreateVerifyHash(suite, jsonldDoc, proof.JSONLdObject(), opts...)
	case SignatureJWS:
		return createVerifyJWS(suite, jsonldDoc, proof, opts...)
	}

	return nil, fmt.Errorf("unsupported signature representation: %v", proof.SignatureRepresentation)
}

// CreateVerifyHash returns data that is used to generate or verify a digital signature
// Algorithm steps are described here https://w3c-dvcg.github.io/ld-signatures/#create-verify-hash-algorithm
func CreateVerifyHash(suite signatureSuite, jsonldDoc, proofOptions map[string]interface{},
	opts ...processor.Opts) ([]byte, error) {
	// in  order to generate canonical form we need context
	// if context is not passed, use document's context
	// spec doesn't mention anything about context
	_, ok := proofOptions[jsonldContext]
	if !ok {
		proofOptions[jsonldContext] = jsonldDoc[jsonldContext]
	}

	canonicalProofOptions, err := prepareCanonicalProofOptions(suite, proofOptions, opts...)
	if err != nil {
		return nil, err
	}

	proofOptionsDigest := suite.GetDigest(canonicalProofOptions)

	canonicalDoc, err := prepareCanonicalDocument(suite, jsonldDoc, opts...)
	if err != nil {
		return nil, err
	}

	docDigest := suite.GetDigest(canonicalDoc)

	return append(proofOptionsDigest, docDigest...), nil
}

func prepareCanonicalProofOptions(suite signatureSuite, proofOptions map[string]interface{},
	opts ...processor.Opts) ([]byte, error) {
	value, ok := proofOptions[jsonldCreated]
	if !ok || value == nil {
		return nil, errors.New("created is missing")
	}

	// copy from the original proof options map without specific keys
	proofOptionsCopy := make(map[string]interface{}, len(proofOptions))

	for key, value := range proofOptions {
		if excludedKeyFromString(key) == 0 {
			proofOptionsCopy[key] = value
		}
	}

	if suite.CompactProof() {
		docCompacted, err := getCompactedWithSecuritySchema(proofOptionsCopy, opts...)
		if err != nil {
			return nil, err
		}

		proofOptionsCopy = docCompacted
	}

	// build canonical proof options
	return suite.GetCanonicalDocument(proofOptionsCopy, opts...)
}

func prepareCanonicalDocument(suite signatureSuite, jsonldObject map[string]interface{},
	opts ...processor.Opts) ([]byte, error) {
	// copy document object without proof
	docCopy := GetCopyWithoutProof(jsonldObject)

	// build canonical document
	return suite.GetCanonicalDocument(docCopy, opts...)
}

// excludedKey defines keys that are excluded for proof options.
type excludedKey uint

const (
	proofID excludedKey = iota + 1
	proofValue
	jws
	nonce
)

//nolint:gochecknoglobals
var (
	excludedKeysStr = [...]string{"id", "proofValue", "jws", "nonce"}
	excludedKeys    = [...]excludedKey{proofID, proofValue, jws, nonce}
)

func (ek excludedKey) String() string {
	return excludedKeysStr[ek-1]
}

func excludedKeyFromString(s string) excludedKey {
	for _, ek := range excludedKeys {
		if ek.String() == s {
			return ek
		}
	}

	return 0
}
