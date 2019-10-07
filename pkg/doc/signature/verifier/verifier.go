/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifier

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/proof"
)

// signatureSuite encapsulates signature suite methods required for signature verification
type signatureSuite interface {

	// GetCanonicalDocument will return normalized/canonical version of the document
	GetCanonicalDocument(doc map[string]interface{}) ([]byte, error)

	// GetDigest returns document digest
	GetDigest(doc []byte) []byte

	// Verify will verify signature against public key
	Verify(pubKey []byte, doc []byte, signature []byte) error

	// Accept registers this signature suite with the given signature type
	Accept(signatureType string) bool
}

// keyResolver encapsulates key resolution
type keyResolver interface {

	// Resolve will return public key bytes
	Resolve(id string) ([]byte, error)
}

// DocumentVerifier implements JSON LD document proof verification
type DocumentVerifier struct {
	signatureSuites []signatureSuite
	pkResolver      keyResolver
}

// New returns new instance of document verifier
func New(resolver keyResolver) *DocumentVerifier {
	var signatureSuites []signatureSuite
	signatureSuites = append(signatureSuites, &ed25519signature2018.SignatureSuite{})

	return &DocumentVerifier{signatureSuites: signatureSuites, pkResolver: resolver}
}

// Verify will verify document proofs
func (dv *DocumentVerifier) Verify(jsonLdDoc []byte) error {
	var jsonLdObject map[string]interface{}
	err := json.Unmarshal(jsonLdDoc, &jsonLdObject)
	if err != nil {
		return fmt.Errorf("failed to unmarshal json ld document: %w", err)
	}

	return dv.verifyObject(jsonLdObject)
}

// verifyObject will verify document proofs for JSON LD object
func (dv *DocumentVerifier) verifyObject(jsonLdObject map[string]interface{}) error {
	proofs, err := proof.GetProofs(jsonLdObject)
	if err != nil {
		return err
	}

	for _, p := range proofs {
		publicKey, err := dv.pkResolver.Resolve(p.Creator)
		if err != nil {
			return err
		}

		suite, err := dv.getSignatureSuite(p.Type)
		if err != nil {
			return err
		}

		message, err := proof.CreateVerifyHash(suite, jsonLdObject, p.JSONLdObject())
		if err != nil {
			return err
		}

		err = suite.Verify(publicKey, message, p.ProofValue)
		if err != nil {
			return err
		}
	}

	return nil
}

// getSignatureSuite returns signature suite based on signature type
func (dv *DocumentVerifier) getSignatureSuite(signatureType string) (signatureSuite, error) {
	for _, s := range dv.signatureSuites {
		if s.Accept(signatureType) {
			return s, nil
		}
	}
	return nil, fmt.Errorf("signature type %s not supported", signatureType)
}
