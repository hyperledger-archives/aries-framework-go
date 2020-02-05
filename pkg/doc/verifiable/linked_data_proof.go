/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
)

// signatureSuite encapsulates signature suite methods required for signing documents
type signatureSuite interface {

	// GetCanonicalDocument will return normalized/canonical version of the document
	GetCanonicalDocument(doc map[string]interface{}) ([]byte, error)

	// GetDigest returns document digest
	GetDigest(doc []byte) []byte

	// Accept registers this signature suite with the given signature type
	Accept(signatureType string) bool
}

type verifierSignatureSuite interface {
	signatureSuite

	// Verify will verify signature against public key
	Verify(pubKey []byte, doc []byte, signature []byte) error
}

type signerSignatureSuite interface {
	signatureSuite

	// Sign will sign JSON LD document
	Sign(jsonLdDoc []byte) ([]byte, error)
}

type keyResolverAdapter struct {
	pubKeyFetcher PublicKeyFetcher
}

func (k *keyResolverAdapter) Resolve(id string) ([]byte, error) {
	fetcher, err := k.pubKeyFetcher("", id)
	if err != nil {
		return nil, err
	}

	pubKeyBytes, ok := fetcher.([]byte)
	if !ok {
		return nil, errors.New("expecting []byte public key, got something else")
	}

	return pubKeyBytes, nil
}

// LinkedDataProofContext holds options needed to build a Linked Data Proof.
type LinkedDataProofContext struct {
	SignatureType string               // required
	Suite         signerSignatureSuite // required
	Creator       string               // required
	Created       *time.Time           // optional
}

func checkLinkedDataProof(jsonldBytes []byte, suite verifierSignatureSuite, pubKeyFetcher PublicKeyFetcher) error {
	documentVerifier := verifier.New(
		&keyResolverAdapter{pubKeyFetcher},
		suite)

	err := documentVerifier.Verify(jsonldBytes)
	if err != nil {
		return fmt.Errorf("check linked data proof: %w", err)
	}

	return nil
}

type rawProof struct {
	Proof json.RawMessage `json:"proof,omitempty"`
}

func addLinkedDataProof(context *LinkedDataProofContext, jsonldBytes []byte) ([]Proof, error) {
	documentSigner := signer.New(context.Suite)

	vcWithNewProofBytes, err := documentSigner.Sign(mapContext(context), jsonldBytes)
	if err != nil {
		return nil, fmt.Errorf("add linked data proof: %w", err)
	}

	// Get a proof from json-ld document.
	var rProof rawProof

	err = json.Unmarshal(vcWithNewProofBytes, &rProof)
	if err != nil {
		return nil, err
	}

	proofs, err := decodeProof(rProof.Proof)
	if err != nil {
		return nil, err
	}

	return proofs, nil
}

func mapContext(context *LinkedDataProofContext) *signer.Context {
	return &signer.Context{
		SignatureType: context.SignatureType,
		Created:       context.Created,
		Creator:       context.Creator,
	}
}
