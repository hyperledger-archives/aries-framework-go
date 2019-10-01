/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/proof"
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

type signer interface {
	// Sign will sign document and return signature
	Sign(doc []byte) ([]byte, error)
}

// DocumentSigner implements signing of JSONLD documents
type DocumentSigner struct {
	signatureSuites []signatureSuite
}

// Context holds signing options and private key
type Context struct {
	SignatureType string     // required
	Creator       string     // required
	Signer        signer     // required
	Created       *time.Time // optional
	Domain        string     // optional
	Nonce         []byte     // optional
}

// New returns new instance of document verifier
func New() *DocumentSigner {
	var signatureSuites []signatureSuite
	signatureSuites = append(signatureSuites, &ed25519signature2018.SignatureSuite{})

	return &DocumentSigner{signatureSuites: signatureSuites}
}

// Sign  will sign JSON LD document
func (signer *DocumentSigner) Sign(context *Context, jsonLdDoc []byte) ([]byte, error) {
	var jsonLdObject map[string]interface{}
	err := json.Unmarshal(jsonLdDoc, &jsonLdObject)
	if err != nil {
		return nil, fmt.Errorf("failed tu unmarshall json ld document: %w", err)
	}

	err = signer.signObject(context, jsonLdObject)
	if err != nil {
		return nil, err
	}

	signedDoc, err := json.Marshal(jsonLdObject)
	if err != nil {
		return nil, err
	}

	return signedDoc, nil
}

// signObject is a helper method that operates on JSON LD objects
func (signer *DocumentSigner) signObject(context *Context, jsonLdObject map[string]interface{}) error {
	if err := isValidContext(context); err != nil {
		return err
	}

	suite, err := signer.getSignatureSuite(context.SignatureType)
	if err != nil {
		return err
	}

	created := context.Created
	if created == nil {
		now := time.Now()
		created = &now
	}

	p := proof.Proof{
		Type:    context.SignatureType,
		Creator: context.Creator,
		Created: created,
		Domain:  context.Domain,
		Nonce:   context.Nonce,
	}

	message, err := proof.CreateVerifyHashAlgorithm(suite, jsonLdObject, p.JSONLdObject())
	if err != nil {
		return err
	}

	s, err := context.Signer.Sign(message)
	if err != nil {
		return err
	}

	p.ProofValue = s

	return proof.AddProof(jsonLdObject, &p)
}

// getSignatureSuite returns signature suite based on signature type
func (signer *DocumentSigner) getSignatureSuite(signatureType string) (signatureSuite, error) {
	for _, s := range signer.signatureSuites {
		if s.Accept(signatureType) {
			return s, nil
		}
	}
	return nil, fmt.Errorf("signature type %s not supported", signatureType)
}

// isValidContext checks required parameters (for signing)
func isValidContext(context *Context) error {
	// we need creator, signatureType and signer
	if context.Creator == "" {
		return errors.New("creator is missing")
	}

	if context.SignatureType == "" {
		return errors.New("signature type is missing")
	}

	if context.Signer == nil {
		return errors.New("signer is missing")
	}

	return nil
}
