/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/hyperledger/aries-framework-go/component/models/ld/processor"
	"github.com/hyperledger/aries-framework-go/component/models/ld/proof"
)

const defaultProofPurpose = "assertionMethod"

// SignatureSuite encapsulates signature suite methods required for signing documents.
type SignatureSuite interface {
	// GetCanonicalDocument will return normalized/canonical version of the document
	GetCanonicalDocument(doc map[string]interface{}, opts ...processor.Opts) ([]byte, error)

	// GetDigest returns document digest
	GetDigest(doc []byte) []byte

	// Accept registers this signature suite with the given signature type
	Accept(signatureType string) bool

	// Sign will sign document and return signature
	Sign(doc []byte) ([]byte, error)

	// Alg will return algorithm
	Alg() string

	// CompactProof indicates weather to compact the proof doc before canonization
	CompactProof() bool
}

// DocumentSigner implements signing of JSONLD documents.
type DocumentSigner struct {
	signatureSuites []SignatureSuite
}

// Context holds signing options and private key.
type Context struct {
	SignatureType           string                        // required
	Creator                 string                        // required
	SignatureRepresentation proof.SignatureRepresentation // optional
	Created                 *time.Time                    // optional
	Domain                  string                        // optional
	Nonce                   []byte                        // optional
	VerificationMethod      string                        // optional
	Challenge               string                        // optional
	Purpose                 string                        // optional
	CapabilityChain         []interface{}                 // optional
}

// New returns new instance of document verifier.
func New(signatureSuites ...SignatureSuite) *DocumentSigner {
	return &DocumentSigner{signatureSuites: signatureSuites}
}

// Sign  will sign JSON LD document.
func (signer *DocumentSigner) Sign(
	context *Context,
	jsonLdDoc []byte,
	opts ...processor.Opts,
) ([]byte, error) {
	var jsonLdObject map[string]interface{}

	err := json.Unmarshal(jsonLdDoc, &jsonLdObject)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal json ld document: %w", err)
	}

	err = signer.signObject(context, jsonLdObject, opts)
	if err != nil {
		return nil, err
	}

	signedDoc, err := json.Marshal(jsonLdObject)
	if err != nil {
		return nil, err
	}

	return signedDoc, nil
}

// signObject is a helper method that operates on JSON LD objects.
func (signer *DocumentSigner) signObject(context *Context, jsonLdObject map[string]interface{},
	opts []processor.Opts) error {
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

	p := &proof.Proof{
		Type:                    context.SignatureType,
		SignatureRepresentation: context.SignatureRepresentation,
		Creator:                 context.Creator,
		Created:                 wrapTime(*created),
		Domain:                  context.Domain,
		Nonce:                   context.Nonce,
		VerificationMethod:      context.VerificationMethod,
		Challenge:               context.Challenge,
		ProofPurpose:            context.Purpose,
		CapabilityChain:         context.CapabilityChain,
	}

	// TODO support custom proof purpose
	//  (https://github.com/hyperledger/aries-framework-go/issues/1586)
	if p.ProofPurpose == "" {
		p.ProofPurpose = defaultProofPurpose
	}

	if context.SignatureRepresentation == proof.SignatureJWS {
		p.JWS = proof.CreateDetachedJWTHeader(suite.Alg()) + ".."
	}

	message, err := proof.CreateVerifyData(suite, jsonLdObject, p, append(opts, processor.WithValidateRDF())...)
	if err != nil {
		return err
	}

	s, err := suite.Sign(message)
	if err != nil {
		return err
	}

	signer.applySignatureValue(context, p, s)

	return proof.AddProof(jsonLdObject, p)
}

func (signer *DocumentSigner) applySignatureValue(context *Context, p *proof.Proof, s []byte) {
	switch context.SignatureRepresentation {
	case proof.SignatureProofValue:
		p.ProofValue = s
	case proof.SignatureJWS:
		p.JWS += base64.RawURLEncoding.EncodeToString(s)
	}
}

// getSignatureSuite returns signature suite based on signature type.
func (signer *DocumentSigner) getSignatureSuite(signatureType string) (SignatureSuite, error) {
	for _, s := range signer.signatureSuites {
		if s.Accept(signatureType) {
			return s, nil
		}
	}

	return nil, fmt.Errorf("signature type %s not supported", signatureType)
}

// isValidContext checks required parameters (for signing).
func isValidContext(context *Context) error {
	if context.SignatureType == "" {
		return errors.New("signature type is missing")
	}

	return nil
}
