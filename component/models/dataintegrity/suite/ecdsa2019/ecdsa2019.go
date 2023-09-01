/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdsa2019

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"

	"github.com/multiformats/go-multibase"
	"github.com/piprate/json-gold/ld"

	kmsapi "github.com/hyperledger/aries-framework-go/spi/kms"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/component/models/dataintegrity/models"
	"github.com/hyperledger/aries-framework-go/component/models/dataintegrity/suite"
	"github.com/hyperledger/aries-framework-go/component/models/ld/processor"
	cryptoapi "github.com/hyperledger/aries-framework-go/spi/crypto"
)

const (
	// SuiteType "ecdsa-2019" is the data integrity Type identifier for the suite
	// implementing ecdsa signatures with RDF canonicalization as per this
	// spec:https://www.w3.org/TR/vc-di-ecdsa/#ecdsa-2019
	SuiteType = "ecdsa-2019"
)

// Suite implements the ecdsa-2019 data integrity cryptographic suite.
type Suite struct {
	ldLoader ld.DocumentLoader
	crypto   cryptoapi.Crypto
	kms      kmsapi.KeyManager
}

// Options provides initialization options for Suite.
type Options struct {
	LDDocumentLoader ld.DocumentLoader
	Crypto           cryptoapi.Crypto
	KMS              kmsapi.KeyManager
}

// SuiteInitializer is the initializer for Suite.
type SuiteInitializer func() (suite.Suite, error)

// New constructs an initializer for Suite.
func New(options *Options) SuiteInitializer {
	return func() (suite.Suite, error) {
		return &Suite{
			ldLoader: options.LDDocumentLoader,
			crypto:   options.Crypto,
			kms:      options.KMS,
		}, nil
	}
}

type initializer SuiteInitializer

// Signer private, implements suite.SignerInitializer.
func (i initializer) Signer() (suite.Signer, error) {
	return i()
}

// Verifier private, implements suite.VerifierInitializer.
func (i initializer) Verifier() (suite.Verifier, error) {
	return i()
}

// Type private, implements suite.SignerInitializer and
// suite.VerifierInitializer.
func (i initializer) Type() string {
	return SuiteType
}

// NewSigner returns a suite.SignerInitializer that initializes an ecdsa-2019
// signing Suite with the given Options.
func NewSigner(options *Options) suite.SignerInitializer {
	return initializer(New(options))
}

// NewVerifier returns a suite.VerifierInitializer that initializes an
// ecdsa-2019 verification Suite with the given Options.
func NewVerifier(options *Options) suite.VerifierInitializer {
	return initializer(New(options))
}

const (
	ldCtxKey = "@context"
)

// CreateProof implements the ecdsa-2019 cryptographic suite for Add Proof:
// https://www.w3.org/TR/vc-di-ecdsa/#add-proof-ecdsa-2019
func (s *Suite) CreateProof(doc []byte, opts *models.ProofOptions) (*models.Proof, error) {
	docHash, vmKey, err := s.transformAndHash(doc, opts)
	if err != nil {
		return nil, err
	}

	sig, err := sign(docHash, vmKey, s.crypto, s.kms)
	if err != nil {
		return nil, err
	}

	sigStr, err := multibase.Encode(multibase.Base58BTC, sig)
	if err != nil {
		return nil, err
	}

	p := &models.Proof{
		Type:               models.DataIntegrityProof,
		CryptoSuite:        SuiteType,
		ProofPurpose:       opts.Purpose,
		Domain:             opts.Domain,
		Challenge:          opts.Challenge,
		VerificationMethod: opts.VerificationMethod.ID,
		ProofValue:         sigStr,
	}

	return p, nil
}

func (s *Suite) transformAndHash(doc []byte, opts *models.ProofOptions) ([]byte, *jwk.JWK, error) {
	docData := make(map[string]interface{})

	err := json.Unmarshal(doc, &docData)
	if err != nil {
		return nil, nil, fmt.Errorf("ecdsa-2019 suite expects JSON-LD payload: %w", err)
	}

	vmKey := opts.VerificationMethod.JSONWebKey()
	if vmKey == nil {
		return nil, nil, errors.New("verification method needs JWK")
	}

	var h hash.Hash

	switch vmKey.Crv {
	case "P-256":
		h = sha256.New()
	case "P-384":
		h = sha512.New384()
	default:
		return nil, nil, errors.New("unsupported ECDSA curve")
	}

	confData := proofConfig(docData[ldCtxKey], opts)

	if opts.ProofType != "DataIntegrityProof" || opts.SuiteType != SuiteType {
		return nil, nil, suite.ErrProofTransformation
	}

	canonDoc, err := canonicalize(docData, s.ldLoader)
	if err != nil {
		return nil, nil, err
	}

	canonConf, err := canonicalize(confData, s.ldLoader)
	if err != nil {
		return nil, nil, err
	}

	docHash := hashData(canonDoc, canonConf, h)

	return docHash, vmKey, nil
}

// VerifyProof implements the ecdsa-2019 cryptographic suite for Verify Proof:
// https://www.w3.org/TR/vc-di-ecdsa/#verify-proof-ecdsa-2019
func (s *Suite) VerifyProof(doc []byte, proof *models.Proof, opts *models.ProofOptions) error {
	sigBase, vmKey, err := s.transformAndHash(doc, opts)
	if err != nil {
		return err
	}

	_, sig, err := multibase.Decode(proof.ProofValue)
	if err != nil {
		return fmt.Errorf("decoding proofValue: %w", err)
	}

	err = verify(sigBase, sig, vmKey, s.crypto, s.kms)
	if err != nil {
		return fmt.Errorf("failed to verify ecdsa-2019 DI proof: %w", err)
	}

	return nil
}

// RequiresCreated returns false, as the ecdsa-2019 cryptographic suite does not
// require the use of the models.Proof.Created field.
func (s *Suite) RequiresCreated() bool {
	return false
}

func canonicalize(data map[string]interface{}, loader ld.DocumentLoader) ([]byte, error) {
	out, err := processor.Default().GetCanonicalDocument(data, processor.WithDocumentLoader(loader))
	if err != nil {
		return nil, fmt.Errorf("canonicalizing signature base data: %w", err)
	}

	return out, nil
}

func hashData(transformedDoc, confData []byte, h hash.Hash) []byte {
	h.Write(transformedDoc)
	docHash := h.Sum(nil)

	h.Reset()
	h.Write(confData)
	result := h.Sum(docHash)

	return result
}

func proofConfig(docCtx interface{}, opts *models.ProofOptions) map[string]interface{} {
	return map[string]interface{}{
		ldCtxKey:             docCtx,
		"type":               models.DataIntegrityProof,
		"cryptosuite":        SuiteType,
		"verificationMethod": opts.VerificationMethodID,
		"created":            opts.Created.Format(models.DateTimeFormat),
		"proofPurpose":       opts.Purpose,
	}
}

// TODO copied from kid_creator.go, should move there: https://github.com/hyperledger/aries-framework-go/issues/3614
func kmsKID(key *jwk.JWK) (string, error) {
	tp, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("computing thumbprint for kms kid: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(tp), nil
}

func sign(sigBase []byte, key *jwk.JWK, cr cryptoapi.Crypto, kms kmsapi.KeyManager) ([]byte, error) {
	kid, err := kmsKID(key)
	if err != nil {
		return nil, err
	}

	kh, err := kms.Get(kid)
	if err != nil {
		return nil, err
	}

	sig, err := cr.Sign(sigBase, kh)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

func verify(sigBase, sig []byte, key *jwk.JWK, cr cryptoapi.Crypto, kms kmsapi.KeyManager) error {
	pkBytes, err := key.PublicKeyBytes()
	if err != nil {
		return fmt.Errorf("getting verification key bytes: %w", err)
	}

	kt, err := key.KeyType()
	if err != nil {
		return fmt.Errorf("getting key type of verification key: %w", err)
	}

	kh, err := kms.PubKeyBytesToHandle(pkBytes, kt)
	if err != nil {
		return err
	}

	err = cr.Verify(sig, sigBase, kh)
	if err != nil {
		return err
	}

	return nil
}
