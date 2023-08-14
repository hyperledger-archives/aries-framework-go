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
)

const (
	// SuiteType "ecdsa-2019" is the data integrity Type identifier for the suite
	// implementing ecdsa signatures with RDF canonicalization as per this
	// spec:https://www.w3.org/TR/vc-di-ecdsa/#ecdsa-2019
	SuiteType = "ecdsa-2019"
)

// A Signer is able to sign messages.
type Signer interface {
	// Sign will sign msg using a matching signature primitive in kh key handle of a private key
	// returns:
	// 		signature in []byte
	//		error in case of errors
	Sign(msg []byte, kh interface{}) ([]byte, error)
}

// A Verifier is able to verify messages.
type Verifier interface {
	// Verify will verify a signature for the given msg using a matching signature primitive in kh key handle of
	// a public key
	// returns:
	// 		error in case of errors or nil if signature verification was successful
	Verify(signature, msg []byte, kh interface{}) error
}

// Suite implements the ecdsa-2019 data integrity cryptographic suite.
type Suite struct {
	ldLoader ld.DocumentLoader
	signer   Signer
	verifier Verifier
	kms      kmsapi.KeyManager
}

// Options provides initialization options for Suite.
type Options struct {
	LDDocumentLoader ld.DocumentLoader
	Signer           Signer
	Verifier         Verifier
	KMS              kmsapi.KeyManager
}

// SuiteInitializer is the initializer for Suite.
type SuiteInitializer func() (suite.Suite, error)

// New constructs an initializer for Suite.
func New(options *Options) SuiteInitializer {
	return func() (suite.Suite, error) {
		return &Suite{
			ldLoader: options.LDDocumentLoader,
			signer:   options.Signer,
			verifier: options.Verifier,
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

// SignerInitializerOptions provides options for a SignerInitializer.
type SignerInitializerOptions struct {
	LDDocumentLoader ld.DocumentLoader
	Signer           Signer
	KMS              kmsapi.KeyManager
}

// NewSignerInitializer returns a suite.SignerInitializer that initializes an ecdsa-2019
// signing Suite with the given SignerInitializerOptions.
func NewSignerInitializer(options *SignerInitializerOptions) suite.SignerInitializer {
	return initializer(New(&Options{
		LDDocumentLoader: options.LDDocumentLoader,
		Signer:           options.Signer,
		KMS:              options.KMS,
	}))
}

// VerifierInitializerOptions provides options for a VerifierInitializer.
type VerifierInitializerOptions struct {
	LDDocumentLoader ld.DocumentLoader
	Verifier         Verifier
	KMS              kmsapi.KeyManager
}

// NewVerifierInitializer returns a suite.VerifierInitializer that initializes an
// ecdsa-2019 verification Suite with the given VerifierInitializerOptions.
func NewVerifierInitializer(options *VerifierInitializerOptions) suite.VerifierInitializer {
	return initializer(New(&Options{
		LDDocumentLoader: options.LDDocumentLoader,
		Verifier:         options.Verifier,
		KMS:              options.KMS,
	}))
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

	sig, err := sign(docHash, vmKey, s.signer, s.kms)
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

	confData, err := proofConfig(docData[ldCtxKey], opts)
	if err != nil {
		return nil, nil, err
	}

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

	err = verify(sigBase, sig, vmKey, s.verifier, s.kms)
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

func proofConfig(docCtx interface{}, opts *models.ProofOptions) (map[string]interface{}, error) {
	if opts.Purpose != opts.VerificationRelationship {
		return nil, errors.New("verification method is not suitable for purpose")
	}

	timeStr := opts.Created.Format(models.DateTimeFormat)

	conf := map[string]interface{}{
		ldCtxKey:             docCtx,
		"type":               models.DataIntegrityProof,
		"cryptosuite":        SuiteType,
		"verificationMethod": opts.VerificationMethodID,
		"created":            timeStr,
		"proofPurpose":       opts.Purpose,
	}

	return conf, nil
}

// TODO copied from kid_creator.go, should move there: https://github.com/hyperledger/aries-framework-go/issues/3614
func kmsKID(key *jwk.JWK) (string, error) {
	tp, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("computing thumbprint for kms kid: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(tp), nil
}

func sign(sigBase []byte, key *jwk.JWK, signer Signer, kms kmsapi.KeyManager) ([]byte, error) {
	kid, err := kmsKID(key)
	if err != nil {
		return nil, err
	}

	kh, err := kms.Get(kid)
	if err != nil {
		return nil, err
	}

	sig, err := signer.Sign(sigBase, kh)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

func verify(sigBase, sig []byte, key *jwk.JWK, verifier Verifier, kms kmsapi.KeyManager) error {
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

	err = verifier.Verify(sig, sigBase, kh)
	if err != nil {
		return err
	}

	return nil
}
