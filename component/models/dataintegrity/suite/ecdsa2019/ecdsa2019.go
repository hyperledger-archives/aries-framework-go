/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdsa2019

import (
	"errors"

	"github.com/hyperledger/aries-framework-go/component/models/dataintegrity/models"
	"github.com/hyperledger/aries-framework-go/component/models/dataintegrity/suite"
)

// TODO note: a Suite could implement both signer and verifier in the same type, or could have separate implementations
//  so, for example, verifier can be initialized without needing permissions/access for private key usage

const (
	// SuiteType "ecdsa-2019" is the data integrity Type identifier for the suite
	// implementing ecdsa signatures with RDF canonicalization as per this
	// spec:https://www.w3.org/TR/vc-di-ecdsa/#ecdsa-2019
	SuiteType = "ecdsa-2019"
)

// Suite implements the ecdsa-2019 data integrity cryptographic suite.
type Suite struct{}

// Options provides initialization options for Suite.
type Options struct{}

// SuiteInitializer is the initializer for Suite.
type SuiteInitializer func() (suite.Suite, error)

// New constructs an initializer for Suite.
func New(options *Options) SuiteInitializer {
	return func() (suite.Suite, error) {
		return &Suite{}, nil
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

// CreateProof implements the ecdsa-2019 cryptographic suite for Add Proof:
// https://www.w3.org/TR/vc-di-ecdsa/#add-proof-ecdsa-2019
func (s *Suite) CreateProof(doc []byte, opts *models.ProofOptions) (*models.Proof, error) {
	return nil, errors.New("implement me")
}

// VerifyProof implements the ecdsa-2019 cryptographic suite for Verify Proof:
// https://www.w3.org/TR/vc-di-ecdsa/#verify-proof-ecdsa-2019
func (s *Suite) VerifyProof(doc []byte, proof *models.Proof, opts *models.ProofOptions) error {
	return errors.New("implement me")
}

// RequiresCreated returns false, as the ecdsa-2019 cryptographic suite does not
// require the use of the models.Proof.Created field.
func (s *Suite) RequiresCreated() bool {
	return false
}
