/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dataintegrity

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"

	"github.com/hyperledger/aries-framework-go/component/models/dataintegrity/models"
	"github.com/hyperledger/aries-framework-go/component/models/dataintegrity/suite"
)

const (
	proofPath = "proof"
)

// Verifier implements the Verify Proof algorithm of the verifiable credential
// data integrity specification, using a set of provided cryptographic suites.
type Verifier struct {
	suites   map[string]suite.Verifier
	resolver didResolver
}

// NewVerifier initializes a Verifier that supports using the provided
// cryptographic suites to perform data integrity verification.
func NewVerifier(opts *Options, suites ...suite.VerifierInitializer) (*Verifier, error) {
	if opts == nil {
		opts = &Options{}
	}

	verifier := &Verifier{
		suites:   map[string]suite.Verifier{},
		resolver: opts.DIDResolver,
	}

	for _, initializer := range suites {
		suiteType := initializer.Type()

		if _, ok := verifier.suites[suiteType]; ok {
			continue
		}

		verifierSuite, err := initializer.Verifier()
		if err != nil {
			return nil, err
		}

		verifier.suites[suiteType] = verifierSuite
	}

	return verifier, nil
}

var (
	// ErrMissingProof is returned when Verifier.VerifyProof() is given a document
	// without a data integrity proof field.
	ErrMissingProof = errors.New("missing data integrity proof")
	// ErrMalformedProof is returned when Verifier.VerifyProof() is given a document
	// with a proof that isn't a JSON object or is missing necessary standard
	// fields.
	ErrMalformedProof = errors.New("malformed data integrity proof")
	// ErrWrongProofType is returned when Verifier.VerifyProof() is given a document
	// with a proof that isn't a Data Integrity proof.
	ErrWrongProofType = errors.New("proof provided is not a data integrity proof")
	// ErrMismatchedPurpose is returned when Verifier.VerifyProof() is given a
	// document with a proof whose Purpose does not match the expected purpose
	// provided in the proof options.
	ErrMismatchedPurpose = errors.New("data integrity proof does not match expected purpose")
	// ErrOutOfDate is returned when Verifier.VerifyProof() is given a document with
	// a proof that was created more than models.ProofOptions.MaxAge seconds ago.
	ErrOutOfDate = errors.New("data integrity proof out of date")
	// ErrInvalidDomain is returned when Verifier.VerifyProof() is given a document
	// with a proof without the expected domain.
	ErrInvalidDomain = errors.New("data integrity proof has invalid domain")
	// ErrInvalidChallenge is returned when Verifier.VerifyProof() is given a
	// document with a proof without the expected challenge.
	ErrInvalidChallenge = errors.New("data integrity proof has invalid challenge")
)

// VerifyProof verifies the data integrity proof on the given JSON document,
// returning an error if proof verification fails, and nil if verification
// succeeds.
func (v *Verifier) VerifyProof(doc []byte, opts *models.ProofOptions) error { // nolint:funlen,gocyclo
	proofRaw := gjson.GetBytes(doc, proofPath)

	if !proofRaw.Exists() {
		return ErrMissingProof
	}

	proof := &models.Proof{}

	err := json.Unmarshal([]byte(proofRaw.Raw), proof)
	if err != nil {
		return ErrMalformedProof
	}

	if proof.Type == "" || proof.VerificationMethod == "" || proof.ProofPurpose == "" {
		return ErrMalformedProof
	}

	if proof.Type != models.DataIntegrityProof {
		return ErrWrongProofType
	}

	verifierSuite, ok := v.suites[proof.CryptoSuite]
	if !ok {
		return ErrUnsupportedSuite
	}

	if opts.SuiteType == "" {
		opts.SuiteType = proof.CryptoSuite
	}

	if verifierSuite.RequiresCreated() && proof.Created == "" {
		return ErrMalformedProof
	}

	if opts.Created.IsZero() {
		var parsedCreatedTime time.Time

		parsedCreatedTime, err = time.Parse(models.DateTimeFormat, proof.Created)
		if err != nil {
			return ErrMalformedProof
		}

		opts.Created = parsedCreatedTime
	}

	if proof.ProofPurpose != opts.Purpose {
		return ErrMismatchedPurpose
	}

	unsecuredDoc, err := sjson.DeleteBytes(doc, proofPath)
	if err != nil {
		return ErrMalformedProof
	}

	err = resolveVM(opts, v.resolver, proof.VerificationMethod)
	if err != nil {
		return err
	}

	verifyResult := verifierSuite.VerifyProof(unsecuredDoc, proof, opts)

	if proof.Created != "" {
		createdTime, err := time.Parse(models.DateTimeFormat, proof.Created)
		if err != nil {
			return ErrMalformedProof
		}

		if opts.MaxAge > 0 {
			now := time.Now()

			diff := now.Sub(createdTime)

			if diff > time.Second*time.Duration(opts.MaxAge) {
				return ErrOutOfDate
			}
		}
	}

	if opts.Domain != "" && opts.Domain != proof.Domain {
		return ErrInvalidDomain
	}

	if opts.Challenge != "" && opts.Challenge != proof.Challenge {
		return ErrInvalidChallenge
	}

	return verifyResult
}
