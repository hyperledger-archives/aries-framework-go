/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dataintegrity

import (
	"encoding/json"
	"errors"

	"github.com/tidwall/sjson"

	"github.com/hyperledger/aries-framework-go/component/models/jwt/didsignjwt"

	"github.com/hyperledger/aries-framework-go/component/models/dataintegrity/models"
	"github.com/hyperledger/aries-framework-go/component/models/dataintegrity/suite"
)

// Signer implements the Add Proof algorithm of the verifiable credential data
// integrity specification, using a set of provided cryptographic suites.
type Signer struct {
	suites   map[string]suite.Signer
	resolver didResolver
}

// NewSigner initializes a Signer that supports using the provided cryptographic
// suites to perform data integrity signing.
func NewSigner(opts *Options, suites ...suite.SignerInitializer) (*Signer, error) {
	if opts == nil {
		opts = &Options{}
	}

	signer := &Signer{
		suites:   map[string]suite.Signer{},
		resolver: opts.DIDResolver,
	}

	for _, initializer := range suites {
		suiteType := initializer.Type()

		if _, ok := signer.suites[suiteType]; ok {
			continue
		}

		signingSuite, err := initializer.Signer()
		if err != nil {
			return nil, err
		}

		signer.suites[suiteType] = signingSuite
	}

	return signer, nil
}

var (
	// ErrProofGeneration is returned when Signer.AddProof() fails to generate a
	// proof using a supported cryptographic suite.
	ErrProofGeneration = errors.New("data integrity proof generation error")
)

// AddProof returns the provided JSON doc, with a top-level "proof" field added,
// signed using the provided options.
//
// If the provided options request a cryptographic suite that this Signer does
// not support, AddProof returns ErrUnsupportedSuite.
//
// If signing fails, or the created proof is invalid, AddProof returns
// ErrProofGeneration.
func (s *Signer) AddProof(doc []byte, opts *models.ProofOptions) ([]byte, error) { // nolint:gocyclo
	signerSuite, ok := s.suites[opts.SuiteType]
	if !ok {
		return nil, ErrUnsupportedSuite
	}

	err := resolveVM(opts, s.resolver, "")
	if err != nil {
		return nil, err
	}

	proof, err := signerSuite.CreateProof(doc, opts)
	if err != nil {
		// TODO update linter to use go 1.20: https://github.com/hyperledger/aries-framework-go/issues/3613
		return nil, errors.Join(ErrProofGeneration, err) // nolint:typecheck
	}

	if proof.Type == "" || proof.ProofPurpose == "" || proof.VerificationMethod == "" {
		return nil, ErrProofGeneration
	}

	if proof.Created == "" && signerSuite.RequiresCreated() {
		return nil, ErrProofGeneration
	}

	if opts.Domain != "" && opts.Domain != proof.Domain {
		return nil, ErrProofGeneration
	}

	if opts.Challenge != "" && opts.Challenge != proof.Challenge {
		return nil, ErrProofGeneration
	}

	proofRaw, err := json.Marshal(proof)
	if err != nil {
		return nil, ErrProofGeneration
	}

	out, err := sjson.SetRawBytes(doc, proofPath, proofRaw)
	if err != nil {
		// TODO update linter to use go 1.20: https://github.com/hyperledger/aries-framework-go/issues/3613
		return nil, errors.Join(ErrProofGeneration, err) // nolint:typecheck
	}

	return out, nil
}

func resolveVM(opts *models.ProofOptions, resolver didResolver, vmID string) error {
	if opts.VerificationMethod == nil || opts.VerificationRelationship == "" {
		if opts.VerificationMethodID == "" {
			opts.VerificationMethodID = vmID
		}

		if resolver == nil {
			return ErrNoResolver
		}

		vm, vmID, rel, err := didsignjwt.ResolveSigningVMWithRelationship(opts.VerificationMethodID, resolver)
		if err != nil {
			// TODO update linter to use go 1.20: https://github.com/hyperledger/aries-framework-go/issues/3613
			return errors.Join(ErrVMResolution, err) // nolint:typecheck
		}

		opts.VerificationMethodID = vmID
		opts.VerificationMethod = vm

		// A VM with general relationship is allowed for assertion
		if rel == "" {
			rel = "assertionMethod"
		}

		opts.VerificationRelationship = rel
	}

	return nil
}
