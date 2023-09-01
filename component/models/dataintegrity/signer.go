/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dataintegrity

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/tidwall/sjson"

	"github.com/hyperledger/aries-framework-go/component/models/dataintegrity/models"
	"github.com/hyperledger/aries-framework-go/component/models/dataintegrity/suite"
	"github.com/hyperledger/aries-framework-go/component/models/did"
)

const (
	// AssertionMethod assertionMethod.
	AssertionMethod = "assertionMethod"

	// Authentication authentication.
	Authentication = "authentication"

	// CapabilityDelegation capabilityDelegation.
	CapabilityDelegation = "capabilityDelegation"

	// CapabilityInvocation capabilityInvocation.
	CapabilityInvocation = "capabilityInvocation"

	creatorParts           = 2
	invalidFormatErrMsgFmt = "verificationMethod value %s should be in did#keyID format"
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
	if opts.VerificationMethod == nil {
		if opts.VerificationMethodID == "" {
			opts.VerificationMethodID = vmID
		}

		if resolver == nil {
			return ErrNoResolver
		}

		didDoc, err := getDIDDocFromVerificationMethod(opts.VerificationMethodID, resolver)
		if err != nil {
			// TODO update linter to use go 1.20: https://github.com/hyperledger/aries-framework-go/issues/3613
			return errors.Join(ErrVMResolution, err) // nolint:typecheck
		}

		vm, err := getVMByPurpose(opts.Purpose, opts.VerificationMethodID, didDoc)
		if err != nil {
			// TODO update linter to use go 1.20: https://github.com/hyperledger/aries-framework-go/issues/3613
			return errors.Join(ErrVMResolution, err) // nolint:typecheck
		}

		opts.VerificationMethod = vm
	}

	return nil
}

func getVMByPurpose(purpose, vmID string, didDoc *did.Doc) (*did.VerificationMethod, error) {
	var verificationMethod *did.VerificationMethod

	vmIDFragment := vmIDFragmentOnly(vmID)

	switch purpose {
	case AssertionMethod:
		assertionMethods := didDoc.VerificationMethods(did.AssertionMethod)[did.AssertionMethod]

		verificationMethod = getVM(vmIDFragment, assertionMethods)
		if verificationMethod == nil {
			// A VM with general relationship is allowed for assertion
			generalMethods :=
				didDoc.VerificationMethods(did.VerificationRelationshipGeneral)[did.VerificationRelationshipGeneral]

			verificationMethod = getVM(vmIDFragment, generalMethods)
		}
	case Authentication:
		authMethods := didDoc.VerificationMethods(did.Authentication)[did.Authentication]

		verificationMethod = getVM(vmIDFragment, authMethods)
	case CapabilityDelegation:
		capabilityDelegationMethods := didDoc.VerificationMethods(did.CapabilityDelegation)[did.CapabilityDelegation]

		verificationMethod = getVM(vmIDFragment, capabilityDelegationMethods)
	case CapabilityInvocation:
		capabilityInvocationMethods := didDoc.VerificationMethods(did.CapabilityInvocation)[did.CapabilityInvocation]

		verificationMethod = getVM(vmIDFragment, capabilityInvocationMethods)
	default:
		return nil, fmt.Errorf("purpose %s not supported", purpose)
	}

	if verificationMethod == nil {
		return nil, fmt.Errorf("unable to find matching %s key IDs for given verification method ID %s",
			purpose, vmID)
	}

	return verificationMethod, nil
}

func getVM(vmID string, vms []did.Verification) *did.VerificationMethod {
	for _, verification := range vms {
		if vmID == vmIDFragmentOnly(verification.VerificationMethod.ID) {
			return &verification.VerificationMethod
		}
	}

	return nil
}

func vmIDFragmentOnly(vmID string) string {
	vmSplit := strings.Split(vmID, "#")
	if len(vmSplit) == 1 {
		return vmSplit[0]
	}

	return vmSplit[1]
}

func getDIDDocFromVerificationMethod(verificationMethod string, didResolver didResolver) (*did.Doc, error) {
	didID, err := getDIDFromVerificationMethod(verificationMethod)
	if err != nil {
		return nil, err
	}

	docResolution, err := didResolver.Resolve(didID)
	if err != nil {
		return nil, err
	}

	return docResolution.DIDDocument, nil
}

func getDIDFromVerificationMethod(creator string) (string, error) {
	idSplit := strings.Split(creator, "#")
	if len(idSplit) != creatorParts {
		return "", fmt.Errorf(fmt.Sprintf(invalidFormatErrMsgFmt, creator))
	}

	return idSplit[0], nil
}
