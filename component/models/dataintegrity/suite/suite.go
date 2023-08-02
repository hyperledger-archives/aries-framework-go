/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package suite

import (
	"errors"

	"github.com/hyperledger/aries-framework-go/component/models/dataintegrity/models"
)

// RequiresCreated specifies that a data integrity suite implementation, must
// provide a method that tells the caller whether this suite requires the
// proof.Created field to exist.
type RequiresCreated interface {
	RequiresCreated() bool
}

// Signer is an implementation of a data integrity cryptographic suite that
// provides the transform, hash, and proof generation steps of the data
// integrity Add Proof algorithm.
type Signer interface {
	// CreateProof performs data integrity proof creation steps: transform, hash,
	// and proof generation, using this implementation's cryptographic suite.
	CreateProof(doc []byte, opts *models.ProofOptions) (*models.Proof, error)
	RequiresCreated
}

// Verifier is an implementation of a data integrity cryptographic suite that
// provides the transform, hash, and proof verification steps of the data
// integrity Verify Proof algorithm.
type Verifier interface {
	// VerifyProof performs data integrity proof verification steps: transform,
	// hash, and proof verification, using this implementation's cryptographic
	// suite.
	VerifyProof(doc []byte, proof *models.Proof, opts *models.ProofOptions) error
	RequiresCreated
}

// Suite implements a data integrity cryptographic suite for both proof creation
// and proof verification.
type Suite interface {
	Signer
	Verifier
}

// Type provides a method that returns the cryptographic suite type of the
// corresponding suite. Each suite has a type constant that's defined in its
// associated specification.
type Type interface {
	Type() string
}

// SignerInitializer initializes a Signer, using initialization options that
// were passed into the SignerInitializer's creation.
type SignerInitializer interface {
	Signer() (Signer, error)
	Type
}

// VerifierInitializer initializes a Verifier, using initialization options that
// were passed into the VerifierInitializer's creation.
type VerifierInitializer interface {
	Verifier() (Verifier, error)
	Type
}

var (
	// ErrInvalidProof is returned by Verifier.VerifyProof when the given proof is
	// invalid.
	ErrInvalidProof = errors.New("data integrity proof invalid")
	// ErrProofTransformation is returned by Signer.CreateProof and
	// Verifier.VerifyProof when proof transformation fails.
	ErrProofTransformation = errors.New("error in data integrity proof transformation")
)
