/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dataintegrity

import (
	"errors"

	"github.com/hyperledger/aries-framework-go/component/models/did"
	spivdr "github.com/hyperledger/aries-framework-go/spi/vdr"
)

var (
	// ErrUnsupportedSuite is returned when a Signer or Verifier is required to use
	// a cryptographic suite for which it doesn't have a suite.Signer or
	// suite.Verifier (respectively) initialized.
	ErrUnsupportedSuite = errors.New("data integrity proof requires unsupported cryptographic suite")
	// ErrNoResolver is returned when a Signer or Verifier needs to resolve a
	// verification method but has no DID resolver.
	ErrNoResolver = errors.New("either did resolver or both verification method and verification relationship must be provided") //nolint:lll
	// ErrVMResolution is returned when a Signer or Verifier needs to resolve a
	// verification method but this fails.
	ErrVMResolution = errors.New("failed to resolve verification method")
)

type didResolver interface {
	Resolve(did string, opts ...spivdr.DIDMethodOption) (*did.DocResolution, error)
}

// Options contains initialization parameters for Data Integrity Signer and Verifier.
type Options struct {
	DIDResolver didResolver
}
