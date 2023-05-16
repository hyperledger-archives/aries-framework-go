// +build testsuite

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0

This is not actually a test but rather a stand-alone generator application
that is used by VC Test Suite (https://github.com/w3c/vc-test-suite).
To run VC Test Suite, execute `make vc-test-suite`.
*/

package verifiable

// WithNoProofCheck disables checking of Verifiable Credential's proofs.
func WithNoProofCheck() CredentialOpt {
	return func(opts *credentialOpts) {
		opts.disabledProofCheck = true
	}
}

// WithPresNoProofCheck tells to skip checking of Verifiable Presentation's proofs.
func WithPresNoProofCheck() PresentationOpt {
	return func(opts *presentationOpts) {
		opts.disabledProofCheck = true
	}
}

// WithPresRequireVC option enables check for at least one verifiableCredential in the VP.
func WithPresRequireVC() PresentationOpt {
	return func(opts *presentationOpts) {
		opts.requireVC = true
	}
}

// WithPresRequireProof option enables check for at least one proof in the VP.
func WithPresRequireProof() PresentationOpt {
	return func(opts *presentationOpts) {
		opts.requireProof = true
	}
}
