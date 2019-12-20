// +build testsuite

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0

This is not actually a test but rather a stand-alone generator application
that is used by VC Test Suite (https://github.com/w3c/vc-test-suite).
To run VC Test Suite, execute `make vc-test-suite`.
*/

package verifiable

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestWithNoProofCheck(t *testing.T) {
	credentialOpt := WithNoProofCheck()
	require.NotNil(t, credentialOpt)

	opts := &credentialOpts{}
	credentialOpt(opts)
	require.True(t, opts.disabledProofCheck)
}

func TestWithPresSkippedEmbeddedProofCheck(t *testing.T) {
	vpOpt := WithPresNoProofCheck()
	require.NotNil(t, vpOpt)

	opts := &presentationOpts{}
	vpOpt(opts)
	require.True(t, opts.disabledProofCheck)
}
