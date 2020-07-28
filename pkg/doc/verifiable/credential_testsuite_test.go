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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// nolint:lll
const validEmptyPresentation = `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1",
    "https://trustbloc.github.io/context/vc/examples-v1.jsonld"
  ],
  "id": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
  "type": "VerifiablePresentation",
  "holder": "did:example:ebfeb1f712ebc6f1c276e12ec21"
}
`

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

func TestWithPresRequireVC(t *testing.T) {
	vpOpt := WithPresRequireVC()
	require.NotNil(t, vpOpt)

	opts := &presentationOpts{}
	vpOpt(opts)
	require.True(t, opts.requireVC)
}

func TestWithPresRequireProof(t *testing.T) {
	vpOpt := WithPresRequireProof()
	require.NotNil(t, vpOpt)

	opts := &presentationOpts{}
	vpOpt(opts)
	require.True(t, opts.requireProof)

	raw := &rawPresentation{}
	require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
	raw.Proof = nil
	bytes, err := json.Marshal(raw)
	require.NoError(t, err)
	vp, err := newTestPresentation(bytes, WithPresRequireProof())
	require.Error(t, err)
	require.Contains(t, err.Error(), "embedded proof is missing")
	require.Nil(t, vp)
}

func TestNewPresentationWithEmptyFields(t *testing.T) {
	t.Run("creates a new Verifiable Presentation from JSON with valid empty VC structure", func(t *testing.T) {
		vp, err := newTestPresentation([]byte(validEmptyPresentation))
		require.NoError(t, err)
		require.NotNil(t, vp)
	})

	t.Run("creates a new Verifiable Presentation from JSON with invalid empty VC structure", func(t *testing.T) {
		vp, err := newTestPresentation([]byte(validEmptyPresentation), WithPresRequireVC())
		require.Error(t, err)
		require.Contains(t, err.Error(), "verifiableCredential is required")
		require.Nil(t, vp)
	})

	t.Run("creates a new Verifiable Presentation from JSON with invalid empty proof structure", func(t *testing.T) {
		vp, err := newTestPresentation([]byte(validEmptyPresentation), WithPresRequireProof())
		require.Error(t, err)
		require.Contains(t, err.Error(), "embedded proof is missing")
		require.Nil(t, vp)
	})
}
