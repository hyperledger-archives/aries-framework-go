/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_parseEmbeddedProof(t *testing.T) {
	t.Run("parse linked data proof with \"Ed25519Signature2018\" proof type", func(t *testing.T) {
		proofType, err := parseEmbeddedProof(map[string]interface{}{
			"type": "Ed25519Signature2018",
		})
		require.NoError(t, err)
		require.Equal(t, linkedDataProof, proofType)
	})

	t.Run("parse embedded proof without \"type\" element", func(t *testing.T) {
		_, err := parseEmbeddedProof(map[string]interface{}{})
		require.Error(t, err)
		require.EqualError(t, err, "proof type is missing")
	})

	t.Run("parse embedded proof with unsupported type", func(t *testing.T) {
		_, err := parseEmbeddedProof(map[string]interface{}{
			"type": "SomethingUnsupported",
		})
		require.Error(t, err)
		require.EqualError(t, err, "unsupported proof type: SomethingUnsupported")
	})
}

func Test_checkEmbeddedProof(t *testing.T) {
	r := require.New(t)
	nonJSONBytes := []byte("not JSON")
	defaultVCOpts := &credentialOpts{}

	t.Run("Does not check the embedded proof if credentialOpts.disabledProofCheck", func(t *testing.T) {
		docBytes, err := checkEmbeddedProof(nonJSONBytes, &credentialOpts{disabledProofCheck: true})
		r.NoError(err)
		r.NotNil(docBytes)
	})

	t.Run("error on checking non-JSON embedded proof", func(t *testing.T) {
		docBytes, err := checkEmbeddedProof(nonJSONBytes, defaultVCOpts)
		r.Error(err)
		r.Contains(err.Error(), "embedded proof is not JSON")
		r.Nil(docBytes)
	})

	t.Run("check embedded proof without \"proof\" element", func(t *testing.T) {
		docWithoutProof := `{
  "@context": "https://www.w3.org/2018/credentials/v1"
}`
		docBytes, err := checkEmbeddedProof([]byte(docWithoutProof), defaultVCOpts)
		r.NoError(err)
		r.NotNil(docBytes)
	})

	t.Run("error on not map \"proof\" element", func(t *testing.T) {
		docWithNotMapProof := `{
  "@context": "https://www.w3.org/2018/credentials/v1",
  "proof": "some string proof"
}`
		docBytes, err := checkEmbeddedProof([]byte(docWithNotMapProof), defaultVCOpts)
		r.Error(err)
		r.EqualError(err, "check embedded proof: expecting [string]interface{}")
		r.Nil(docBytes)
	})

	t.Run("error on not supported type of embedded proof", func(t *testing.T) {
		docWithNotSupportedProof := `{
  "@context": "https://www.w3.org/2018/credentials/v1",
  "proof": {
	"type": "SomethingUnsupported"
  }
}`
		docBytes, err := checkEmbeddedProof([]byte(docWithNotSupportedProof), defaultVCOpts)
		r.Error(err)
		r.EqualError(err, "unsupported proof type: SomethingUnsupported")
		r.Nil(docBytes)
	})

	t.Run("error on invalid proof of Linked Data embedded proof", func(t *testing.T) {
		docWithNotSupportedProof := `{
  "@context": "https://www.w3.org/2018/credentials/v1",
  "proof": {
	"type": "Ed25519Signature2018",
    "created": "2020-01-21T12:59:31+02:00",
    "creator": "John",
    "proofValue": "invalid value"
  }
}`
		docBytes, err := checkEmbeddedProof([]byte(docWithNotSupportedProof), defaultVCOpts)
		r.Error(err)
		r.Contains(err.Error(), "check embedded proof")
		r.Nil(docBytes)
	})
}
