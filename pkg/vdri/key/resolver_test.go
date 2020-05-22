/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package key

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRead(t *testing.T) {
	t.Run("validate did:key", func(t *testing.T) {
		v := New()

		doc, err := v.Read("invalid")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid did: invalid")
		require.Nil(t, doc)
	})

	t.Run("validate did:key method specific ID", func(t *testing.T) {
		v := New()

		doc, err := v.Read("did:key:invalid")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid did:key method ID: invalid")
		require.Nil(t, doc)
	})

	t.Run("validate not supported public key", func(t *testing.T) {
		v := New()

		doc, err := v.Read("did:key:z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc")
		require.Error(t, err)
		require.Contains(t, err.Error(), "not supported public key (multicodec code: 0xec)") // Curve25519 public key
		require.Nil(t, doc)
	})

	t.Run("resolve assuming default key type", func(t *testing.T) {
		v := New()

		doc, err := v.Read(didKey)
		require.NoError(t, err)
		require.NotNil(t, doc)
		require.True(t, doc.KeyAgreement[0].Embedded)

		assertDoc(t, doc)
	})
}
