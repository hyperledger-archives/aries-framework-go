/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package fingerprint

import (
	"strings"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"
)

func TestCreateDIDKey(t *testing.T) {
	pubKeyBase58 := "B12NYF8RrR3h41TDCTJojY59usg3mbtbjnFs7Eud1Y6u"
	expectedDIDKey := "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
	expectedDIDKeyID := "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH" //nolint:lll

	t.Run("test CreateDIDKey", func(t *testing.T) {
		didKey, keyID := CreateDIDKey(base58.Decode(pubKeyBase58))

		require.Equal(t, didKey, expectedDIDKey)
		require.Equal(t, keyID, expectedDIDKeyID)
	})

	t.Run("test PubKeyFromFingerprint success", func(t *testing.T) {
		pubKey, code, err := PubKeyFromFingerprint(strings.Split(expectedDIDKeyID, "#")[1])
		require.Equal(t, uint64(ed25519pub), code)
		require.NoError(t, err)

		require.Equal(t, base58.Encode(pubKey), pubKeyBase58)
	})

	t.Run("test PubKeyFromFingerprint fail", func(t *testing.T) {
		badDIDKeyID := "AB" + strings.Split(expectedDIDKeyID, "#")[1][2:]

		_, _, err := PubKeyFromFingerprint(badDIDKeyID)
		require.EqualError(t, err, "unknown key encoding")
	})

	t.Run("invalid fingerprint", func(t *testing.T) {
		_, _, err := PubKeyFromFingerprint("")
		require.Error(t, err)

		_, _, err = PubKeyFromFingerprint("a6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH")
		require.Error(t, err)
	})
}

func TestDIDKeyEd25519(t *testing.T) {
	const (
		k1       = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
		k1Base58 = "B12NYF8RrR3h41TDCTJojY59usg3mbtbjnFs7Eud1Y6u"
	)

	pubKey, err := PubKeyFromDIDKey(k1)
	require.Equal(t, k1Base58, base58.Encode(pubKey))
	require.NoError(t, err)
}
