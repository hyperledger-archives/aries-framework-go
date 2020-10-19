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
		pubKey, err := PubKeyFromFingerprint(strings.Split(expectedDIDKeyID, "#")[1])
		require.NoError(t, err)

		require.Equal(t, base58.Encode(pubKey), pubKeyBase58)
	})

	t.Run("test PubKeyFromFingerprint fail", func(t *testing.T) {
		badDIDKeyID := "AB" + strings.Split(expectedDIDKeyID, "#")[1][2:]

		_, err := PubKeyFromFingerprint(badDIDKeyID)
		require.EqualError(t, err, "pubKeyFromFingerprint: not supported public key (multicodec code: 0x1)")
	})
}
