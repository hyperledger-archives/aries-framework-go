/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tinkcrypto

import (
	"testing"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"github.com/stretchr/testify/require"
)

func Test_ExtractPrivKey(t *testing.T) {
	_, err := extractPrivKey(nil)
	require.EqualError(t, err, "extractPrivKey: kh is nil")

	badKey, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	require.NoError(t, err)

	_, err = extractPrivKey(badKey)
	require.EqualError(t, err, "extractPrivKey: can't extract unsupported private key")

	_, err = extractPrivKey(&keyset.Handle{})
	require.EqualError(t, err, "extractPrivKey: retrieving private key failed: keyset.Handle: invalid keyset")
}

func TestNoopAEAD_Decrypt(t *testing.T) {
	n := noopAEAD{}

	plainText, err := n.Decrypt([]byte("test"), nil)
	require.NoError(t, err)
	require.EqualValues(t, "test", plainText)
}

func TestPrivKeyWriter_Write(t *testing.T) {
	p := privKeyWriter{}

	err := p.Write(nil)
	require.EqualError(t, err, "privKeyWriter: write function not supported")
}
