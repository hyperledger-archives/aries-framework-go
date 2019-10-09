/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cryptoutil

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
	chacha "golang.org/x/crypto/chacha20poly1305"
)

func TestIsKeyPairValid(t *testing.T) {
	require.False(t, IsKeyPairValid(KeyPair{}))
	pubKey := []byte("testpublickey")
	privKey := []byte("testprivatekey")
	validChachaKey, err := base64.RawURLEncoding.DecodeString("c8CSJr_27PN9xWCpzXNmepRndD6neQcnO9DS0YWjhNs")
	require.NoError(t, err)

	require.False(t, IsKeyPairValid(KeyPair{Priv: privKey, Pub: nil}))
	require.False(t, IsKeyPairValid(KeyPair{Priv: nil, Pub: pubKey}))
	require.True(t, IsKeyPairValid(KeyPair{Priv: privKey, Pub: pubKey}))

	require.EqualError(t,
		VerifyKeys(
			KeyPair{Priv: privKey, Pub: pubKey},
			[][]byte{[]byte("abc"), []byte("def")}),
		ErrInvalidKey.Error())
	require.EqualError(t,
		VerifyKeys(
			KeyPair{Priv: privKey, Pub: pubKey},
			[][]byte{}),
		errEmptyRecipients.Error())
	require.EqualError(t, VerifyKeys(KeyPair{}, [][]byte{[]byte("abc"), []byte("def")}), errInvalidKeypair.Error())
	require.NoError(t, VerifyKeys(KeyPair{Priv: validChachaKey, Pub: validChachaKey}, [][]byte{validChachaKey}))
}

func TestDeriveKEK_Util(t *testing.T) {
	kek, err := Derive25519KEK(nil, nil, nil, nil)
	require.EqualError(t, err, ErrInvalidKey.Error())
	require.Empty(t, kek)
	validChachaKey, err := base64.RawURLEncoding.DecodeString("c8CSJr_27PN9xWCpzXNmepRndD6neQcnO9DS0YWjhNs")
	require.NoError(t, err)
	chachaKey := new([chacha.KeySize]byte)
	copy(chachaKey[:], validChachaKey)
	kek, err = Derive25519KEK(nil, nil, chachaKey, nil)
	require.EqualError(t, err, ErrInvalidKey.Error())
	require.Empty(t, kek)
	validChachaKey2, err := base64.RawURLEncoding.DecodeString("AAjrHjiFLw6kf6CZ5zqH1ooG3y2aQhuqxmUvqJnIvDI")
	require.NoError(t, err)
	chachaKey2 := new([chacha.KeySize]byte)
	copy(chachaKey2[:], validChachaKey2)
	kek, err = Derive25519KEK(nil, nil, chachaKey, chachaKey2)
	require.NoError(t, err)
	require.NotEmpty(t, kek)
}
