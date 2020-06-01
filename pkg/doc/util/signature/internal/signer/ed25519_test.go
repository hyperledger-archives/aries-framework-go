/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewEd25519Signer(t *testing.T) {
	signer, err := NewEd25519Signer()
	require.NoError(t, err)
	require.NotNil(t, signer)
	require.NotNil(t, signer.privateKey)
	require.NotNil(t, signer.PubKey)
}

func TestGetEd25519Signer(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	signer := GetEd25519Signer(privKey, pubKey)
	require.NotNil(t, signer)
	require.Equal(t, pubKey, signer.PubKey)
	require.Equal(t, privKey, signer.privateKey)
}

func TestEd25519Signer_Sign(t *testing.T) {
	signer, err := NewEd25519Signer()
	require.NoError(t, err)

	signature, err := signer.Sign([]byte("test message"))
	require.NoError(t, err)
	require.NotEmpty(t, signature)

	signer = GetEd25519Signer([]byte("invalid private key"), signer.PubKey)
	signature, err = signer.Sign([]byte("test message"))
	require.Error(t, err)
	require.EqualError(t, err, "ed25519: bad private key length")
	require.Nil(t, signature)
}
