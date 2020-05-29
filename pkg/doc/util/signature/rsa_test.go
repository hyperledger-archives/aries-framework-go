/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signature

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewRS256Signer(t *testing.T) {
	signer, err := NewRS256Signer()

	require.NoError(t, err)
	require.NotNil(t, signer)
	require.NotNil(t, signer.privateKey)
	require.NotNil(t, signer.PublicKey)
}

func TestGetRS256Signer(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := GetRS256Signer(privKey)
	require.NotNil(t, signer)
	require.Equal(t, privKey, signer.privateKey)
	require.Equal(t, &privKey.PublicKey, signer.PublicKey)
}

func TestRS256Signer_Sign(t *testing.T) {
	signer, err := NewRS256Signer()
	require.NoError(t, err)

	signature, err := signer.Sign([]byte("test message"))
	require.NoError(t, err)
	require.NotEmpty(t, signature)
}

func TestNewPS256Signer(t *testing.T) {
	signer, err := NewPS256Signer()

	require.NoError(t, err)
	require.NotNil(t, signer)
	require.NotNil(t, signer.privateKey)
	require.NotNil(t, signer.PublicKey)
}

func TestGetPS256Signer(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := GetPS256Signer(privKey)
	require.NotNil(t, signer)
	require.Equal(t, privKey, signer.privateKey)
	require.Equal(t, &privKey.PublicKey, signer.PublicKey)
}

func TestPS256Signer_Sign(t *testing.T) {
	signer, err := NewPS256Signer()
	require.NoError(t, err)

	signature, err := signer.Sign([]byte("test message"))
	require.NoError(t, err)
	require.NotEmpty(t, signature)
}
