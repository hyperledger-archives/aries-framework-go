/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/nacl/box"
)

func TestIsKeyPairValid(t *testing.T) {
	require.False(t, IsKeyPairValid(KeyPair{}))
	pubKey, privKey, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)
	require.False(t, IsKeyPairValid(KeyPair{Priv: privKey, Pub: nil}))
	require.False(t, IsKeyPairValid(KeyPair{Priv: nil, Pub: pubKey}))
	require.True(t, IsKeyPairValid(KeyPair{Priv: privKey, Pub: pubKey}))
}
