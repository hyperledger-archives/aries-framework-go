/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsKeyPairValid(t *testing.T) {
	require.False(t, IsKeyPairValid(KeyPair{}))
	pubKey := []byte("testpublickey")
	privKey := []byte("testprivatekey")

	require.False(t, IsKeyPairValid(KeyPair{Priv: privKey, Pub: nil}))
	require.False(t, IsKeyPairValid(KeyPair{Priv: nil, Pub: pubKey}))
	require.True(t, IsKeyPairValid(KeyPair{Priv: privKey, Pub: pubKey}))
}
