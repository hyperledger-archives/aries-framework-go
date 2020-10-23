/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub_test

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	bbs "github.com/hyperledger/aries-framework-go/pkg/doc/bbs/bbs12381g2pub"
)

func TestGenerateKeyPair(t *testing.T) {
	h := sha256.New

	seed := make([]byte, 32)

	pubKey, privKey, err := bbs.GenerateKeyPair(h, seed)
	require.NoError(t, err)
	require.NotNil(t, pubKey)
	require.NotNil(t, privKey)

	// use random seed
	pubKey, privKey, err = bbs.GenerateKeyPair(h, nil)
	require.NoError(t, err)
	require.NotNil(t, pubKey)
	require.NotNil(t, privKey)

	// invalid size of seed
	pubKey, privKey, err = bbs.GenerateKeyPair(h, make([]byte, 31))
	require.Error(t, err)
	require.EqualError(t, err, "invalid size of seed")
	require.Nil(t, pubKey)
	require.Nil(t, privKey)
}

func TestPrivateKey_Marshal(t *testing.T) {
	_, privKey, err := generateKeyPairRandom()
	require.NoError(t, err)

	privKeyBytes, err := privKey.Marshal()
	require.NoError(t, err)
	require.NotNil(t, privKeyBytes)

	privKeyUnmarshalled, err := bbs.UnmarshalPrivateKey(privKeyBytes)
	require.NoError(t, err)
	require.NotNil(t, privKeyUnmarshalled)
	require.Equal(t, privKey, privKeyUnmarshalled)

	privKeyUnmarshalled, err = bbs.UnmarshalPrivateKey(getInvalidFrBytes())
	require.Error(t, err)
	require.Nil(t, privKeyUnmarshalled)
	require.EqualError(t, err, "parse private key: invalid FR")
}

func TestPrivateKey_PublicKey(t *testing.T) {
	pubKey, privKey, err := generateKeyPairRandom()
	require.NoError(t, err)

	require.Equal(t, pubKey, privKey.PublicKey())
}

func TestPublicKey_Marshal(t *testing.T) {
	pubKey, _, err := generateKeyPairRandom()
	require.NoError(t, err)

	pubKeyBytes, err := pubKey.Marshal()
	require.NoError(t, err)
	require.NotNil(t, pubKeyBytes)

	pubKeyUnmarshalled, err := bbs.UnmarshalPublicKey(pubKeyBytes)
	require.NoError(t, err)
	require.NotNil(t, pubKeyUnmarshalled)
	require.Equal(t, pubKey, pubKeyUnmarshalled)
}

func generateKeyPairRandom() (*bbs.PublicKey, *bbs.PrivateKey, error) {
	seed := make([]byte, 32)

	_, err := rand.Read(seed)
	if err != nil {
		panic(err)
	}

	return bbs.GenerateKeyPair(sha256.New, seed)
}
