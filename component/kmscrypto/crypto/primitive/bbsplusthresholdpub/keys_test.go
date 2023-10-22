/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbsplusthresholdpub_test

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	bbs "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbsplusthresholdpub"
)

func TestGenerateKeyPair(t *testing.T) {
	h := sha256.New

	seed := make([]byte, 32)

	pubKey, privKey, precomputations, err := bbs.GenerateKeyPair(h, seed, threshold, n, k)

	require.NoError(t, err)
	require.NotNil(t, pubKey)
	require.NotNil(t, privKey)
	require.NotNil(t, precomputations)

	lenPrecomputations := len(precomputations)
	require.Equal(t, lenPrecomputations, n)
	for _, precomputation := range precomputations {
		require.NotNil(t, precomputation)
		require.NotNil(t, precomputation.PublicKey)
		require.NotNil(t, precomputation.SkShare)
		require.NotNil(t, precomputation.Presignatures)
		numOfPresigs := len(precomputation.Presignatures)
		require.Equal(t, numOfPresigs, k)
	}

	// use random seed
	pubKey, privKey, precomputations, err = bbs.GenerateKeyPair(h, nil, threshold, n, k)
	require.NoError(t, err)
	require.NotNil(t, pubKey)
	require.NotNil(t, privKey)
	require.NotNil(t, precomputations)

	lenPrecomputations = len(precomputations)
	require.Equal(t, lenPrecomputations, n)
	for _, precomputation := range precomputations {
		require.NotNil(t, precomputation)
		require.NotNil(t, precomputation.Presignatures)
		numOfPresigs := len(precomputation.Presignatures)
		require.Equal(t, numOfPresigs, k)
	}

	// invalid size of seed
	pubKey, privKey, precomputations, err = bbs.GenerateKeyPair(h, make([]byte, 31), threshold, n, k)
	require.Error(t, err)
	require.EqualError(t, err, "invalid size of seed")
	require.Nil(t, pubKey)
	require.Nil(t, privKey)
	require.Nil(t, precomputations)
}

func TestPrivateKey_Marshal(t *testing.T) {
	_, privKey, _, err := generateKeyPairRandom(threshold, n, k)
	require.NoError(t, err)

	privKeyBytes, err := privKey.Marshal()
	require.NoError(t, err)
	require.NotNil(t, privKeyBytes)

	privKeyUnmarshalled, err := bbs.UnmarshalPrivateKey(privKeyBytes)
	require.NoError(t, err)
	require.NotNil(t, privKeyUnmarshalled)
	require.Equal(t, privKey, privKeyUnmarshalled)
}

func TestPrivateKey_PublicKey(t *testing.T) {
	pubKey, privKey, precomputations, err := generateKeyPairRandom(threshold, n, k)
	require.NoError(t, err)

	require.Equal(t, pubKey, privKey.PublicKey())
	for _, precomputation := range precomputations {
		require.Equal(t, pubKey, precomputation.PartyPrivateKey().PublicKey())
	}

}

func TestPublicKey_Marshal(t *testing.T) {
	pubKey, _, _, err := generateKeyPairRandom(threshold, n, k)
	require.NoError(t, err)

	pubKeyBytes, err := pubKey.Marshal()
	require.NoError(t, err)
	require.NotNil(t, pubKeyBytes)

	pubKeyUnmarshalled, err := bbs.UnmarshalPublicKey(pubKeyBytes)
	require.NoError(t, err)
	require.NotNil(t, pubKeyUnmarshalled)
	require.Equal(t, pubKey, pubKeyUnmarshalled)
}

func TestPartyPrivateKey_Marshal(t *testing.T) {

	_, _, precomputations, err := generateKeyPairRandom(threshold, n, k)
	require.NoError(t, err)

	for _, precomputation := range precomputations {
		partyPrivateKeyBytes, err := precomputation.PartyPrivateKey().Marshal()
		require.NoError(t, err)
		require.NotNil(t, partyPrivateKeyBytes)

		partyPrivateKeyUnmarshalled, err := bbs.UnmarshalPartyPrivateKey(partyPrivateKeyBytes)
		require.NoError(t, err)
		require.NotNil(t, partyPrivateKeyUnmarshalled)
		require.Equal(t, precomputation.PartyPrivateKey(), partyPrivateKeyUnmarshalled)
	}
}

func TestPresignature_Marshal(t *testing.T) {

	_, _, precomputations, err := generateKeyPairRandom(threshold, n, k)
	require.NoError(t, err)

	for _, precomputation := range precomputations {
		for _, presignature := range precomputation.Presignatures {
			presigBytes, err := presignature.ToBytes()
			require.NoError(t, err)
			require.NotNil(t, presigBytes)

			presignatureUnmarshalled, err := bbs.ParsePerPartyPresignature(presigBytes)
			require.NoError(t, err)
			require.NotNil(t, presignatureUnmarshalled)

			presigBytes2, err := presignatureUnmarshalled.ToBytes()
			require.NoError(t, err)
			require.NotNil(t, presigBytes2)
			require.Equal(t, presigBytes, presigBytes2)
		}
	}
}

func TestPrecomputation_Marshal(t *testing.T) {

	_, _, precomputations, err := generateKeyPairRandom(threshold, n, k)
	require.NoError(t, err)

	for _, precomputation := range precomputations {
		precomputationBytes, err := precomputation.ToBytes()
		require.NoError(t, err)
		require.NotNil(t, precomputationBytes)

		precomputationUnmarshalled, err := bbs.ParsePerPartyPrecomputations(precomputationBytes)
		require.NoError(t, err)
		require.NotNil(t, precomputationUnmarshalled)

		precomputationBytes2, err := precomputationUnmarshalled.ToBytes()
		require.NoError(t, err)
		require.NotNil(t, precomputationBytes2)
		require.Equal(t, precomputationBytes, precomputationBytes2)
	}
}

func generateKeyPairRandom(t, n, k int) (*bbs.PublicKey, *bbs.PrivateKey, []*bbs.PerPartyPrecomputations, error) {
	seed := make([]byte, 32)

	_, err := rand.Read(seed)
	if err != nil {
		panic(err)
	}

	return bbs.GenerateKeyPair(sha256.New, seed, t, n, k)
}
