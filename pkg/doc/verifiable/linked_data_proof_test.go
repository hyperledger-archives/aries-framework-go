/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_keyResolverAdapter_Resolve(t *testing.T) {
	t.Run("successful public key resolving", func(t *testing.T) {
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		kra := &keyResolverAdapter{pubKeyFetcher: SingleKey([]byte(pubKey))}
		resolvedPubKey, err := kra.Resolve("did1#key1")
		require.NoError(t, err)
		require.Equal(t, []byte(pubKey), resolvedPubKey)
	})

	t.Run("error wrong key format", func(t *testing.T) {
		kra := &keyResolverAdapter{pubKeyFetcher: func(issuerID, keyID string) (interface{}, error) {
			return nil, nil
		}}
		resolvedPubKey, err := kra.Resolve("any")
		require.Error(t, err)
		require.EqualError(t, err, "wrong id [any] to resolve")
		require.Nil(t, resolvedPubKey)
	})

	t.Run("error at public key resolving (e.g. not found)", func(t *testing.T) {
		kra := &keyResolverAdapter{pubKeyFetcher: func(issuerID, keyID string) (interface{}, error) {
			return nil, errors.New("no key found")
		}}
		resolvedPubKey, err := kra.Resolve("any#key1")
		require.Error(t, err)
		require.EqualError(t, err, "no key found")
		require.Nil(t, resolvedPubKey)
	})

	t.Run("returned public key is not []byte", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		kra := &keyResolverAdapter{pubKeyFetcher: SingleKey(privateKey.Public())}
		resolvedPubKey, err := kra.Resolve("any#key1")
		require.Error(t, err)
		require.EqualError(t, err, "expecting []byte public key, got something else")
		require.Nil(t, resolvedPubKey)
	})
}
