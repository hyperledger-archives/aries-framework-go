/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"

	api "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
)

const (
	keyType = "key-type"
)

func TestDIDCreator(t *testing.T) {
	t.Run("test create without service type", func(t *testing.T) {
		c, err := New(&storage.MockStoreProvider{})
		require.NoError(t, err)
		require.NotNil(t, c)

		didDoc, err := c.Build(getSigningKey())
		require.NoError(t, err)
		require.NotNil(t, didDoc)

		// verify empty services
		require.Empty(t, didDoc.Service)
	})

	t.Run("test request overrides", func(t *testing.T) {
		c, err := New(&storage.MockStoreProvider{})
		require.NoError(t, err)
		require.NotNil(t, c)

		routingKeys := []string{"abc", "xyz"}
		didDoc, err := c.Build(
			getSigningKey(),
			api.WithServiceEndpoint("request-endpoint"),
			api.WithServiceType("request-type"),
			api.WithRoutingKeys(routingKeys),
		)
		require.NoError(t, err)
		require.NotNil(t, didDoc)

		// verify service not empty, type and endpoint from request options
		require.NotEmpty(t, didDoc.Service)
		require.Equal(t, "request-type", didDoc.Service[0].Type)
		require.Equal(t, "request-endpoint", didDoc.Service[0].ServiceEndpoint)
		require.Equal(t, routingKeys, didDoc.Service[0].RoutingKeys)
	})

	t.Run("test accept", func(t *testing.T) {
		c, err := New(&storage.MockStoreProvider{})
		require.NoError(t, err)
		require.NotNil(t, c)

		accepted := c.Accept("invalid")
		require.False(t, accepted)

		accepted = c.Accept("peer")
		require.True(t, accepted)
	})
}

func getSigningKey() *api.PubKey {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	return &api.PubKey{Value: base58.Encode(pub[:]), Type: keyType}
}
