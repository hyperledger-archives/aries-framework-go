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

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/mock/storage"
)

const (
	keyType = ed25519VerificationKey2018
)

func TestDIDCreator(t *testing.T) {
	t.Run("test create without service type", func(t *testing.T) {
		c, err := New(storage.NewMockStoreProvider())
		require.NoError(t, err)
		require.NotNil(t, c)

		docResolution, err := c.Create(nil,
			&did.Doc{VerificationMethod: []did.VerificationMethod{getSigningKey()}})
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		// verify empty services
		require.Empty(t, docResolution.DIDDocument.Service)
	})

	t.Run("test request overrides", func(t *testing.T) {
		c, err := New(storage.NewMockStoreProvider())
		require.NoError(t, err)
		require.NotNil(t, c)

		routingKeys := []string{"abc", "xyz"}
		docResolution, err := c.Create(nil,
			&did.Doc{VerificationMethod: []did.VerificationMethod{getSigningKey()}, Service: []did.Service{{
				ServiceEndpoint: "request-endpoint",
				Type:            "request-type",
				RoutingKeys:     routingKeys,
			}}})

		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		// verify service not empty, type and endpoint from request options
		require.NotEmpty(t, docResolution.DIDDocument.Service)
		require.Equal(t, "request-type", docResolution.DIDDocument.Service[0].Type)
		require.Equal(t, "request-endpoint", docResolution.DIDDocument.Service[0].ServiceEndpoint)
		require.Equal(t, routingKeys, docResolution.DIDDocument.Service[0].RoutingKeys)
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

func TestBuild(t *testing.T) {
	t.Run("inlined recipient keys for didcomm", func(t *testing.T) {
		expected := getSigningKey()
		c, err := New(storage.NewMockStoreProvider())
		require.NoError(t, err)

		result, err := c.Create(nil,
			&did.Doc{VerificationMethod: []did.VerificationMethod{expected}, Service: []did.Service{{
				Type: "did-communication",
			}}})

		require.NoError(t, err)
		require.NotEmpty(t, result.DIDDocument.Service)
		require.NotEmpty(t, result.DIDDocument.Service[0].RecipientKeys)
		require.Equal(t, base58.Encode(expected.Value),
			result.DIDDocument.Service[0].RecipientKeys[0])
	})
}

func getSigningKey() did.VerificationMethod {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	return did.VerificationMethod{Value: pub[:], Type: keyType}
}
