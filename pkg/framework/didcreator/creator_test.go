/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didcreator

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didmethod/peer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	api "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/didcreator"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/internal/mock/kms"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	serviceEndpoint    = "sample-endpoint.com"
	serviceTypeDIDComm = "did-communication"
	testMethod         = "peer"
)

func TestDIDCreator(t *testing.T) {
	verifyDID := func(t *testing.T, method string, didDoc *did.Doc) {
		require.NotEmpty(t, didDoc.Context)
		require.Equal(t, didDoc.Context[0], did.Context)
		require.NotEmpty(t, didDoc.Updated)
		require.NotEmpty(t, didDoc.Created)
		require.NotEmpty(t, didDoc.ID)
		require.NotEmpty(t, didDoc.PublicKey)

		for _, pubK := range didDoc.PublicKey {
			require.NotEmpty(t, pubK.ID)
			switch method {
			case peerDIDMethod:
				require.Equal(t, pubK.ID, string(pubK.Value)[0:7])
			default:
				require.Fail(t, "Invalid DID Method")
			}
			require.NotEmpty(t, pubK.Value)
			require.NotEmpty(t, pubK.Type)
			require.NotEmpty(t, pubK.Controller)
		}

		// verify DID identifier
		switch method {
		case peerDIDMethod:
			require.Equal(t, didDoc.ID[0:9], "did:peer:")
		default:
			require.Fail(t, "Invalid DID method")
		}
	}

	t.Run("test default creator options", func(t *testing.T) {
		c, err := New(newMockProvider(), WithDidMethod(&peer.DIDCreator{}))
		require.NoError(t, err)
		didDoc, err := c.Create(testMethod)
		require.NoError(t, err)
		require.NotNil(t, didDoc)

		verifyDID(t, peerDIDMethod, didDoc)

		// verify empty services
		require.Empty(t, didDoc.Service)
	})

	t.Run("test all creator options", func(t *testing.T) {
		c, err := New(newMockProvider(),
			WithDidMethod(&peer.DIDCreator{}),
			WithCreatorKeyType("key-type"),
			WithCreatorServiceEndpoint("service-endpoint"),
			WithCreatorServiceType("service-type"))
		require.NoError(t, err)
		didDoc, err := c.Create(testMethod)
		require.NoError(t, err)
		require.NotNil(t, didDoc)

		verifyDID(t, peerDIDMethod, didDoc)

		// verify not empty services
		require.NotEmpty(t, didDoc.Service)
		require.Equal(t, didDoc.Service[0].Type, "service-type")
		require.Equal(t, didDoc.Service[0].ServiceEndpoint, "service-endpoint")
	})

	t.Run("create Peer DID with service type", func(t *testing.T) {
		c, err := New(newMockProvider(), WithDidMethod(&peer.DIDCreator{}))
		require.NoError(t, err)
		didDoc, err := c.Create(testMethod, api.WithServiceType(serviceTypeDIDComm), api.WithServiceEndpoint(serviceEndpoint))
		require.NoError(t, err)
		require.NotNil(t, didDoc)

		verifyDID(t, peerDIDMethod, didDoc)

		// verify services
		require.NotEmpty(t, didDoc.Service)
		for _, service := range didDoc.Service {
			require.NotEmpty(t, service.ID)
			require.Equal(t, "#agent", service.ID)
			require.NotEmpty(t, service.Type)
			require.Equal(t, serviceTypeDIDComm, service.Type)
			require.NotEmpty(t, service.ServiceEndpoint)
			require.Equal(t, serviceEndpoint, service.ServiceEndpoint)
		}
	})

	t.Run("create/fetch Peer DID with key type", func(t *testing.T) {
		c, err := New(newMockProvider(), WithDidMethod(&peer.DIDCreator{}))
		require.NoError(t, err)
		didDoc, err := c.Create(testMethod, api.WithKeyType("key-type"))
		require.NoError(t, err)
		require.NotNil(t, didDoc)

		verifyDID(t, peerDIDMethod, didDoc)

		// verify empty services since service type not provided
		require.Empty(t, didDoc.Service)
	})

	t.Run("create new DID without service type", func(t *testing.T) {
		c, err := New(newMockProvider(), WithDidMethod(&peer.DIDCreator{}))
		require.NoError(t, err)
		didDoc, err := c.Create(testMethod)
		require.NoError(t, err)
		require.NotNil(t, didDoc)

		verifyDID(t, peerDIDMethod, didDoc)

		// verify services
		require.Empty(t, didDoc.Service)
	})

	t.Run("test error while generating key", func(t *testing.T) {
		mockProvider := newMockProvider()
		mockProvider.crypto = &mockkms.CloseableKMS{CreateKeyErr: errors.New("encryption error")}
		c, err := New(mockProvider, WithDidMethod(&peer.DIDCreator{}))
		require.NoError(t, err)

		didDoc, err := c.Create(testMethod)
		require.Nil(t, didDoc)
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "encryption error")
	})
}

func newMockProvider() *mockProvider {
	crypto := &mockkms.CloseableKMS{}
	crypto.CreateSigningKeyValue = getSigningKey()
	return &mockProvider{storage: mockstorage.NewMockStoreProvider(), crypto: crypto}
}

func getSigningKey() string {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return base58.Encode(pub[:])
}

// mockProvider mocks provider for creator
type mockProvider struct {
	storage *mockstorage.MockStoreProvider
	crypto  *mockkms.CloseableKMS
}

func (m *mockProvider) StorageProvider() storage.Provider {
	return m.storage
}

func (m *mockProvider) KMS() kms.KeyManager {
	return m.crypto
}
