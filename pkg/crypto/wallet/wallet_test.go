/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/operator/box"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/wallet"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	serviceEndpoint = "sample-endpoint.com"
)

func TestBaseWallet_New(t *testing.T) {
	t.Run("test error from OpenStore for keystore", func(t *testing.T) {
		const errMsg = "error from OpenStore"
		_, err := wallet.New(newMockWalletProvider(
			&mockstorage.MockStoreProvider{ErrOpenStoreHandle: fmt.Errorf(errMsg)}))
		require.Error(t, err)
		require.Contains(t, err.Error(), errMsg)
	})
	t.Run("test error from OpenStore for did store", func(t *testing.T) {
		_, err := wallet.New(newMockWalletProvider(
			&mockstorage.MockStoreProvider{FailNameSpace: "didstore"}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open store for name space")
	})
}

func newMockWalletProvider(storagePvdr *mockstorage.MockStoreProvider) *mockProvider {
	return &mockProvider{storagePvdr}
}

// mockProvider mocks provider for wallet
type mockProvider struct {
	storage *mockstorage.MockStoreProvider
}

func (m *mockProvider) StorageProvider() storage.Provider {
	return m.storage
}

func (m *mockProvider) InboundTransportEndpoint() string {
	return serviceEndpoint
}

func TestBaseWallet_Wrappers(t *testing.T) {
	bw, err := wallet.New(newMockWalletProvider(&mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
		Store: make(map[string][]byte),
	}}))
	require.NoError(t, err)

	t.Run("CreateEncryptionKey", func(t *testing.T) {
		ret, err := bw.CreateEncryptionKey()
		require.NoError(t, err)
		require.NotNil(t, ret)
	})

	t.Run("CreateSigningKey", func(t *testing.T) {
		ret, err := bw.CreateSigningKey()
		require.NoError(t, err)
		require.NotNil(t, ret)
	})

	t.Run("AttachCryptoOperator", func(t *testing.T) {
		err := bw.AttachCryptoOperator(&box.CryptoBox{})
		require.NoError(t, err)

		err = bw.AttachCryptoOperator(nil)
		require.EqualError(t, err, "cannot attach nil crypto operator")
	})

	t.Run("FindVerKey", func(t *testing.T) {
		ret, err := bw.FindVerKey([]string{"test"})
		require.EqualError(t, err, "key not found")
		require.Equal(t, -1, ret)

		key, err := bw.CreateSigningKey()
		require.NoError(t, err)

		ret, err = bw.FindVerKey([]string{"test1", key, "test2"})
		require.NoError(t, err)
		require.Equal(t, 1, ret) // key is at index 1
	})

	t.Run("SignMessage", func(t *testing.T) {
		_, err := bw.SignMessage([]byte("message"), "key")
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "failed to get key")

		key, err := bw.CreateSigningKey()
		require.NoError(t, err)
		sig, err := bw.SignMessage([]byte("message"), key)
		require.NoError(t, err)
		require.NotNil(t, sig)
	})

	t.Run("DeriveKEK", func(t *testing.T) {
		_, err := bw.DeriveKEK(nil, nil, nil, nil)
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "invalid key")
	})

	t.Run("CreateDID", func(t *testing.T) {
		ret, err := bw.CreateDID("peer")
		require.NoError(t, err)
		require.NotNil(t, ret)
	})

	t.Run("GetDID", func(t *testing.T) {
		did, err := bw.CreateDID("peer")
		require.NoError(t, err)
		require.NotNil(t, did)
		ret, err := bw.GetDID(did.ID)
		require.NoError(t, err)
		require.NotNil(t, ret)
	})

	t.Run("Close", func(t *testing.T) {
		err := bw.Close()
		require.NoError(t, err)
		err = bw.Close()
		require.NoError(t, err)
	})
}
