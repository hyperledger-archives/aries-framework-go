/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package envelope

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/crypto/jwe/authcrypt"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm"
	mprovider "github.com/hyperledger/aries-framework-go/pkg/internal/mock/provider"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

func TestBaseKMSInPackager_UnpackMessage(t *testing.T) {
	t.Run("test failed to unmarshal encMessage", func(t *testing.T) {
		w, err := kms.New(newMockKMSProvider(&mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
			Store: make(map[string][]byte),
		}}))
		require.NoError(t, err)

		mockedProviders := &mprovider.Provider{
			KMSValue: w,
		}
		crypter, err := authcrypt.New(mockedProviders, authcrypt.XC20P)
		require.NoError(t, err)

		mockedProviders.CrypterValue = crypter
		packager, err := New(mockedProviders)
		require.NoError(t, err)
		_, err = packager.UnpackMessage(nil)
		require.Error(t, err)
		require.EqualError(t, err, "failed from decrypt: failed to decrypt message: unexpected end of JSON input")
	})

	t.Run("test key not found", func(t *testing.T) {
		wp := newMockKMSProvider(&mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
			Store: make(map[string][]byte),
		}})
		w, err := kms.New(wp)
		require.NoError(t, err)

		mockedProviders := &mprovider.Provider{
			KMSValue: w,
		}
		crypter, err := authcrypt.New(mockedProviders, authcrypt.XC20P)
		require.NoError(t, err)

		// use a real crypter with a mocked KMS to validate pack/unpack
		mockedProviders.CrypterValue = crypter
		packager, err := New(mockedProviders)
		require.NoError(t, err)

		// fromKey is stored in the KMS
		_, base58FromVerKey, err := w.CreateKeySet()
		require.NoError(t, err)

		// toVerKey is stored in the KMS as well
		base58ToEncKey, base58ToVerKey, err := w.CreateKeySet()
		require.NoError(t, err)

		// PackMessage should pass with both value from and to verification keys
		packMsg, err := packager.PackMessage(&Envelope{Message: []byte("msg1"),
			FromVerKey: base58FromVerKey,
			ToVerKeys:  []string{base58ToVerKey}})
		require.NoError(t, err)

		// mock KMS without ToVerKey and ToEncKey then try UnpackMessage
		delete(wp.storage.Store.Store, base58ToVerKey)
		delete(wp.storage.Store.Store, base58ToEncKey)
		// It should fail since Recipient keys are not found in the KMS
		_, err = packager.UnpackMessage(packMsg)
		require.Error(t, err)
		require.EqualError(t, err, "failed from decrypt: failed to decrypt message: key not found")
	})

	t.Run("test Pack/Unpack fails", func(t *testing.T) {
		w, err := kms.New(newMockKMSProvider(&mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
			Store: make(map[string][]byte),
		}}))
		require.NoError(t, err)

		decryptValue := func(envelope []byte) ([]byte, error) {
			return nil, fmt.Errorf("decrypt error")
		}

		mockedProviders := &mprovider.Provider{
			KMSValue: w,
		}

		// use a mocked crypter with a mocked KMS to validate pack/unpack
		e := func(payload []byte, senderPubKey []byte, recipientsKeys [][]byte) (bytes []byte, e error) {
			crypter, e := authcrypt.New(mockedProviders, authcrypt.XC20P)
			require.NoError(t, e)
			return crypter.Encrypt(payload, senderPubKey, recipientsKeys)
		}
		mockCrypter := &didcomm.MockAuthCrypt{DecryptValue: decryptValue,
			EncryptValue: e}

		mockedProviders.CrypterValue = mockCrypter

		packager, err := New(mockedProviders)
		require.NoError(t, err)

		_, base58FromVerKey, err := w.CreateKeySet()
		require.NoError(t, err)

		_, base58ToVerKey, err := w.CreateKeySet()
		require.NoError(t, err)

		// try pack with nil envelope - should fail
		packMsg, err := packager.PackMessage(nil)
		require.EqualError(t, err, "envelope argument is nil")
		require.Empty(t, packMsg)

		// now try to pack with non empty envelope - should pass
		packMsg, err = packager.PackMessage(&Envelope{Message: []byte("msg1"),
			FromVerKey: base58FromVerKey,
			ToVerKeys:  []string{base58ToVerKey}})
		require.NoError(t, err)
		require.NotEmpty(t, packMsg)

		// now try unpack - should fail since we mocked the crypter's Decrypt value to return "decrypt error"
		// see 'decryptValue' above
		_, err = packager.UnpackMessage(packMsg)
		require.Error(t, err)
		require.EqualError(t, err, "failed from decrypt: decrypt error")

		// now mock encrypt failure to test PackMessage with non empty envelope
		e = func(payload []byte, senderPubKey []byte, recipientsKeys [][]byte) (bytes []byte, e error) {
			return nil, fmt.Errorf("encrypt error")
		}
		mockCrypter = &didcomm.MockAuthCrypt{EncryptValue: e}
		mockedProviders.CrypterValue = mockCrypter
		packager, err = New(mockedProviders)
		require.NoError(t, err)
		packMsg, err = packager.PackMessage(&Envelope{Message: []byte("msg1"),
			FromVerKey: base58FromVerKey,
			ToVerKeys:  []string{base58ToVerKey}})
		require.Error(t, err)
		require.Empty(t, packMsg)
		require.EqualError(t, err, "failed from encrypt: encrypt error")
	})

	t.Run("test Pack/Unpack success", func(t *testing.T) {
		// create a mock KMS with storage as a map
		w, err := kms.New(newMockKMSProvider(&mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
			Store: map[string][]byte{}}}))
		require.NoError(t, err)
		mockedProviders := &mprovider.Provider{
			KMSValue: w,
		}
		// create a real crypter (no mocking here)
		crypter, err := authcrypt.New(mockedProviders, authcrypt.XC20P)
		require.NoError(t, err)
		mockedProviders.CrypterValue = crypter

		// now create a new packager with the above provider context
		packager, err := New(mockedProviders)
		require.NoError(t, err)

		_, base58FromVerKey, err := w.CreateKeySet()
		require.NoError(t, err)

		_, base58ToVerKey, err := w.CreateKeySet()
		require.NoError(t, err)

		// pack an non empty envelope - should pass
		packMsg, err := packager.PackMessage(&Envelope{Message: []byte("msg1"),
			FromVerKey: base58FromVerKey,
			ToVerKeys:  []string{base58ToVerKey}})
		require.NoError(t, err)

		// unpack the packed message above - should pass and match the same payload (msg1)
		unpackedMsg, err := packager.UnpackMessage(packMsg)
		require.NoError(t, err)
		require.Equal(t, unpackedMsg.Message, []byte("msg1"))
	})
}

func newMockKMSProvider(storagePvdr *mockstorage.MockStoreProvider) *mockProvider {
	return &mockProvider{storagePvdr}
}

// mockProvider mocks provider for KMS
type mockProvider struct {
	storage *mockstorage.MockStoreProvider
}

func (m *mockProvider) StorageProvider() storage.Provider {
	return m.storage
}

func (m *mockProvider) InboundTransportEndpoint() string {
	return "sample-endpoint.com"
}
