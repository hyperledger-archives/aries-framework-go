/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package envelope_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/envelope"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer/jwe/authcrypt"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm"
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

		mockedProviders := &mockProvider{nil, w, nil}
		testPacker, err := authcrypt.New(mockedProviders, authcrypt.XC20P)
		require.NoError(t, err)

		mockedProviders.packer = testPacker
		packager, err := envelope.New(mockedProviders)
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

		mockedProviders := &mockProvider{nil, w, nil}
		testPacker, err := authcrypt.New(mockedProviders, authcrypt.XC20P)
		require.NoError(t, err)

		// use a real testPacker with a mocked KMS to validate pack/unpack
		mockedProviders.packer = testPacker
		packager, err := envelope.New(mockedProviders)
		require.NoError(t, err)

		// fromKey is stored in the KMS
		_, base58FromVerKey, err := w.CreateKeySet()
		require.NoError(t, err)

		// toVerKey is stored in the KMS as well
		base58ToEncKey, base58ToVerKey, err := w.CreateKeySet()
		require.NoError(t, err)

		// PackMessage should pass with both value from and to verification keys
		packMsg, err := packager.PackMessage(&envelope.Envelope{Message: []byte("msg1"),
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

		mockedProviders := &mockProvider{nil, w, nil}

		// use a mocked packer with a mocked KMS to validate pack/unpack
		e := func(payload []byte, senderPubKey []byte, recipientsKeys [][]byte) (bytes []byte, e error) {
			crypter, e := authcrypt.New(mockedProviders, authcrypt.XC20P)
			require.NoError(t, e)
			return crypter.Pack(payload, senderPubKey, recipientsKeys)
		}
		mockPacker := &didcomm.MockAuthCrypt{DecryptValue: decryptValue,
			EncryptValue: e}

		mockedProviders.packer = mockPacker

		packager, err := envelope.New(mockedProviders)
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
		packMsg, err = packager.PackMessage(&envelope.Envelope{Message: []byte("msg1"),
			FromVerKey: base58FromVerKey,
			ToVerKeys:  []string{base58ToVerKey}})
		require.NoError(t, err)
		require.NotEmpty(t, packMsg)

		// now try unpack - should fail since we mocked the packer's Unpack value to return "decrypt error"
		// see 'decryptValue' above
		_, err = packager.UnpackMessage(packMsg)
		require.Error(t, err)
		require.EqualError(t, err, "failed from decrypt: decrypt error")

		// now mock encrypt failure to test PackMessage with non empty envelope
		e = func(payload []byte, senderPubKey []byte, recipientsKeys [][]byte) (bytes []byte, e error) {
			return nil, fmt.Errorf("encrypt error")
		}
		mockPacker = &didcomm.MockAuthCrypt{EncryptValue: e}
		mockedProviders.packer = mockPacker
		packager, err = envelope.New(mockedProviders)
		require.NoError(t, err)
		packMsg, err = packager.PackMessage(&envelope.Envelope{Message: []byte("msg1"),
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
		mockedProviders := &mockProvider{nil, w, nil}

		// create a real testPacker (no mocking here)
		testPacker, err := authcrypt.New(mockedProviders, authcrypt.XC20P)
		require.NoError(t, err)
		mockedProviders.packer = testPacker

		// now create a new packager with the above provider context
		packager, err := envelope.New(mockedProviders)
		require.NoError(t, err)

		_, base58FromVerKey, err := w.CreateKeySet()
		require.NoError(t, err)

		_, base58ToVerKey, err := w.CreateKeySet()
		require.NoError(t, err)

		// pack an non empty envelope - should pass
		packMsg, err := packager.PackMessage(&envelope.Envelope{Message: []byte("msg1"),
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
	return &mockProvider{storagePvdr, nil, nil}
}

// mockProvider mocks provider for KMS
type mockProvider struct {
	storage *mockstorage.MockStoreProvider
	kms     kms.KeyManager
	packer  envelope.Packer
}

func (m *mockProvider) Packer() envelope.Packer {
	return m.packer
}

func (m *mockProvider) KMS() kms.KeyManager {
	return m.kms
}

func (m *mockProvider) StorageProvider() storage.Provider {
	return m.storage
}

func (m *mockProvider) InboundTransportEndpoint() string {
	return "sample-endpoint.com"
}
