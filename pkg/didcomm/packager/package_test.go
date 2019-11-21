/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package packager_test

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/transport"
	. "github.com/hyperledger/aries-framework-go/pkg/didcomm/packager"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer"
	jwe "github.com/hyperledger/aries-framework-go/pkg/didcomm/packer/jwe/authcrypt"
	legacy "github.com/hyperledger/aries-framework-go/pkg/didcomm/packer/legacy/authcrypt"
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

		mockedProviders := &mockProvider{
			storage:       nil,
			kms:           w,
			primaryPacker: nil,
			packers:       nil,
		}
		testPacker, err := jwe.New(mockedProviders, jwe.XC20P)
		require.NoError(t, err)

		mockedProviders.primaryPacker = testPacker
		packager, err := New(mockedProviders)
		require.NoError(t, err)
		_, err = packager.UnpackMessage(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unexpected end of JSON input")
	})

	t.Run("test bad encoding type", func(t *testing.T) {
		w, err := kms.New(newMockKMSProvider(&mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
			Store: make(map[string][]byte),
		}}))
		require.NoError(t, err)

		mockedProviders := &mockProvider{
			storage:       nil,
			kms:           w,
			primaryPacker: nil,
			packers:       nil,
		}
		testPacker, err := jwe.New(mockedProviders, jwe.XC20P)
		require.NoError(t, err)

		mockedProviders.primaryPacker = testPacker
		packager, err := New(mockedProviders)
		require.NoError(t, err)

		msg := []byte(`{"protected":"` + base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"badtype"}`)) + `"}`)

		_, err = packager.UnpackMessage(msg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "message Type not recognized")

		msg = []byte(`{"protected":"` + "## NOT B64 ##" + `"}`)

		_, err = packager.UnpackMessage(msg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "illegal base64 data")

		msg = []byte(`{"protected":"` + base64.RawURLEncoding.EncodeToString([]byte(`## NOT JSON ##`)) + `"}`)

		_, err = packager.UnpackMessage(msg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid character")
	})

	t.Run("test key not found", func(t *testing.T) {
		wp := newMockKMSProvider(&mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
			Store: make(map[string][]byte),
		}})
		w, err := kms.New(wp)
		require.NoError(t, err)

		mockedProviders := &mockProvider{
			storage:       nil,
			kms:           w,
			primaryPacker: nil,
			packers:       nil,
		}
		testPacker, err := jwe.New(mockedProviders, jwe.XC20P)
		require.NoError(t, err)

		// use a real testPacker with a mocked KMS to validate pack/unpack
		mockedProviders.primaryPacker = testPacker
		packager, err := New(mockedProviders)
		require.NoError(t, err)

		// fromKey is stored in the KMS
		_, base58FromVerKey, err := w.CreateKeySet()
		require.NoError(t, err)

		// toVerKey is stored in the KMS as well
		_, base58ToVerKey, err := w.CreateKeySet()
		require.NoError(t, err)

		toVerKey := base58.Decode(base58ToVerKey)

		// PackMessage should pass with both value from and to verification keys
		packMsg, err := packager.PackMessage(&transport.Envelope{Message: []byte("msg1"),
			FromVerKey: base58FromVerKey,
			ToVerKeys:  []string{base58ToVerKey}})
		require.NoError(t, err)

		// mock KMS without ToVerKey and ToEncKey then try UnpackMessage
		delete(wp.storage.Store.Store, kms.MockKeyID(toVerKey, true, true))
		delete(wp.storage.Store.Store, kms.MockKeyID(toVerKey, true, false))
		// It should fail since Recipient keys are not found in the KMS
		_, err = packager.UnpackMessage(packMsg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "key not found")
	})

	t.Run("test Pack/Unpack fails", func(t *testing.T) {
		w, err := kms.New(newMockKMSProvider(&mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
			Store: make(map[string][]byte),
		}}))
		require.NoError(t, err)

		decryptValue := func(envelope []byte) ([]byte, error) {
			return nil, fmt.Errorf("unpack error")
		}

		mockedProviders := &mockProvider{
			storage:       nil,
			kms:           w,
			primaryPacker: nil,
			packers:       nil,
		}

		// use a mocked packager with a mocked KMS to validate pack/unpack
		e := func(payload []byte, senderPubKey []byte, recipientsKeys [][]byte) (bytes []byte, e error) {
			packer, e := jwe.New(mockedProviders, jwe.XC20P)
			require.NoError(t, e)
			return packer.Pack(payload, senderPubKey, recipientsKeys)
		}
		mockPacker := &didcomm.MockAuthCrypt{DecryptValue: decryptValue,
			EncryptValue: e, Type: "prs.hyperledger.aries-auth-message"}

		mockedProviders.primaryPacker = mockPacker

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
		packMsg, err = packager.PackMessage(&transport.Envelope{Message: []byte("msg1"),
			FromVerKey: base58FromVerKey,
			ToVerKeys:  []string{base58ToVerKey}})
		require.NoError(t, err)
		require.NotEmpty(t, packMsg)

		// now try unpack - should fail since we mocked the packager's Unpack value to return "decrypt error"
		// see 'decryptValue' above
		_, err = packager.UnpackMessage(packMsg)
		require.Error(t, err)
		require.EqualError(t, err, "unpack: unpack error")

		// now mock pack failure to test PackMessage with non empty envelope
		e = func(payload []byte, senderPubKey []byte, recipientsKeys [][]byte) (bytes []byte, e error) {
			return nil, fmt.Errorf("pack error")
		}
		mockPacker = &didcomm.MockAuthCrypt{EncryptValue: e}
		mockedProviders.primaryPacker = mockPacker
		packager, err = New(mockedProviders)
		require.NoError(t, err)
		packMsg, err = packager.PackMessage(&transport.Envelope{Message: []byte("msg1"),
			FromVerKey: base58FromVerKey,
			ToVerKeys:  []string{base58ToVerKey}})
		require.Error(t, err)
		require.Empty(t, packMsg)
		require.EqualError(t, err, "pack: pack error")
	})

	t.Run("test Pack/Unpack success", func(t *testing.T) {
		// create a mock KMS with storage as a map
		w, err := kms.New(newMockKMSProvider(&mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
			Store: map[string][]byte{}}}))
		require.NoError(t, err)
		mockedProviders := &mockProvider{
			storage:       nil,
			kms:           w,
			primaryPacker: nil,
			packers:       nil,
		}

		// create a real testPacker (no mocking here)
		testPacker, err := jwe.New(mockedProviders, jwe.XC20P)
		require.NoError(t, err)
		mockedProviders.primaryPacker = testPacker

		legacyPacker := legacy.New(mockedProviders)
		mockedProviders.packers = []packer.Packer{testPacker, legacyPacker}

		// now create a new packager with the above provider context
		packager, err := New(mockedProviders)
		require.NoError(t, err)

		_, base58FromVerKey, err := w.CreateKeySet()
		require.NoError(t, err)

		_, base58ToVerKey, err := w.CreateKeySet()
		require.NoError(t, err)

		// pack an non empty envelope - should pass
		packMsg, err := packager.PackMessage(&transport.Envelope{Message: []byte("msg1"),
			FromVerKey: base58FromVerKey,
			ToVerKeys:  []string{base58ToVerKey}})
		require.NoError(t, err)

		// unpack the packed message above - should pass and match the same payload (msg1)
		unpackedMsg, err := packager.UnpackMessage(packMsg)
		require.NoError(t, err)
		require.Equal(t, unpackedMsg.Message, []byte("msg1"))

		// pack with legacy, unpack using a packager that has JWE as default but supports legacy

		mockedProviders.primaryPacker = legacyPacker

		packager2, err := New(mockedProviders)
		require.NoError(t, err)

		packMsg, err = packager2.PackMessage(&transport.Envelope{Message: []byte("msg2"),
			FromVerKey: base58FromVerKey,
			ToVerKeys:  []string{base58ToVerKey}})
		require.NoError(t, err)

		// unpack the packed message above - should pass and match the same payload (msg2)
		unpackedMsg, err = packager.UnpackMessage(packMsg)
		require.NoError(t, err)
		require.Equal(t, unpackedMsg.Message, []byte("msg2"))
	})
}

func newMockKMSProvider(storagePvdr *mockstorage.MockStoreProvider) *mockProvider {
	return &mockProvider{storagePvdr, nil, nil, nil}
}

// mockProvider mocks provider for KMS
type mockProvider struct {
	storage       *mockstorage.MockStoreProvider
	kms           kms.KeyManager
	packers       []packer.Packer
	primaryPacker packer.Packer
}

func (m *mockProvider) Packers() []packer.Packer {
	return m.packers
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

func (m *mockProvider) PrimaryPacker() packer.Packer {
	return m.primaryPacker
}
