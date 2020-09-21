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
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer/authcrypt"
	legacy "github.com/hyperledger/aries-framework-go/pkg/didcomm/packer/legacy/authcrypt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/mock/didcomm"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/wrapper/prefix"
)

func TestBaseKMSInPackager_UnpackMessage(t *testing.T) {
	localKeyURI := "local-lock://test/key-uri/"

	t.Run("test failed to unmarshal encMessage", func(t *testing.T) {
		// create a custom KMS instance with this provider
		customKMS, err := localkms.New(localKeyURI,
			newMockKMSProvider(mockstorage.NewMockStoreProvider()))
		require.NoError(t, err)
		require.NotEmpty(t, customKMS)

		require.NoError(t, err)

		mockedProviders := &mockProvider{
			storage:       mockstorage.NewMockStoreProvider(),
			kms:           customKMS,
			primaryPacker: nil,
			packers:       nil,
		}
		testPacker, err := authcrypt.New(mockedProviders, jose.A256GCM)
		require.NoError(t, err)

		mockedProviders.primaryPacker = testPacker
		packager, err := New(mockedProviders)
		require.NoError(t, err)
		_, err = packager.UnpackMessage(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unexpected end of JSON input")
	})

	t.Run("test bad encoding type", func(t *testing.T) {
		customKMS, err := localkms.New(localKeyURI,
			newMockKMSProvider(mockstorage.NewMockStoreProvider()))
		require.NoError(t, err)
		require.NotEmpty(t, customKMS)

		mockedProviders := &mockProvider{
			storage:       mockstorage.NewMockStoreProvider(),
			kms:           customKMS,
			primaryPacker: nil,
			packers:       nil,
		}
		testPacker, err := authcrypt.New(mockedProviders, jose.A256GCM)
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
		storeMap := make(map[string][]byte)
		customStore := &mockstorage.MockStore{
			Store: storeMap,
		}

		thirdPartyKeysStoreMap := make(map[string][]byte)
		thirdPartyStore := &mockstorage.MockStore{
			Store: thirdPartyKeysStoreMap,
		}

		// create a customKMS with a custom storage provider using the above store to access the store map.
		customKMS, err := localkms.New(localKeyURI,
			newMockKMSProvider(mockstorage.NewCustomMockStoreProvider(customStore)))
		require.NoError(t, err)
		require.NotEmpty(t, customKMS)

		mockedProviders := &mockProvider{
			storage:       mockstorage.NewCustomMockStoreProvider(thirdPartyStore),
			kms:           customKMS,
			primaryPacker: nil,
			packers:       nil,
		}
		testPacker, err := authcrypt.New(mockedProviders, jose.A256GCM)
		require.NoError(t, err)

		// use a real testPacker and a real KMS to validate pack/unpack
		mockedProviders.primaryPacker = testPacker
		packager, err := New(mockedProviders)
		require.NoError(t, err)

		// fromKey is stored in the KMS
		fromKID, fromKey, err := customKMS.CreateAndExportPubKeyBytes(kms.ECDH1PU256AES256GCMType)
		require.NoError(t, err)

		// for authcrypt, sender key should be in third party store, must use base58 wrapped store to match kms store.
		wThirdPartyStore, err := prefix.NewPrefixStoreWrapper(thirdPartyStore, prefix.StorageKIDPrefix)
		require.NoError(t, err)

		err = wThirdPartyStore.Put(fromKID, fromKey)
		require.NoError(t, err)

		// toVerKey is stored in the KMS as well
		toKID, toKey, err := customKMS.CreateAndExportPubKeyBytes(kms.ECDH1PU256AES256GCM)
		require.NoError(t, err)

		// PackMessage should pass with both value from and to keys
		packMsg, err := packager.PackMessage(&transport.Envelope{
			Message: []byte("msg1"),
			FromKey: []byte(fromKID), // authcrypt uses sender's KID as Fromkey value
			ToKeys:  []string{base58.Encode(toKey)},
		})
		require.NoError(t, err)

		// mock KMS without ToKey then try UnpackMessage
		delete(storeMap, prefix.StorageKIDPrefix+toKID) // keys in storeMap are prefixed

		// It should fail since Recipient keys are not found in the KMS
		_, err = packager.UnpackMessage(packMsg)
		require.Error(t, err)
		require.EqualError(t, err, "unpack: authcrypt Unpack: no matching recipient in envelope")
	})

	t.Run("test Pack/Unpack fails", func(t *testing.T) {
		customKMS, err := localkms.New(localKeyURI,
			newMockKMSProvider(mockstorage.NewMockStoreProvider()))
		require.NoError(t, err)
		require.NotEmpty(t, customKMS)

		decryptValue := func(envelope []byte) (*transport.Envelope, error) {
			return nil, fmt.Errorf("unpack error")
		}

		mockedProviders := &mockProvider{
			storage:       mockstorage.NewMockStoreProvider(),
			kms:           customKMS,
			primaryPacker: nil,
			packers:       nil,
		}

		// use a mocked packager with a mocked KMS to validate pack/unpack
		e := func(payload []byte, senderPubKey []byte, recipientsKeys [][]byte) (bytes []byte, e error) {
			p, e := authcrypt.New(mockedProviders, jose.A256GCM)
			require.NoError(t, e)
			return p.Pack(payload, senderPubKey, recipientsKeys)
		}

		// Type must match the packer ID since this is a mock packer. Since EncryptValue calls Authcrypt, tweak the type
		// to match the packerID of authcrypt (encType + "-authcrypt")
		mockPacker := &didcomm.MockAuthCrypt{
			DecryptValue: decryptValue,
			EncryptValue: e, Type: "didcomm-envelope-enc-authcrypt",
		}

		mockedProviders.primaryPacker = mockPacker

		packager, err := New(mockedProviders)
		require.NoError(t, err)

		// use ECDH1PU type as we are using a sender key (ie: packer's FromKey is not empty aka authcrypt)
		fromKID, _, err := customKMS.Create(kms.ECDH1PU384AES256GCMType)
		require.NoError(t, err)

		_, toKey, err := customKMS.CreateAndExportPubKeyBytes(kms.ECDH1PU384AES256GCMType)
		require.NoError(t, err)

		// try pack with nil envelope - should fail
		packMsg, err := packager.PackMessage(nil)
		require.EqualError(t, err, "packMessage: envelope argument is nil")
		require.Empty(t, packMsg)

		// now try to pack with non empty envelope - should pass
		packMsg, err = packager.PackMessage(&transport.Envelope{
			Message: []byte("msg1"),
			FromKey: []byte(fromKID),
			ToKeys:  []string{base58.Encode(toKey)},
		})
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
		packMsg, err = packager.PackMessage(&transport.Envelope{
			Message: []byte("msg1"),
			FromKey: []byte(fromKID),
			ToKeys:  []string{base58.Encode(toKey)},
		})
		require.Error(t, err)
		require.Empty(t, packMsg)
		require.EqualError(t, err, "packMessage: failed to pack: pack error")
	})

	t.Run("test Pack/Unpack success", func(t *testing.T) {
		customKMS, err := localkms.New(localKeyURI,
			newMockKMSProvider(mockstorage.NewMockStoreProvider()))
		require.NoError(t, err)
		require.NotEmpty(t, customKMS)

		thirdPartyKeyStore := make(map[string][]byte)
		customStore := &mockstorage.MockStore{
			Store: thirdPartyKeyStore,
		}

		mockedProviders := &mockProvider{
			storage:       mockstorage.NewCustomMockStoreProvider(customStore),
			kms:           customKMS,
			primaryPacker: nil,
			packers:       nil,
		}

		// create a real testPacker (no mocking here)
		testPacker, err := authcrypt.New(mockedProviders, jose.A256GCM)
		require.NoError(t, err)
		mockedProviders.primaryPacker = testPacker

		legacyPacker := legacy.New(mockedProviders)
		mockedProviders.packers = []packer.Packer{testPacker, legacyPacker}

		// now create a new packager with the above provider context
		packager, err := New(mockedProviders)
		require.NoError(t, err)

		fromKID, fromKey, err := customKMS.CreateAndExportPubKeyBytes(kms.ECDH1PU256AES256GCMType)
		require.NoError(t, err)

		_, toKey, err := customKMS.CreateAndExportPubKeyBytes(kms.ECDH1PU256AES256GCMType)
		require.NoError(t, err)

		// pack an non empty envelope - should pass
		packMsg, err := packager.PackMessage(&transport.Envelope{
			Message: []byte("msg1"),
			FromKey: []byte(fromKID),
			ToKeys:  []string{base58.Encode(toKey)},
		})
		require.NoError(t, err)

		// for unpacking authcrypt (ECDH1PU), the assumption is the recipient has received the sender's key
		// adding the key in the thirdPartyKeyStore of the recipient, stored using StorePrefixWrapper
		fromWrappedKID := prefix.StorageKIDPrefix + fromKID
		thirdPartyKeyStore[fromWrappedKID] = fromKey

		// unpack the packed message above - should pass and match the same payload (msg1)
		unpackedMsg, err := packager.UnpackMessage(packMsg)
		require.NoError(t, err)
		require.Equal(t, unpackedMsg.Message, []byte("msg1"))

		// pack with legacy, unpack using a packager that has JWE as default but supports legacy

		mockedProviders.primaryPacker = legacyPacker

		packager2, err := New(mockedProviders)
		require.NoError(t, err)

		// legacy packer uses ED25519 keys only
		_, fromKey, err = customKMS.CreateAndExportPubKeyBytes(kms.ED25519)
		require.NoError(t, err)

		_, toKey, err = customKMS.CreateAndExportPubKeyBytes(kms.ED25519)
		require.NoError(t, err)

		packMsg, err = packager2.PackMessage(&transport.Envelope{
			Message: []byte("msg2"),
			FromKey: fromKey,
			ToKeys:  []string{base58.Encode(toKey)},
		})
		require.NoError(t, err)

		// unpack the packed message above - should pass and match the same payload (msg2)
		unpackedMsg, err = packager.UnpackMessage(packMsg)
		require.NoError(t, err)
		require.Equal(t, unpackedMsg.Message, []byte("msg2"))
	})

	t.Run("test success - dids not found", func(t *testing.T) {
		customKMS, err := localkms.New(localKeyURI,
			newMockKMSProvider(mockstorage.NewMockStoreProvider()))
		require.NoError(t, err)
		require.NotEmpty(t, customKMS)

		require.NoError(t, err)
		mockedProviders := &mockProvider{
			storage:       mockstorage.NewMockStoreProvider(),
			kms:           customKMS,
			primaryPacker: nil,
			packers:       nil,
		}

		// create a real testPacker (no mocking here)
		testPacker := legacy.New(mockedProviders)
		require.NoError(t, err)
		mockedProviders.primaryPacker = testPacker

		mockedProviders.packers = []packer.Packer{testPacker}

		// now create a new packager with the above provider context
		packager, err := New(mockedProviders)
		require.NoError(t, err)

		_, fromKey, err := customKMS.CreateAndExportPubKeyBytes(kms.ED25519Type)
		require.NoError(t, err)

		_, toKey, err := customKMS.CreateAndExportPubKeyBytes(kms.ED25519Type)
		require.NoError(t, err)

		// pack an non empty envelope - should pass
		packMsg, err := packager.PackMessage(&transport.Envelope{
			Message: []byte("msg1"),
			FromKey: fromKey,
			ToKeys:  []string{base58.Encode(toKey)},
		})
		require.NoError(t, err)

		// unpack the packed message above - should pass and match the same payload (msg1)
		unpackedMsg, err := packager.UnpackMessage(packMsg)
		require.NoError(t, err)
		require.Equal(t, unpackedMsg.Message, []byte("msg1"))
	})

	t.Run("test failure - did lookup broke", func(t *testing.T) {
		customKMS, err := localkms.New(localKeyURI,
			newMockKMSProvider(mockstorage.NewMockStoreProvider()))
		require.NoError(t, err)
		require.NotEmpty(t, customKMS)

		mockedProviders := &mockProvider{
			storage: mockstorage.NewCustomMockStoreProvider(&mockstorage.MockStore{
				Store:  make(map[string][]byte),
				ErrGet: fmt.Errorf("bad error"),
			}),
			kms:           customKMS,
			primaryPacker: nil,
			packers:       nil,
		}

		// create a real testPacker (no mocking here)
		testPacker := legacy.New(mockedProviders)
		require.NoError(t, err)
		mockedProviders.primaryPacker = testPacker

		mockedProviders.packers = []packer.Packer{testPacker}

		// now create a new packager with the above provider context
		packager, err := New(mockedProviders)
		require.NoError(t, err)

		_, fromKey, err := customKMS.CreateAndExportPubKeyBytes(kms.ED25519Type)
		require.NoError(t, err)

		_, toKey, err := customKMS.CreateAndExportPubKeyBytes(kms.ED25519Type)
		require.NoError(t, err)

		// pack an non empty envelope - should pass
		packMsg, err := packager.PackMessage(&transport.Envelope{
			Message: []byte("msg1"),
			FromKey: fromKey,
			ToKeys:  []string{base58.Encode(toKey)},
		})
		require.NoError(t, err)

		// unpack the packed message above - should pass and match the same payload (msg1)
		unpackedMsg, err := packager.UnpackMessage(packMsg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "bad error")
		require.Nil(t, unpackedMsg)
	})
}

func newMockKMSProvider(storagePvdr *mockstorage.MockStoreProvider) *mockProvider {
	return &mockProvider{storagePvdr, nil, &noop.NoLock{}, nil, nil, nil}
}

// mockProvider mocks provider for KMS.
type mockProvider struct {
	storage       *mockstorage.MockStoreProvider
	kms           kms.KeyManager
	secretLock    secretlock.Service
	packers       []packer.Packer
	primaryPacker packer.Packer
	vdriRegistry  vdriapi.Registry
}

func (m *mockProvider) Packers() []packer.Packer {
	return m.packers
}

func (m *mockProvider) KMS() kms.KeyManager {
	return m.kms
}

func (m *mockProvider) SecretLock() secretlock.Service {
	return m.secretLock
}

func (m *mockProvider) StorageProvider() storage.Provider {
	return m.storage
}

func (m *mockProvider) PrimaryPacker() packer.Packer {
	return m.primaryPacker
}

// VDRIRegistry returns a vdri registry.
func (m *mockProvider) VDRIRegistry() vdriapi.Registry {
	return m.vdriRegistry
}
