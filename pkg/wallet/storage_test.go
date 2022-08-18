/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/storage/edv"
	kmsapi "github.com/hyperledger/aries-framework-go/pkg/kms"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

func TestStorageProvider_OpenStore(t *testing.T) {
	sampleUser := uuid.New().String()
	masterLock, err := getDefaultSecretLock(samplePassPhrase)
	require.NoError(t, err)

	masterLockCipherText, err := createMasterLock(masterLock)
	require.NoError(t, err)
	require.NotEmpty(t, masterLockCipherText)

	profileInfo := &profile{
		User:             sampleUser,
		MasterLockCipher: masterLockCipherText,
	}

	kmsStore, err := kmsapi.NewAriesProviderWrapper(mockstorage.NewMockStoreProvider())
	require.NoError(t, err)

	kmgr, err := keyManager().createKeyManager(profileInfo, kmsStore,
		&unlockOpts{passphrase: samplePassPhrase})
	require.NoError(t, err)
	require.NotEmpty(t, kmgr)

	token, err := sessionManager().createSession(uuid.New().String(), kmgr, 0)

	require.NoError(t, err)
	require.NotEmpty(t, token)

	t.Run("successfully open store", func(t *testing.T) {
		sp := getMockStorageProvider()
		sampleProfile := &profile{ID: uuid.New().String(), User: uuid.New().String()}
		wsp := newWalletStorageProvider(sampleProfile, sp)

		store, e := wsp.OpenStore(kmgr, &unlockOpts{},
			storage.StoreConfiguration{TagNames: []string{Credential.Name()}})

		require.NoError(t, e)
		require.NotEmpty(t, store)
		require.Len(t, sp.config.TagNames, 1)
	})

	t.Run("successfully open EDV store", func(t *testing.T) {
		sampleProfile := &profile{
			ID: uuid.New().String(), User: uuid.New().String(),
			EDVConf: &edvConf{
				ServerURL: "sample-server",
				VaultID:   "sample-vault-ID",
			},
			KeyServerURL: sampleKeyServerURL,
		}

		err = sampleProfile.setupEDVEncryptionKey(kmgr)
		require.NoError(t, err)

		err = sampleProfile.setupEDVMacKey(kmgr)
		require.NoError(t, err)

		wsp := newWalletStorageProvider(sampleProfile, nil)

		store, err := wsp.OpenStore(kmgr, &unlockOpts{},
			storage.StoreConfiguration{TagNames: []string{Credential.Name()}})
		require.NoError(t, err)
		require.NotEmpty(t, store)

		// with edv opts
		store, err = wsp.OpenStore(kmgr, &unlockOpts{
			edvOpts: []edv.RESTProviderOption{
				edv.WithFullDocumentsReturnedFromQueries(),
				edv.WithBatchEndpointExtension(),
			},
		}, storage.StoreConfiguration{TagNames: []string{Credential.Name()}})
		require.NoError(t, err)
		require.NotEmpty(t, store)

		// no edv opts
		store, err = wsp.OpenStore(kmgr, &unlockOpts{},
			storage.StoreConfiguration{TagNames: []string{Credential.Name()}})
		require.NoError(t, err)
		require.NotEmpty(t, store)
	})

	t.Run("failed to open EDV store", func(t *testing.T) {
		sampleProfile := &profile{
			ID: uuid.New().String(), User: uuid.New().String(),
			EDVConf: &edvConf{
				ServerURL: "sample-server",
				VaultID:   "sample-vault-ID",
			},
		}

		// invalid settings
		wsp := newWalletStorageProvider(sampleProfile, nil)
		store, err := wsp.OpenStore(kmgr, &unlockOpts{},
			storage.StoreConfiguration{TagNames: []string{Credential.Name()}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid EDV configuration found in wallet profile")
		require.Empty(t, store)

		err = sampleProfile.setupEDVEncryptionKey(kmgr)
		require.NoError(t, err)

		err = sampleProfile.setupEDVMacKey(kmgr)
		require.NoError(t, err)

		wsp = newWalletStorageProvider(sampleProfile, nil)

		// incorrect mac key ID
		wsp.profile.EDVConf.MACKeyID += "x"
		store, err = wsp.OpenStore(kmgr, &unlockOpts{},
			storage.StoreConfiguration{TagNames: []string{Credential.Name()}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create mac crypto")
		require.Empty(t, store)

		// incorrect encryption key ID
		wsp.profile.EDVConf.EncryptionKeyID += "x"
		store, err = wsp.OpenStore(kmgr, &unlockOpts{},
			storage.StoreConfiguration{TagNames: []string{Credential.Name()}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create JWE encrypter")
		require.Empty(t, store)

		val, err := getJWSEncrypter("sample-kid", &mockkms.KeyManager{
			ExportPubKeyBytesValue: []byte("invalid"),
		}, &mockcrypto.Crypto{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to unmarshal JWE public key bytes to an EC public key")
		require.Empty(t, val)
	})

	t.Run("failed to set store config", func(t *testing.T) {
		sp := getMockStorageProvider()
		sampleProfile := &profile{ID: uuid.New().String(), User: uuid.New().String()}
		wsp := newWalletStorageProvider(sampleProfile, sp)

		sp.failure = errors.New(sampleWalletErr)
		sp.Store.ErrClose = errors.New(sampleWalletErr)

		store, err := wsp.OpenStore(kmgr, &unlockOpts{},
			storage.StoreConfiguration{TagNames: []string{Credential.Name()}})
		require.Error(t, err)
		require.Empty(t, store)
	})
}
