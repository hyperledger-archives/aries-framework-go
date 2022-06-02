/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/hyperledger/aries-framework-go/pkg/mock/secretlock"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
)

const (
	sampleProfileUser      = "sampleProfileUser#01"
	sampleKeyServerURL     = "sample/keyserver/test"
	sampleMasterCipherText = "sample-master-cipher"
	sampleCustomProfileErr = "sample profile custom error"
)

func TestCreateNewProfile(t *testing.T) {
	t.Run("test create new profile with key server URL", func(t *testing.T) {
		profile, err := createProfile(sampleProfileUser,
			&profileOpts{passphrase: "", secretLockSvc: nil, keyServerURL: sampleKeyServerURL})

		require.NoError(t, err)
		require.NotEmpty(t, profile)
		require.NotEmpty(t, profile.ID)
		require.Equal(t, profile.KeyServerURL, sampleKeyServerURL)
		require.Empty(t, profile.MasterLockCipher)
	})

	t.Run("test create new profile with passphrase", func(t *testing.T) {
		profile, err := createProfile(sampleProfileUser,
			&profileOpts{passphrase: samplePassPhrase, secretLockSvc: nil, keyServerURL: sampleKeyServerURL})

		require.NoError(t, err)
		require.NotEmpty(t, profile)
		require.NotEmpty(t, profile.ID)
		require.Empty(t, profile.KeyServerURL, "")
		require.NotEmpty(t, profile.MasterLockCipher)
	})

	t.Run("test create new profile with secret lock service", func(t *testing.T) {
		profile, err := createProfile(sampleProfileUser,
			&profileOpts{passphrase: "", secretLockSvc: &secretlock.MockSecretLock{
				ValEncrypt: sampleMasterCipherText,
			}, keyServerURL: sampleKeyServerURL})

		require.NoError(t, err)
		require.NotEmpty(t, profile)
		require.NotEmpty(t, profile.ID)
		require.Empty(t, profile.KeyServerURL, "")
		require.Equal(t, profile.MasterLockCipher, sampleMasterCipherText)
	})

	t.Run("test create new profile with EDV conf", func(t *testing.T) {
		profile, err := createProfile(sampleProfileUser,
			&profileOpts{
				passphrase: samplePassPhrase, secretLockSvc: nil, keyServerURL: sampleKeyServerURL,
				edvConf: &edvConf{
					ServerURL:       "sample-server-url",
					VaultID:         "sample-vault-ID",
					EncryptionKeyID: "sample-enc-kid",
					MACKeyID:        "sample-mac-kid",
				},
			})

		require.NoError(t, err)
		require.NotEmpty(t, profile)
		require.NotEmpty(t, profile.ID)
		require.Empty(t, profile.KeyServerURL, "")
		require.NotEmpty(t, profile.MasterLockCipher)
		require.NotEmpty(t, profile.EDVConf)
		require.NotEmpty(t, profile.EDVConf.ServerURL)
		require.NotEmpty(t, profile.EDVConf.VaultID)
		require.NotEmpty(t, profile.EDVConf.EncryptionKeyID)
		require.NotEmpty(t, profile.EDVConf.MACKeyID)
	})

	t.Run("test create new profile failure", func(t *testing.T) {
		// invalid profile option
		profile, err := createProfile(sampleProfileUser,
			&profileOpts{passphrase: "", secretLockSvc: nil, keyServerURL: ""})

		require.Empty(t, profile)
		require.Error(t, err)
		require.EqualError(t, err, "invalid create profile options")

		// secret lock service error
		profile, err = createProfile(sampleProfileUser,
			&profileOpts{passphrase: "", secretLockSvc: &secretlock.MockSecretLock{
				ErrEncrypt: fmt.Errorf(sampleCustomProfileErr),
			}, keyServerURL: ""})

		require.Empty(t, profile)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create master lock from secret lock service provided")
		require.Contains(t, err.Error(), sampleCustomProfileErr)

		// invalid EDV settings
		profile, err = createProfile(sampleProfileUser,
			&profileOpts{
				passphrase: samplePassPhrase, secretLockSvc: nil, keyServerURL: sampleKeyServerURL,
				edvConf: &edvConf{
					ServerURL: "sample-server-url",
				},
			})
		require.Empty(t, profile)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid EDV settings in profile")
	})

	t.Run("test setup edv keys", func(t *testing.T) {
		sampleProfile := &profile{
			EDVConf: &edvConf{
				ServerURL: "sample-server-url",
				VaultID:   "sample-vault-id",
			},
		}

		kid := "sample-kid"

		// setup edv keys
		err := sampleProfile.setupEDVEncryptionKey(&mockkms.KeyManager{CreateKeyID: kid})
		require.NoError(t, err)
		require.Equal(t, sampleProfile.EDVConf.EncryptionKeyID, kid)

		err = sampleProfile.setupEDVMacKey(&mockkms.KeyManager{CreateKeyID: kid})
		require.NoError(t, err)
		require.Equal(t, sampleProfile.EDVConf.MACKeyID, kid)

		// test create key error
		err = sampleProfile.setupEDVEncryptionKey(&mockkms.KeyManager{CreateKeyErr: errors.New(sampleKeyMgrErr)})
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleKeyMgrErr)

		err = sampleProfile.setupEDVMacKey(&mockkms.KeyManager{CreateKeyErr: errors.New(sampleKeyMgrErr)})
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleKeyMgrErr)
	})
}

func TestProfileStore(t *testing.T) {
	t.Run("test create new profile store instance", func(t *testing.T) {
		// success
		profileStore, err := newProfileStore(mockstorage.NewMockStoreProvider())
		require.NoError(t, err)
		require.NotEmpty(t, profileStore)

		// error
		profileStore, err = newProfileStore(&mockstorage.MockStoreProvider{
			ErrOpenStoreHandle: fmt.Errorf(sampleCustomProfileErr),
		})
		require.Error(t, err)
		require.EqualError(t, err, sampleCustomProfileErr)
		require.Empty(t, profileStore)
	})

	t.Run("test save profiles in store", func(t *testing.T) {
		profileStore, err := newProfileStore(mockstorage.NewMockStoreProvider())
		require.NoError(t, err)
		require.NotEmpty(t, profileStore)

		// success save
		err = profileStore.save(&profile{User: sampleProfileUser}, false)
		require.NoError(t, err)
		result, err := profileStore.get(sampleProfileUser)
		require.NoError(t, err)
		require.Equal(t, result.User, sampleProfileUser)

		// save existing profile
		err = profileStore.save(&profile{User: sampleProfileUser}, false)
		require.Error(t, err)
		require.EqualError(t, err, "profile already exists for given user")

		// save override existing profile
		err = profileStore.save(&profile{User: sampleProfileUser}, true)
		require.NoError(t, err)
		result, err = profileStore.get(sampleProfileUser)
		require.NoError(t, err)
		require.Equal(t, result.User, sampleProfileUser)
	})

	t.Run("test get profiles from store", func(t *testing.T) {
		profileStore, err := newProfileStore(mockstorage.NewMockStoreProvider())
		require.NoError(t, err)
		require.NotEmpty(t, profileStore)

		// setup data
		err = profileStore.save(&profile{User: sampleProfileUser}, false)
		require.NoError(t, err)

		// get profile from store
		result, err := profileStore.get(sampleProfileUser)
		require.NoError(t, err)
		require.Equal(t, result.User, sampleProfileUser)

		// get non-existing profile from store
		result, err = profileStore.get("non-existing-user")
		require.Empty(t, result)
		require.Error(t, err)
		require.Equal(t, err, ErrProfileNotFound)
	})

	t.Run("test errors while getting profiles from store", func(t *testing.T) {
		const sampleProfileUser2 = "sampleProfileUser#02"
		profileStore, err := newProfileStore(&mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{
				ErrGet: fmt.Errorf(sampleCustomProfileErr),
			},
		})
		require.NoError(t, err)
		require.NotEmpty(t, profileStore)

		// get profile from store
		result, err := profileStore.get(sampleProfileUser)
		require.Empty(t, result)
		require.Error(t, err)
		require.EqualError(t, err, sampleCustomProfileErr)

		// unmarshal error test
		profileStore, err = newProfileStore(&mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{
				Store: map[string]mockstorage.DBEntry{
					getUserKeyPrefix(sampleProfileUser2): {Value: []byte("----")},
				},
			},
		})
		require.NoError(t, err)

		// put invalid data in store to get unmarshal error
		result, err = profileStore.get(sampleProfileUser2)
		require.Empty(t, result)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid character")
	})
}
