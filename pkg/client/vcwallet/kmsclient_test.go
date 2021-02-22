/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcwallet

import (
	"crypto/sha256"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	kmsapi "github.com/hyperledger/aries-framework-go/pkg/kms"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local/masterlock/pbkdf2"
)

const (
	samplePassPhrase    = "fakepassphrase"
	sampleRemoteKMSAuth = "sample-auth-token"
	keyNotFoundErr      = "Key not found."
)

func TestKeyManagerStore(t *testing.T) {
	t.Run("test key manager instance", func(t *testing.T) {
		require.NotEmpty(t, keyManager())
		require.Equal(t, keyManager(), keyManager())
	})
}

func TestKeyManager(t *testing.T) {
	t.Run("create key manager for localkms - with passphrase", func(t *testing.T) {
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

		tkn, err := keyManager().createKeyManager(profileInfo, mockstorage.NewMockStoreProvider(),
			samplePassPhrase, nil, 0)
		require.NoError(t, err)
		require.NotEmpty(t, tkn)

		// get key manager
		kms, err := keyManager().getKeyManger(tkn)
		require.NoError(t, err)
		require.NotEmpty(t, kms)

		// try to create again before expiry
		tkn, err = keyManager().createKeyManager(profileInfo, mockstorage.NewMockStoreProvider(),
			samplePassPhrase, nil, 0)
		require.Error(t, err)
		require.Equal(t, err, ErrAlreadyUnlocked)
		require.Empty(t, tkn)
	})

	t.Run("create key manager for localkms - with secret lock service", func(t *testing.T) {
		sampleUser := uuid.New().String()
		masterLock, err := pbkdf2.NewMasterLock(samplePassPhrase, sha256.New, 0, nil)
		require.NoError(t, err)

		masterLockCipherText, err := createMasterLock(masterLock)
		require.NoError(t, err)
		require.NotEmpty(t, masterLockCipherText)

		profileInfo := &profile{
			User:             sampleUser,
			MasterLockCipher: masterLockCipherText,
		}

		tkn, err := keyManager().createKeyManager(profileInfo, mockstorage.NewMockStoreProvider(),
			"", masterLock, 0)
		require.NoError(t, err)
		require.NotEmpty(t, tkn)

		// get key manager
		kms, err := keyManager().getKeyManger(tkn)
		require.NoError(t, err)
		require.NotEmpty(t, kms)

		// try to create again before expiry
		tkn, err = keyManager().createKeyManager(profileInfo, mockstorage.NewMockStoreProvider(),
			"", masterLock, 0)
		require.Error(t, err)
		require.Equal(t, err, ErrAlreadyUnlocked)
		require.Empty(t, tkn)
	})

	t.Run("create key manager for localkms - passphrase missmatch", func(t *testing.T) {
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

		// use wrong passphrase
		tkn, err := keyManager().createKeyManager(profileInfo, mockstorage.NewMockStoreProvider(),
			samplePassPhrase+"wrong", nil, 0)
		require.Empty(t, tkn)
		require.Error(t, err)
		require.Contains(t, err.Error(), "message authentication failed")

		// get key manager
		kms, err := keyManager().getKeyManger(tkn)
		require.Empty(t, kms)
		require.Error(t, err)
		require.EqualError(t, err, keyNotFoundErr)
	})

	t.Run("create key manager for localkms - secret lock service missmatch", func(t *testing.T) {
		sampleUser := uuid.New().String()
		masterLock, err := pbkdf2.NewMasterLock(samplePassPhrase, sha256.New, 0, nil)
		require.NoError(t, err)

		masterLockCipherText, err := createMasterLock(masterLock)
		require.NoError(t, err)
		require.NotEmpty(t, masterLockCipherText)

		profileInfo := &profile{
			User:             sampleUser,
			MasterLockCipher: masterLockCipherText,
		}

		// use wrong secret lock service
		masterLockBad, err := pbkdf2.NewMasterLock(samplePassPhrase+"wrong", sha256.New, 0, nil)
		require.NoError(t, err)

		tkn, err := keyManager().createKeyManager(profileInfo, mockstorage.NewMockStoreProvider(),
			"", masterLockBad, 0)
		require.Empty(t, tkn)
		require.Error(t, err)
		require.Contains(t, err.Error(), "message authentication failed")

		// get key manager
		kms, err := keyManager().getKeyManger(tkn)
		require.Empty(t, kms)
		require.Error(t, err)
		require.EqualError(t, err, keyNotFoundErr)
	})

	t.Run("create key manager for remotekms", func(t *testing.T) {
		sampleUser := uuid.New().String()
		profileInfo := &profile{
			User:         sampleUser,
			KeyServerURL: sampleKeyServerURL,
		}

		tkn, err := keyManager().createKeyManager(profileInfo, mockstorage.NewMockStoreProvider(),
			sampleRemoteKMSAuth, nil, 0)
		require.NoError(t, err)
		require.NotEmpty(t, tkn)

		// get key manager
		kmgr, err := keyManager().getKeyManger(tkn)
		require.NoError(t, err)
		require.NotEmpty(t, kmgr)

		_, _, err = kmgr.Create(kmsapi.ED25519Type)
		require.Error(t, err)

		// try to create again before expiry
		tkn, err = keyManager().createKeyManager(profileInfo, mockstorage.NewMockStoreProvider(),
			sampleRemoteKMSAuth, nil, 0)
		require.Error(t, err)
		require.Equal(t, err, ErrAlreadyUnlocked)
		require.Empty(t, tkn)
	})

	t.Run("create key manager for failure - invalid profile", func(t *testing.T) {
		profileInfo := &profile{
			User: uuid.New().String(),
		}

		tkn, err := keyManager().createKeyManager(profileInfo, mockstorage.NewMockStoreProvider(),
			sampleRemoteKMSAuth, nil, 0)
		require.Empty(t, tkn)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid wallet profile")

		// get key manager
		kms, err := keyManager().getKeyManger(tkn)
		require.Empty(t, kms)
		require.Error(t, err)
		require.EqualError(t, err, keyNotFoundErr)
	})

	t.Run("test remove key manager", func(t *testing.T) {
		sampleUser := uuid.New().String()
		profileInfo := &profile{
			User:         sampleUser,
			KeyServerURL: sampleKeyServerURL,
		}

		tkn, err := keyManager().createKeyManager(profileInfo, mockstorage.NewMockStoreProvider(),
			sampleRemoteKMSAuth, nil, 0)
		require.NoError(t, err)
		require.NotEmpty(t, tkn)

		// get key manager
		kmgr, err := keyManager().getKeyManger(tkn)
		require.NoError(t, err)
		require.NotEmpty(t, kmgr)

		// try to create again before expiry
		tkn, err = keyManager().createKeyManager(profileInfo, mockstorage.NewMockStoreProvider(),
			sampleRemoteKMSAuth, nil, 0)
		require.Error(t, err)
		require.Equal(t, err, ErrAlreadyUnlocked)
		require.Empty(t, tkn)

		// remove key manager
		require.True(t, keyManager().removeKeyManager(profileInfo.User))
		require.False(t, keyManager().removeKeyManager(profileInfo.User))

		// try to get key manager
		kmgr, err = keyManager().getKeyManger(tkn)
		require.Empty(t, kmgr)
		require.Error(t, err)
		require.EqualError(t, err, keyNotFoundErr)

		// try again to create
		tkn, err = keyManager().createKeyManager(profileInfo, mockstorage.NewMockStoreProvider(),
			sampleRemoteKMSAuth, nil, 0)
		require.NoError(t, err)
		require.NotEmpty(t, tkn)

		// get key manager
		kmgr, err = keyManager().getKeyManger(tkn)
		require.NoError(t, err)
		require.NotEmpty(t, kmgr)
	})
}
