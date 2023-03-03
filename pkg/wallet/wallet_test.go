/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/storage/edv"
	"github.com/hyperledger/aries-framework-go/internal/testdata"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/internal/ldtestutil"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/webkms"
	cryptomock "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	"github.com/hyperledger/aries-framework-go/pkg/mock/secretlock"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local/masterlock/pbkdf2"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// nolint: lll
const (
	sampleUserID            = "sample-user01"
	sampleFakeTkn           = "fake-auth-tkn"
	toBeImplementedErr      = "to be implemented"
	sampleWalletErr         = "sample wallet err"
	sampleCreatedDate       = "2020-12-25"
	sampleChallenge         = "sample-challenge"
	sampleDomain            = "sample-domain"
	sampleInvalidDIDID      = "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHdI"
	sampleInvalidDIDContent = `{
    	"@context": ["https://w3id.org/did/v1"],
    	"id": "did:example:sampleInvalidDIDContent"
		}`
	sampleVerificationMethod = "did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5#z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5"
	didKey                   = "did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5"
	pkBase58                 = "2MP5gWCnf67jvW3E4Lz8PpVrDWAXMYY1sDxjnkEnKhkkbKD7yP2mkVeyVpu5nAtr3TeDgMNjBPirk2XcQacs3dvZ"
	kid                      = "z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5"
	didKeyBBS                = "did:key:zUC72c7u4BYVmfYinDceXkNAwzPEyuEE23kUmJDjLy8495KH3pjLwFhae1Fww9qxxRdLnS2VNNwni6W3KbYZKsicDtiNNEp76fYWR6HCD8jAz6ihwmLRjcHH6kB294Xfg1SL1qQ"
	pkBBSBase58              = "6gsgGpdx7p1nYoKJ4b5fKt1xEomWdnemg9nJFX6mqNCh"
	keyIDBBS                 = "zUC72c7u4BYVmfYinDceXkNAwzPEyuEE23kUmJDjLy8495KH3pjLwFhae1Fww9qxxRdLnS2VNNwni6W3KbYZKsicDtiNNEp76fYWR6HCD8jAz6ihwmLRjcHH6kB294Xfg1SL1qQ"
	sampleEDVServerURL       = "sample-edv-url"
	sampleEDVVaultID         = "sample-edv-vault-id"
	sampleEDVEncryptionKID   = "sample-edv-encryption-kid"
	sampleEDVMacKID          = "sample-edv-mac-kid"
)

func TestCreate(t *testing.T) {
	t.Run("test create new wallet using local kms passphrase", func(t *testing.T) {
		mockctx := newMockProvider(t)
		err := CreateProfile(sampleUserID, mockctx, WithPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NoError(t, ProfileExists(sampleUserID, mockctx))

		wallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)
	})

	t.Run("test create new wallet using local kms secret lock service", func(t *testing.T) {
		mockctx := newMockProvider(t)
		err := CreateProfile(sampleUserID, mockctx, WithSecretLockService(&secretlock.MockSecretLock{}))
		require.NoError(t, err)

		wallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)
	})

	t.Run("test create new wallet using remote kms key server URL", func(t *testing.T) {
		mockctx := newMockProvider(t)
		err := CreateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL))
		require.NoError(t, err)

		wallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)
	})

	t.Run("test create new wallet using remote kms key server URL & EDV", func(t *testing.T) {
		mockctx := newMockProvider(t)
		err := CreateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL),
			WithEDVStorage(sampleEDVServerURL, sampleEDVVaultID, sampleEDVEncryptionKID, sampleEDVMacKID))
		require.NoError(t, err)

		wallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)
		require.NotEmpty(t, wallet.profile.EDVConf)
		require.Equal(t, wallet.profile.EDVConf.ServerURL, sampleEDVServerURL)
		require.Equal(t, wallet.profile.EDVConf.VaultID, sampleEDVVaultID)
		require.Equal(t, wallet.profile.EDVConf.EncryptionKeyID, sampleEDVEncryptionKID)
		require.Equal(t, wallet.profile.EDVConf.MACKeyID, sampleEDVMacKID)
	})

	t.Run("test create new wallet failure", func(t *testing.T) {
		mockctx := newMockProvider(t)
		err := CreateProfile(sampleUserID, mockctx)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid create profile options")

		require.True(t, errors.Is(ProfileExists(sampleUserID, mockctx), ErrProfileNotFound))

		wallet, err := New(sampleUserID, mockctx)
		require.Error(t, err)
		require.Empty(t, wallet)
	})

	t.Run("test create new wallet failure - create store error", func(t *testing.T) {
		mockctx := newMockProvider(t)
		mockctx.StorageProviderValue = &mockstorage.MockStoreProvider{
			ErrOpenStoreHandle: fmt.Errorf(sampleWalletErr),
		}

		err := CreateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL))
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleWalletErr)

		err = ProfileExists(sampleUserID, mockctx)
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleWalletErr)

		wallet, err := New(sampleUserID, mockctx)
		require.Error(t, err)
		require.Empty(t, wallet)
	})

	t.Run("test create new wallet failure - save profile error", func(t *testing.T) {
		mockctx := newMockProvider(t)
		mockctx.StorageProviderValue = &mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{
				ErrPut: fmt.Errorf(sampleWalletErr),
			},
		}

		err := CreateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL))
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleWalletErr)

		wallet, err := New(sampleUserID, mockctx)
		require.Error(t, err)
		require.Empty(t, wallet)
	})
}

func TestUpdate(t *testing.T) {
	t.Run("test update wallet using local kms passphrase", func(t *testing.T) {
		mockctx := newMockProvider(t)
		createSampleProfile(t, mockctx)

		err := UpdateProfile(sampleUserID, mockctx, WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		wallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)
		require.NotEmpty(t, wallet.profile.MasterLockCipher)
	})

	t.Run("test update wallet using local kms secret lock service", func(t *testing.T) {
		mockctx := newMockProvider(t)
		createSampleProfile(t, mockctx)

		err := UpdateProfile(sampleUserID, mockctx, WithSecretLockService(&secretlock.MockSecretLock{}))
		require.NoError(t, err)

		wallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)
	})

	t.Run("test update wallet using remote kms key server URL", func(t *testing.T) {
		mockctx := newMockProvider(t)
		createSampleProfile(t, mockctx)

		err := UpdateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL))
		require.NoError(t, err)

		wallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)
		require.Empty(t, wallet.profile.MasterLockCipher)
		require.NotEmpty(t, wallet.profile.KeyServerURL)
	})

	t.Run("test update wallet profile edv settings", func(t *testing.T) {
		mockctx := newMockProvider(t)
		createSampleProfile(t, mockctx)

		err := UpdateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL),
			WithEDVStorage(sampleEDVServerURL, sampleEDVVaultID, sampleEDVEncryptionKID, sampleEDVMacKID))
		require.NoError(t, err)

		wallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)
		require.NotEmpty(t, wallet.profile.EDVConf)
		require.Equal(t, wallet.profile.EDVConf.ServerURL, sampleEDVServerURL)
		require.Equal(t, wallet.profile.EDVConf.VaultID, sampleEDVVaultID)
		require.Equal(t, wallet.profile.EDVConf.EncryptionKeyID, sampleEDVEncryptionKID)
		require.Equal(t, wallet.profile.EDVConf.MACKeyID, sampleEDVMacKID)
	})

	t.Run("test update wallet failure", func(t *testing.T) {
		mockctx := newMockProvider(t)
		createSampleProfile(t, mockctx)

		err := UpdateProfile(sampleUserID, mockctx)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid create profile options")

		wallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)
		require.NotEmpty(t, wallet.profile.MasterLockCipher)
	})

	t.Run("test update wallet failure - profile doesn't exists", func(t *testing.T) {
		mockctx := newMockProvider(t)
		err := UpdateProfile(sampleUserID, mockctx)
		require.Error(t, err)
		require.Contains(t, err.Error(), "profile does not exist")

		wallet, err := New(sampleUserID, mockctx)
		require.Error(t, err)
		require.Empty(t, wallet)
	})

	t.Run("test update wallet failure - create store error", func(t *testing.T) {
		mockctx := newMockProvider(t)
		mockctx.StorageProviderValue = &mockstorage.MockStoreProvider{
			ErrOpenStoreHandle: fmt.Errorf(sampleWalletErr),
		}

		err := UpdateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL))
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleWalletErr)

		wallet, err := New(sampleUserID, mockctx)
		require.Error(t, err)
		require.Empty(t, wallet)
	})

	t.Run("test update wallet failure - save profile error", func(t *testing.T) {
		mockctx := newMockProvider(t)
		createSampleProfile(t, mockctx)

		mockctx.StorageProviderValue.(*mockstorage.MockStoreProvider).Store.ErrPut = fmt.Errorf(sampleWalletErr)

		err := UpdateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL))
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleWalletErr)

		wallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)
		require.Empty(t, wallet.profile.KeyServerURL)
		require.NotEmpty(t, wallet.profile.MasterLockCipher)
	})

	t.Run("test update wallet failure - save edv settings error", func(t *testing.T) {
		mockctx := newMockProvider(t)
		createSampleProfile(t, mockctx)

		err := UpdateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL),
			WithEDVStorage(sampleEDVServerURL, "", sampleEDVEncryptionKID, sampleEDVMacKID))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to update EDV configuration")
	})
}

func TestCreateDataVaultKeyPairs(t *testing.T) {
	t.Run("successfully create EDV key pair", func(t *testing.T) {
		mockctx := newMockProvider(t)

		// create a wallet profile
		err := CreateProfile(sampleUserID, mockctx, WithPassphrase(samplePassPhrase),
			WithEDVStorage(sampleEDVServerURL, sampleEDVVaultID, "", ""))
		require.NoError(t, err)

		err = CreateDataVaultKeyPairs(sampleUserID, mockctx, WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)

		wallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)
		require.NotEmpty(t, wallet.profile.EDVConf.EncryptionKeyID)
		require.NotEmpty(t, wallet.profile.EDVConf.MACKeyID)

		// call again to replace existing settings
		err = CreateDataVaultKeyPairs(sampleUserID, mockctx, WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)

		wallet2, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet2)
		require.NotEmpty(t, wallet2.profile.EDVConf.EncryptionKeyID)
		require.NotEmpty(t, wallet2.profile.EDVConf.MACKeyID)

		require.NotEqual(t, wallet.profile.EDVConf.EncryptionKeyID, wallet2.profile.EDVConf.EncryptionKeyID)
		require.NotEqual(t, wallet.profile.EDVConf.MACKeyID, wallet2.profile.EDVConf.MACKeyID)
	})

	t.Run("successfully create key pair failures", func(t *testing.T) {
		mockctx := newMockProvider(t)

		// test create a wallet profile without EDV settings
		err := CreateProfile(sampleUserID, mockctx, WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		err = CreateDataVaultKeyPairs(sampleUserID, mockctx, WithUnlockByPassphrase(samplePassPhrase))
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid operation")

		// test store errors
		mockctx = newMockProvider(t)
		mockctx.StorageProviderValue = &mockstorage.MockStoreProvider{
			ErrOpenStoreHandle: errors.New(sampleWalletErr),
		}

		err = CreateDataVaultKeyPairs(sampleUserID, mockctx, WithUnlockByPassphrase(samplePassPhrase))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get store")

		// invalid user profile
		mockctx = newMockProvider(t)
		err = CreateDataVaultKeyPairs(sampleUserID, mockctx, WithUnlockByPassphrase(samplePassPhrase))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get wallet user profile")

		// invalid auth
		mockctx = newMockProvider(t)

		err = CreateProfile(sampleUserID, mockctx, WithPassphrase(samplePassPhrase),
			WithEDVStorage(sampleEDVServerURL, sampleEDVVaultID, "", ""))
		require.NoError(t, err)

		err = CreateDataVaultKeyPairs(sampleUserID, mockctx, WithUnlockByPassphrase("invalid"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "message authentication failed")

		// test create key pair error
		mockctx = newMockProvider(t)

		err = CreateProfile(sampleUserID, mockctx, WithPassphrase(samplePassPhrase),
			WithEDVStorage(sampleEDVServerURL, sampleEDVVaultID, "", ""))
		require.NoError(t, err)

		mockStPvdr, ok := mockctx.StorageProviderValue.(*mockstorage.MockStoreProvider)
		require.True(t, ok)
		mockStPvdr.Store.ErrPut = errors.New(sampleWalletErr)

		err = CreateDataVaultKeyPairs(sampleUserID, mockctx, WithUnlockByPassphrase(samplePassPhrase))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create key pairs")
	})

	t.Run("fail to create new KMS Aries provider wrapper", func(t *testing.T) {
		testProfile := profile{EDVConf: &edvConf{}}

		testProfileBytes, err := json.Marshal(testProfile)
		require.NoError(t, err)

		mockContext := &mockprovider.Provider{
			StorageProviderValue: &mockstorage.MockStoreProvider{
				FailNamespace: kms.AriesWrapperStoreName,
				Store: &mockstorage.MockStore{
					Store: map[string]mockstorage.DBEntry{
						"vcwallet_usr_sample-user01": {Value: testProfileBytes},
					},
				},
			},
		}

		err = CreateDataVaultKeyPairs(sampleUserID, mockContext)
		require.EqualError(t, err, "failed to open store for name space kmsdb")
	})

	t.Run("test update profile errors", func(t *testing.T) {
		kmgr := &mockkms.KeyManager{CreateKeyFn: func(kt kms.KeyType) (s string, i interface{}, e error) {
			if kt == kms.HMACSHA256Tag256Type {
				return "", nil, errors.New(sampleWalletErr)
			}
			return "", nil, nil
		}}

		err := updateProfile(kmgr, &profile{EDVConf: &edvConf{}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create EDV MAC key pair")

		kmgr = &mockkms.KeyManager{CreateKeyFn: func(kt kms.KeyType) (s string, i interface{}, e error) {
			if kt == kms.NISTP256ECDHKWType {
				return "", nil, errors.New(sampleWalletErr)
			}
			return "", nil, nil
		}}

		err = updateProfile(kmgr, &profile{EDVConf: &edvConf{}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create EDV encryption key pair")
	})
}

func TestNew(t *testing.T) {
	t.Run("test get wallet by user", func(t *testing.T) {
		mockctx := newMockProvider(t)
		// create a wallet
		err := CreateProfile(sampleUserID, mockctx, WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		wallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)
	})

	t.Run("test get wallet by invalid userID", func(t *testing.T) {
		mockctx := newMockProvider(t)
		err := CreateProfile(sampleUserID, mockctx, WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		wallet, err := New(sampleUserID+"invalid", mockctx)
		require.Empty(t, wallet)
		require.Error(t, err)
		require.Contains(t, err.Error(), "profile does not exist")
	})

	t.Run("test get wallet failure - save profile error", func(t *testing.T) {
		mockctx := newMockProvider(t)
		mockctx.StorageProviderValue = &mockstorage.MockStoreProvider{
			ErrOpenStoreHandle: fmt.Errorf(sampleWalletErr),
		}

		wallet, err := New(sampleUserID, mockctx)
		require.Error(t, err)
		require.Empty(t, wallet)
		require.Contains(t, err.Error(), sampleWalletErr)
	})
}

func TestWallet_OpenClose(t *testing.T) {
	t.Run("test open & close wallet using local kms passphrase", func(t *testing.T) {
		mockctx := newMockProvider(t)
		err := CreateProfile(sampleUserID, mockctx, WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		wallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		// get token
		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase), WithUnlockExpiry(500*time.Millisecond))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		// try again
		token, err = wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.Empty(t, token)
		require.Error(t, err)
		require.Equal(t, err, ErrAlreadyUnlocked)

		// close wallet
		require.True(t, wallet.Close())
		require.False(t, wallet.Close())

		// try to open with wrong passphrase
		token, err = wallet.Open(WithUnlockByPassphrase(samplePassPhrase + "wrong"))
		require.Empty(t, token)
		require.Error(t, err)
		require.Contains(t, err.Error(), "message authentication failed")
	})

	t.Run("test open & close wallet using secret lock service", func(t *testing.T) {
		mockctx := newMockProvider(t)
		masterLock, err := pbkdf2.NewMasterLock(samplePassPhrase, sha256.New, 0, nil)
		require.NoError(t, err)

		err = CreateProfile(sampleUserID, mockctx, WithSecretLockService(masterLock))
		require.NoError(t, err)

		wallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		// get token
		token, err := wallet.Open(WithUnlockBySecretLockService(masterLock))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		// try again
		token, err = wallet.Open(WithUnlockBySecretLockService(masterLock))
		require.Empty(t, token)
		require.Error(t, err)
		require.Equal(t, err, ErrAlreadyUnlocked)

		// close wallet
		require.True(t, wallet.Close())
		require.False(t, wallet.Close())

		// try to open with wrong secret lock service
		badLock, err := pbkdf2.NewMasterLock(samplePassPhrase+"wrong", sha256.New, 0, nil)
		require.NoError(t, err)

		token, err = wallet.Open(WithUnlockBySecretLockService(badLock))
		require.Empty(t, token)
		require.Error(t, err)
		require.Contains(t, err.Error(), "message authentication failed")
	})

	t.Run("test open & close wallet using remote kms URL & auth token option", func(t *testing.T) {
		mockctx := newMockProvider(t)
		err := CreateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL))
		require.NoError(t, err)

		wallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		// get token
		token, err := wallet.Open(WithUnlockByAuthorizationToken(sampleRemoteKMSAuth))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		// try again
		token, err = wallet.Open(WithUnlockByAuthorizationToken(sampleRemoteKMSAuth))
		require.Empty(t, token)
		require.Error(t, err)
		require.Equal(t, err, ErrAlreadyUnlocked)

		// close wallet
		require.True(t, wallet.Close())
		require.False(t, wallet.Close())
	})

	t.Run("test open & close wallet using remote kms URL & auth header option", func(t *testing.T) {
		mockctx := newMockProvider(t)
		err := CreateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL))
		require.NoError(t, err)

		wallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		// get token
		token, err := wallet.Open(WithUnlockWebKMSOptions(
			webkms.WithHeaders(func(req *http.Request) (*http.Header, error) {
				req.Header.Set("authorization", fmt.Sprintf("Bearer %s", sampleRemoteKMSAuth))

				return &req.Header, nil
			}),
		))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		// try again
		token, err = wallet.Open(WithUnlockWebKMSOptions(
			webkms.WithHeaders(func(req *http.Request) (*http.Header, error) {
				req.Header.Set("authorization", fmt.Sprintf("Bearer %s", sampleRemoteKMSAuth))

				return &req.Header, nil
			}),
		))
		require.Empty(t, token)
		require.Error(t, err)
		require.Equal(t, err, ErrAlreadyUnlocked)

		// close wallet
		require.True(t, wallet.Close())
		require.False(t, wallet.Close())
	})

	t.Run("test open & close wallet using EDV options", func(t *testing.T) {
		mockctx := newMockProvider(t)
		user := uuid.New().String()

		// create profile
		err := CreateProfile(user, mockctx, WithPassphrase(samplePassPhrase),
			WithEDVStorage(sampleEDVServerURL, sampleEDVVaultID, sampleEDVEncryptionKID, sampleEDVMacKID))
		require.NoError(t, err)

		// create key pairs
		err = CreateDataVaultKeyPairs(user, mockctx, WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)

		wallet, err := New(user, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase), WithUnlockEDVOptions(
			edv.WithFullDocumentsReturnedFromQueries(), edv.WithBatchEndpointExtension(),
		))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		// try again
		token, err = wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.Empty(t, token)
		require.Error(t, err)
		require.Equal(t, err, ErrAlreadyUnlocked)

		// close wallet
		require.True(t, wallet.Close())
		require.False(t, wallet.Close())
	})

	t.Run("test opened wallet between multliple instances", func(t *testing.T) {
		mockctx := newMockProvider(t)
		err := CreateProfile(sampleUserID, mockctx, WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		wallet1, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet1)

		// get token
		token, err := wallet1.Open(WithUnlockByPassphrase(samplePassPhrase), WithUnlockExpiry(500*time.Millisecond))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		// create new instance for same profile
		wallet2, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet2)

		// no need to unlock again since token is shared
		require.NoError(t, wallet2.Add(token, Metadata, []byte(sampleContentValid)))

		// close first instance
		wallet1.Close()
		require.Error(t, wallet2.Add(token, Metadata, []byte(sampleContentNoID)))
	})

	t.Run("test open wallet failure when store open fails", func(t *testing.T) {
		mockctx := newMockProvider(t)
		err := CreateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL))
		require.NoError(t, err)

		wallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		// corrupt content store
		wallet.contents = newContentStore(&mockstorage.MockStoreProvider{
			ErrOpenStoreHandle: fmt.Errorf(sampleWalletErr),
		}, createTestDocumentLoader(t), wallet.profile)

		// get token
		token, err := wallet.Open(WithUnlockByAuthorizationToken(sampleRemoteKMSAuth))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open store : sample wallet err")
		require.Empty(t, token)

		// close wallet
		require.False(t, wallet.Close())
	})
}

func TestWallet_Export(t *testing.T) {
	mockctx := newMockProvider(t)
	err := CreateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL))
	require.NoError(t, err)

	walletInstance, err := New(sampleUserID, mockctx)
	require.NotEmpty(t, walletInstance)
	require.NoError(t, err)

	result, err := walletInstance.Export("")
	require.Empty(t, result)
	require.Error(t, err)
	require.EqualError(t, err, toBeImplementedErr)
}

func TestWallet_Import(t *testing.T) {
	mockctx := newMockProvider(t)
	err := CreateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL))
	require.NoError(t, err)

	walletInstance, err := New(sampleUserID, mockctx)
	require.NotEmpty(t, walletInstance)
	require.NoError(t, err)

	err = walletInstance.Import("", nil)
	require.Error(t, err)
	require.EqualError(t, err, toBeImplementedErr)
}

func TestWallet_Add(t *testing.T) {
	mockctx := newMockProvider(t)
	err := CreateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL))
	require.NoError(t, err)

	walletInstance, err := New(sampleUserID, mockctx)
	require.NotEmpty(t, walletInstance)
	require.NoError(t, err)

	// wallet locked
	require.True(t, errors.Is(walletInstance.Add(sampleFakeTkn, Metadata, []byte(sampleContentValid)), ErrWalletLocked))

	// unlock wallet
	tkn, err := walletInstance.Open(WithUnlockByAuthorizationToken(sampleRemoteKMSAuth))
	require.NoError(t, err)

	// add data model to wallet
	err = walletInstance.Add(tkn, Metadata, []byte(sampleContentValid))
	require.NoError(t, err)
}

func TestWallet_Get(t *testing.T) {
	mockctx := newMockProvider(t)
	user := uuid.New().String()

	err := CreateProfile(user, mockctx, WithKeyServerURL(sampleKeyServerURL))
	require.NoError(t, err)

	walletInstance, err := New(user, mockctx)
	require.NotEmpty(t, walletInstance)
	require.NoError(t, err)

	tkn, err := walletInstance.Open(WithUnlockByAuthorizationToken(sampleRemoteKMSAuth))
	require.NoError(t, err)

	err = walletInstance.Add(tkn, Metadata, []byte(sampleContentValid))
	require.NoError(t, err)

	content, err := walletInstance.Get(tkn, Metadata, "did:example:123456789abcdefghi")
	require.NoError(t, err)
	require.NotEmpty(t, content)
	require.Equal(t, sampleContentValid, string(content))
}

func TestWallet_GetAll(t *testing.T) {
	const vcContent = `{
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "id": "%s",
      "issuer": {
        "id": "did:example:76e12ec712ebc6f1c221ebfeb1f"
      },
      "type": [
        "VerifiableCredential",
        "UniversityDegreeCredential"
      ]
    }`

	const orgCollection = `{
                    "@context": ["https://w3id.org/wallet/v1"],
                    "id": "did:example:acme123456789abcdefghi",
                    "type": "Organization",
                    "name": "Acme Corp.",
                    "image": "https://via.placeholder.com/150",
                    "description" : "A software company.",
                    "tags": ["professional", "organization"],
                    "correlation": ["4058a72a-9523-11ea-bb37-0242ac130002"]
                }`

	const collectionID = "did:example:acme123456789abcdefghi"

	user := uuid.New().String()

	mockctx := newMockProvider(t)
	err := CreateProfile(user, mockctx, WithPassphrase(samplePassPhrase))
	require.NoError(t, err)

	walletInstance, err := New(user, mockctx)
	require.NotEmpty(t, walletInstance)
	require.NoError(t, err)

	tkn, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
	require.NoError(t, err)

	const count = 5

	var taggedKeys, untaggedKeys [count]string

	// save test data without collection
	for i := 0; i < count; i++ {
		k := uuid.New().String()

		require.NoError(t, walletInstance.Add(tkn, Credential, []byte(fmt.Sprintf(vcContent, k))))

		untaggedKeys[i] = k
	}

	// save a collection
	require.NoError(t, walletInstance.Add(tkn, Collection, []byte(orgCollection)))

	// save contents by collection
	for i := 0; i < count; i++ {
		k := uuid.New().String()

		require.NoError(t, walletInstance.Add(tkn, Credential, []byte(fmt.Sprintf(vcContent, k)),
			AddByCollection(collectionID)))

		taggedKeys[i] = k
	}

	// get all by content
	vcs, err := walletInstance.GetAll(tkn, Credential)
	require.NoError(t, err)
	require.Len(t, vcs, count*2)

	// get all by content & collection
	vcs, err = walletInstance.GetAll(tkn, Credential, FilterByCollection(collectionID))
	require.NoError(t, err)
	require.Len(t, vcs, count)

	// delete one item under collection
	require.NoError(t, walletInstance.Remove(tkn, Credential, taggedKeys[0]))
	// get all by content & collection
	vcs, err = walletInstance.GetAll(tkn, Credential, FilterByCollection(collectionID))
	require.NoError(t, err)
	require.Len(t, vcs, count-1)

	// delete one item which is not under collection
	require.NoError(t, walletInstance.Remove(tkn, Credential, untaggedKeys[0]))
	// get all by content
	vcs, err = walletInstance.GetAll(tkn, Credential)
	require.NoError(t, err)
	require.Len(t, vcs, count*2-2)
}

func TestWallet_Remove(t *testing.T) {
	mockctx := newMockProvider(t)
	user := uuid.New().String()

	err := CreateProfile(user, mockctx, WithKeyServerURL(sampleKeyServerURL))
	require.NoError(t, err)

	walletInstance, err := New(user, mockctx)
	require.NotEmpty(t, walletInstance)
	require.NoError(t, err)

	tkn, err := walletInstance.Open(WithUnlockByAuthorizationToken(sampleRemoteKMSAuth))
	require.NoError(t, err)

	err = walletInstance.Add(tkn, Metadata, []byte(sampleContentValid))
	require.NoError(t, err)

	content, err := walletInstance.Get(tkn, Metadata, "did:example:123456789abcdefghi")
	require.NoError(t, err)
	require.NotEmpty(t, content)

	err = walletInstance.Remove(tkn, Metadata, "did:example:123456789abcdefghi")
	require.NoError(t, err)

	content, err = walletInstance.Get(tkn, Metadata, "did:example:123456789abcdefghi")
	require.Empty(t, content)
	require.Error(t, err)
	require.True(t, errors.Is(err, storage.ErrDataNotFound))
}

func TestWallet_Query(t *testing.T) {
	mockctx := newMockProvider(t)
	user := uuid.New().String()

	mockctx.VDRegistryValue = &mockvdr.MockVDRegistry{
		ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
			if strings.HasPrefix(didID, "did:key:") {
				k := key.New()

				d, e := k.Read(didID)
				if e != nil {
					return nil, e
				}

				return d, nil
			}

			return nil, fmt.Errorf("did not found")
		},
	}

	err := CreateProfile(user, mockctx, WithKeyServerURL(sampleKeyServerURL))
	require.NoError(t, err)

	vc1, err := (&verifiable.Credential{
		Context: []string{verifiable.ContextURI},
		Types:   []string{verifiable.VCType},
		ID:      "http://example.edu/credentials/9999",
		CustomFields: map[string]interface{}{
			"first_name": "Jesse",
		},
		Issued: &util.TimeWrapper{
			Time: time.Now(),
		},
		Issuer: verifiable.Issuer{
			ID: "did:example:76e12ec712ebc6f1c221ebfeb1f",
		},
		Subject: uuid.New().String(),
	}).MarshalJSON()
	require.NoError(t, err)

	sampleVC := fmt.Sprintf(sampleVCFmt, verifiable.ContextURI)
	vcForQuery := []byte(strings.ReplaceAll(sampleVC,
		"http://example.edu/credentials/1872", "http://example.edu/credentials/1879"))
	vcForDerive := []byte(sampleBBSVC)

	walletInstance, err := New(user, mockctx)
	require.NotEmpty(t, walletInstance)
	require.NoError(t, err)

	tkn, err := walletInstance.Open(WithUnlockByAuthorizationToken(sampleRemoteKMSAuth))
	require.NoError(t, err)

	require.NoError(t, walletInstance.Add(tkn, Credential, vc1))
	require.NoError(t, walletInstance.Add(tkn, Credential, vcForQuery))
	require.NoError(t, walletInstance.Add(tkn, Credential, vcForDerive))

	pd := &presexch.PresentationDefinition{
		ID: uuid.New().String(),
		InputDescriptors: []*presexch.InputDescriptor{{
			ID: uuid.New().String(),
			Schema: []*presexch.Schema{{
				URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
			}},
			Constraints: &presexch.Constraints{
				Fields: []*presexch.Field{{
					Path: []string{"$.first_name"},
				}},
			},
		}},
	}

	// presentation exchange
	pdJSON, err := json.Marshal(pd)
	require.NoError(t, err)
	require.NotEmpty(t, pdJSON)

	// query by example
	queryByExample := []byte(fmt.Sprintf(sampleQueryByExFmt, verifiable.ContextURI))
	// query by frame
	queryByFrame := []byte(sampleQueryByFrame)

	t.Run("test wallet queries", func(t *testing.T) {
		tests := []struct {
			name        string
			params      []*QueryParams
			resultCount int
			vcCount     map[int]int
			error       string
		}{
			{
				name: "query by presentation exchange - success",
				params: []*QueryParams{
					{Type: "PresentationExchange", Query: []json.RawMessage{pdJSON}},
				},
				resultCount: 1,
				vcCount:     map[int]int{0: 1},
			},
			{
				name: "query by example - success",
				params: []*QueryParams{
					{Type: "QueryByExample", Query: []json.RawMessage{queryByExample}},
				},
				resultCount: 1,
				vcCount:     map[int]int{0: 1},
			},
			{
				name: "query by frame - success",
				params: []*QueryParams{
					{Type: "QueryByFrame", Query: []json.RawMessage{queryByFrame}},
				},
				resultCount: 1,
				vcCount:     map[int]int{0: 1},
			},
			{
				name: "DIDAuth - success",
				params: []*QueryParams{
					{Type: "DIDAuth"},
				},
				resultCount: 1,
				vcCount:     map[int]int{0: 0},
			},
			{
				name: "multiple queries - success",
				params: []*QueryParams{
					{Type: "PresentationExchange", Query: []json.RawMessage{pdJSON}},
					{Type: "QueryByExample", Query: []json.RawMessage{queryByExample}},
					{Type: "QueryByFrame", Query: []json.RawMessage{queryByFrame}},
				},
				resultCount: 2,
				vcCount:     map[int]int{0: 1, 1: 2},
			},
			{
				name: "invalid query type",
				params: []*QueryParams{
					{Type: "invalid"},
				},
				error: "unsupported query type",
			},
			{
				name:   "empty query type",
				params: []*QueryParams{},
				error:  "no result found",
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.name, func(t *testing.T) {
				results, err := walletInstance.Query(tkn, tc.params...)

				if tc.error != "" {
					require.Empty(t, results)
					require.Error(t, err)
					require.Contains(t, err.Error(), tc.error)

					return
				}

				require.NoError(t, err)
				require.Len(t, results, tc.resultCount)

				for i, result := range results {
					require.Len(t, result.Credentials(), tc.vcCount[i])
				}
			})
		}
	})

	t.Run("test get all error", func(t *testing.T) {
		user := uuid.New().String()
		mockctxInvalid := newMockProvider(t)

		sp := getMockStorageProvider()

		sp.MockStoreProvider.Store.ErrQuery = errors.New(sampleContenttErr)
		mockctxInvalid.StorageProviderValue = sp

		err := CreateProfile(user, mockctxInvalid, WithKeyServerURL(sampleKeyServerURL))
		require.NoError(t, err)

		walletInstanceInvalid, err := New(user, mockctxInvalid)
		require.NoError(t, err)
		require.NotEmpty(t, walletInstanceInvalid)

		result, err := walletInstanceInvalid.Query(sampleFakeTkn, &QueryParams{Type: "QueryByFrame"})
		require.True(t, errors.Is(err, ErrWalletLocked))
		require.Empty(t, result)

		tk, err := walletInstanceInvalid.Open(WithUnlockByAuthorizationToken(sampleRemoteKMSAuth))
		require.NoError(t, err)

		result, err = walletInstanceInvalid.Query(tk, &QueryParams{Type: "QueryByFrame"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to query credentials")
		require.Contains(t, err.Error(), sampleContenttErr)
		require.Empty(t, result)
	})
}

func TestWallet_Query_TwoInputDescriptorsWithTwoCredentialsWithOverlap(t *testing.T) {
	mockctx := newMockProvider(t)
	user := uuid.New().String()

	err := CreateProfile(user, mockctx, WithKeyServerURL(sampleKeyServerURL))
	require.NoError(t, err)

	walletInstance, err := New(user, mockctx)
	require.NotEmpty(t, walletInstance)
	require.NoError(t, err)

	tkn, err := walletInstance.Open(WithUnlockByAuthorizationToken(sampleRemoteKMSAuth))
	require.NoError(t, err)

	require.NoError(t, walletInstance.Add(tkn, Credential, []byte(testJSONLD)))
	require.NoError(t, walletInstance.Add(tkn, Credential, []byte(testSDJWT)))

	var pd presexch.PresentationDefinition

	err = json.Unmarshal([]byte(testPD), &pd)
	require.NoError(t, err)

	vps, err := walletInstance.Query(tkn, &QueryParams{
		Type:  "PresentationExchange",
		Query: []json.RawMessage{[]byte(testPD)},
	})

	require.NoError(t, err)

	for _, vp := range vps {
		vpBytes, err := json.Marshal(vp)
		require.NoError(t, err)

		require.False(t, strings.Contains(string(vpBytes), "[2]"))
	}
}

func TestWallet_Issue(t *testing.T) {
	user := uuid.New().String()
	customVDR := &mockvdr.MockVDRegistry{
		ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
			if didID == sampleInvalidDIDID {
				d, e := did.ParseDocument(testdata.SampleInvalidDID)
				require.NoError(t, e)

				return &did.DocResolution{DIDDocument: d}, nil
			} else if strings.HasPrefix(didID, "did:key:") {
				k := key.New()

				d, e := k.Read(didID)
				if e != nil {
					return nil, e
				}

				return d, nil
			}

			return nil, fmt.Errorf("did not found")
		},
	}

	mockctx := newMockProvider(t)
	mockctx.VDRegistryValue = customVDR
	mockctx.CryptoValue = &cryptomock.Crypto{}

	err := CreateProfile(user, mockctx, WithPassphrase(samplePassPhrase))
	require.NoError(t, err)

	t.Run("Test VC wallet issue using controller - success", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		// unlock wallet
		authToken, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, authToken)

		defer walletInstance.Close()

		// import keys manually
		session, err := sessionManager().getSession(authToken)
		require.NotEmpty(t, session)
		require.NoError(t, err)

		kmgr := session.KeyManager
		require.NotEmpty(t, kmgr)

		edPriv := ed25519.PrivateKey(base58.Decode(pkBase58))
		// nolint: errcheck, gosec
		kmgr.ImportPrivateKey(edPriv, kms.ED25519, kms.WithKeyID(kid))

		// sign with just controller
		result, err := walletInstance.Issue(authToken, testdata.SampleUDCVC, &ProofOptions{
			Controller: didKey,
		})
		require.NoError(t, err)
		require.NotEmpty(t, result)
		require.Len(t, result.Proofs, 1)
	})

	t.Run("Test VC wallet issue JSONWebSignature2020 using controller - success", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		// unlock wallet
		authToken, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, authToken)

		defer walletInstance.Close()

		// import keys manually
		session, err := sessionManager().getSession(authToken)
		require.NotEmpty(t, session)
		require.NoError(t, err)
		edPriv := ed25519.PrivateKey(base58.Decode(pkBase58))
		// nolint: errcheck, gosec
		session.KeyManager.ImportPrivateKey(edPriv, kms.ED25519, kms.WithKeyID(kid))

		// sign with just controller
		result, err := walletInstance.Issue(authToken, testdata.SampleUDCVC, &ProofOptions{
			Controller: didKey,
			ProofType:  JSONWebSignature2020,
		})
		require.NoError(t, err)
		require.NotEmpty(t, result)
		require.Len(t, result.Proofs, 1)
	})

	t.Run("Test VC wallet issue JWT VC using controller - success", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		walletInstance.walletCrypto = &cryptomock.Crypto{
			SignValue: []byte("abcdefg"),
		}

		// unlock wallet
		authToken, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, authToken)

		defer walletInstance.Close()

		// import keys manually
		session, err := sessionManager().getSession(authToken)
		require.NotEmpty(t, session)
		require.NoError(t, err)
		edPriv := ed25519.PrivateKey(base58.Decode(pkBase58))
		// nolint: errcheck, gosec
		session.KeyManager.ImportPrivateKey(edPriv, kms.ED25519, kms.WithKeyID(kid))

		// sign with just controller
		result, err := walletInstance.Issue(authToken, testdata.SampleUDCVC, &ProofOptions{
			Controller:  didKey,
			ProofFormat: ExternalJWTProofFormat,
			ProofType:   JSONWebSignature2020,
		})
		require.NoError(t, err)
		require.NotEmpty(t, result)

		require.NotEqual(t, "", result.JWT)

		vcExpected, err := verifiable.ParseCredential(testdata.SampleUDCVC, verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(walletInstance.jsonldDocumentLoader))
		require.NoError(t, err)

		vcActual, err := verifiable.ParseCredential([]byte(result.JWT), verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(walletInstance.jsonldDocumentLoader))
		require.NoError(t, err)

		require.Equal(t, result.JWT, vcActual.JWT)
		vcActual.JWT = ""

		require.Equal(t, vcExpected, vcActual)
	})

	t.Run("Test VC wallet issue JWT VC - fail to generate claims", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		walletInstance.walletCrypto = &cryptomock.Crypto{
			SignValue: []byte("abcdefg"),
		}

		// unlock wallet
		authToken, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, authToken)

		defer walletInstance.Close()

		// import keys manually
		session, err := sessionManager().getSession(authToken)
		require.NotEmpty(t, session)
		require.NoError(t, err)
		edPriv := ed25519.PrivateKey(base58.Decode(pkBase58))
		// nolint: errcheck, gosec
		session.KeyManager.ImportPrivateKey(edPriv, kms.ED25519, kms.WithKeyID(kid))

		minimalVC := &verifiable.Credential{
			Context: []string{verifiable.ContextURI},
			ID:      "https://foo.bar",
			Issued:  util.NewTime(time.Now()),
			Types:   []string{verifiable.VCType},
			Subject: []verifiable.Subject{
				{
					ID: "foo", // with multiple subjects, VC can't be converted to JWT claims.
				},
				{
					ID: "bar",
				},
			},
			Issuer: verifiable.Issuer{
				ID: "https://bar.baz",
			},
		}

		vcBytes, err := minimalVC.MarshalJSON()
		require.NoError(t, err)

		// sign with just controller
		_, err = walletInstance.Issue(authToken, vcBytes, &ProofOptions{
			Controller:  didKey,
			ProofFormat: ExternalJWTProofFormat,
			ProofType:   JSONWebSignature2020,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to generate JWT claims for VC")
	})

	t.Run("Test VC wallet issue JWT VC - fail to create JWT", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		expectErr := errors.New("expected error")

		walletInstance.walletCrypto = &cryptomock.Crypto{
			SignErr: expectErr,
		}

		// unlock wallet
		authToken, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, authToken)

		defer walletInstance.Close()

		// import keys manually
		session, err := sessionManager().getSession(authToken)
		require.NotEmpty(t, session)
		require.NoError(t, err)
		edPriv := ed25519.PrivateKey(base58.Decode(pkBase58))
		// nolint: errcheck, gosec
		session.KeyManager.ImportPrivateKey(edPriv, kms.ED25519, kms.WithKeyID(kid))

		_, err = walletInstance.Issue(authToken, testdata.SampleUDCVC, &ProofOptions{
			Controller:  didKey,
			ProofFormat: ExternalJWTProofFormat,
			ProofType:   JSONWebSignature2020,
		})
		require.Error(t, err)
		require.ErrorIs(t, err, expectErr)
		require.Contains(t, err.Error(), "failed to generate JWT VC")
	})

	t.Run("Test VC wallet issue using verification method - success", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		// unlock wallet
		authToken, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, authToken)

		defer walletInstance.Close()

		// import keys manually
		session, err := sessionManager().getSession(authToken)
		require.NotEmpty(t, session)
		require.NoError(t, err)

		edPriv := ed25519.PrivateKey(base58.Decode(pkBase58))
		// nolint: errcheck, gosec
		session.KeyManager.ImportPrivateKey(edPriv, kms.ED25519, kms.WithKeyID(kid))

		// issue
		result, err := walletInstance.Issue(authToken, testdata.SampleUDCVC, &ProofOptions{
			Controller:         didKey,
			VerificationMethod: sampleVerificationMethod,
		})
		require.NoError(t, err)
		require.NotEmpty(t, result)
		require.Len(t, result.Proofs, 1)
	})

	t.Run("Test VC wallet issue using all options - success", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		// unlock wallet
		authToken, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, authToken)

		defer walletInstance.Close()

		// import keys manually
		session, err := sessionManager().getSession(authToken)
		require.NotEmpty(t, session)
		require.NoError(t, err)

		kmgr := session.KeyManager
		require.NotEmpty(t, kmgr)

		edPriv := ed25519.PrivateKey(base58.Decode(pkBase58))
		// nolint: errcheck, gosec
		kmgr.ImportPrivateKey(edPriv, kms.ED25519, kms.WithKeyID(kid))

		// issue credential
		proofRepr := verifiable.SignatureJWS
		vm := sampleVerificationMethod
		created, err := time.Parse("2006-01-02", sampleCreatedDate)
		require.NoError(t, err)

		result, err := walletInstance.Issue(authToken, testdata.SampleUDCVC, &ProofOptions{
			Controller:          didKey,
			VerificationMethod:  vm,
			ProofType:           JSONWebSignature2020,
			Challenge:           sampleChallenge,
			Domain:              sampleDomain,
			Created:             &created,
			ProofRepresentation: &proofRepr,
		})
		require.NoError(t, err)
		require.NotEmpty(t, result)
		require.Len(t, result.Proofs, 1)

		require.Equal(t, result.Proofs[0]["challenge"], sampleChallenge)
		require.Equal(t, result.Proofs[0]["created"], "2020-12-25T00:00:00Z")
		require.Equal(t, result.Proofs[0]["domain"], sampleDomain)
		require.NotEmpty(t, result.Proofs[0]["jws"])
		require.Equal(t, result.Proofs[0]["proofPurpose"], "assertionMethod")
		require.Equal(t, result.Proofs[0]["type"], JSONWebSignature2020)
		require.Equal(t, result.Proofs[0]["verificationMethod"], vm)
	})

	t.Run("Test VC wallet issue using BBS - success", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		// unlock wallet
		authToken, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, authToken)

		defer walletInstance.Close()

		// import keys manually
		session, err := sessionManager().getSession(authToken)
		require.NotEmpty(t, session)
		require.NoError(t, err)

		kmgr := session.KeyManager
		require.NotEmpty(t, kmgr)

		privKeyBBS, err := bbs12381g2pub.UnmarshalPrivateKey(base58.Decode(pkBBSBase58))
		require.NoError(t, err)
		// nolint: errcheck, gosec
		kmgr.ImportPrivateKey(privKeyBBS, kms.BLS12381G2Type, kms.WithKeyID(keyIDBBS))

		// sign with just controller
		proofRepr := verifiable.SignatureProofValue
		result, err := walletInstance.Issue(authToken, testdata.SampleUDCVC, &ProofOptions{
			Controller:          didKeyBBS,
			ProofType:           BbsBlsSignature2020,
			ProofRepresentation: &proofRepr,
		})
		require.NoError(t, err)
		require.NotEmpty(t, result)
		require.Len(t, result.Proofs, 1)
	})

	t.Run("Test VC wallet issue using stored DID - success", func(t *testing.T) {
		mockctx1 := newMockProvider(t)
		mockctx1.VDRegistryValue = &mockvdr.MockVDRegistry{}
		mockctx1.CryptoValue = &cryptomock.Crypto{}

		err := CreateProfile(user, mockctx1, WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		walletInstance, err := New(user, mockctx1)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		// unlock wallet
		authToken, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, authToken)

		defer walletInstance.Close()

		// import keys manually
		session, err := sessionManager().getSession(authToken)
		require.NotEmpty(t, session)
		require.NoError(t, err)

		kmgr := session.KeyManager
		require.NotEmpty(t, kmgr)

		edPriv := ed25519.PrivateKey(base58.Decode(pkBase58))
		// nolint: errcheck, gosec
		kmgr.ImportPrivateKey(edPriv, kms.ED25519, kms.WithKeyID(kid))

		// save DID Resolution response
		err = walletInstance.Add(authToken, DIDResolutionResponse, testdata.SampleDocResolutionResponse)
		require.NoError(t, err)

		// sign with just controller
		result, err := walletInstance.Issue(authToken, testdata.SampleUDCVC, &ProofOptions{
			Controller: didKey,
		})
		require.NoError(t, err)
		require.NotEmpty(t, result)
		require.Len(t, result.Proofs, 1)
	})

	t.Run("Test VC wallet issue failure - invalid VC", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		result, err := walletInstance.Issue(sampleFakeTkn, []byte("--"), &ProofOptions{})
		require.Empty(t, result)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse credential")
	})

	t.Run("Test VC wallet issue failure - proof option validation", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		// unlock wallet
		authToken, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, authToken)

		defer walletInstance.Close()

		// no controller
		result, err := walletInstance.Issue(authToken, testdata.SampleUDCVC, &ProofOptions{})
		require.Empty(t, result)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid proof option, 'controller' is required")

		// DID not found
		result, err = walletInstance.Issue(authToken, testdata.SampleUDCVC, &ProofOptions{
			Controller: "did:example:1234",
		})
		require.Empty(t, result)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to prepare proof: did not found")

		// no assertion method
		result, err = walletInstance.Issue(authToken, testdata.SampleUDCVC, &ProofOptions{
			Controller: sampleInvalidDIDID,
		})
		require.Empty(t, result)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to find 'assertionMethod' for given verification method")
	})

	t.Run("Test VC wallet issue failure - add proof errors", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		// wallet locked
		result, err := walletInstance.Issue(sampleFakeTkn, testdata.SampleUDCVC, &ProofOptions{
			Controller: didKey,
		})
		require.Empty(t, result)
		require.Error(t, err)
		require.Contains(t, err.Error(), "wallet locked")

		// get token
		authToken, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, authToken)

		defer walletInstance.Close()

		// key not found
		result, err = walletInstance.Issue(authToken, testdata.SampleUDCVC, &ProofOptions{
			Controller: "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
		})
		require.Empty(t, result)
		require.Contains(t, err.Error(), "cannot read data for keysetID")

		// import keys manually
		session, err := sessionManager().getSession(authToken)
		require.NotEmpty(t, session)
		require.NoError(t, err)

		kmgr := session.KeyManager
		require.NotEmpty(t, kmgr)

		edPriv := ed25519.PrivateKey(base58.Decode(pkBase58))
		// nolint: errcheck, gosec
		kmgr.ImportPrivateKey(edPriv, kms.ED25519, kms.WithKeyID(kid))

		// invalid signature type
		result, err = walletInstance.Issue(authToken, testdata.SampleUDCVC, &ProofOptions{
			Controller: didKey,
			ProofType:  "invalid",
		})
		require.Empty(t, result)
		require.Contains(t, err.Error(), " unsupported signature type 'invalid'")

		// wrong key type
		result, err = walletInstance.Issue(authToken, testdata.SampleUDCVC, &ProofOptions{
			Controller: didKey,
			ProofType:  BbsBlsSignature2020,
		})
		require.Empty(t, result)
		require.Contains(t, err.Error(), "failed to add linked data proof")
	})
}

func TestWallet_Prove(t *testing.T) {
	user := uuid.New().String()
	customVDR := &mockvdr.MockVDRegistry{
		ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
			if didID == sampleInvalidDIDID {
				d, e := did.ParseDocument(testdata.SampleInvalidDID)
				require.NoError(t, e)

				return &did.DocResolution{DIDDocument: d}, nil
			} else if strings.HasPrefix(didID, "did:key:") {
				k := key.New()

				d, e := k.Read(didID)
				if e != nil {
					return nil, e
				}

				return d, nil
			}

			return nil, fmt.Errorf("did not found")
		},
	}

	mockctx := newMockProvider(t)
	mockctx.VDRegistryValue = customVDR
	mockctx.CryptoValue = &cryptomock.Crypto{
		SignValue: []byte("abcdefg"),
	}

	// create profile
	err := CreateProfile(user, mockctx, WithPassphrase(samplePassPhrase))
	require.NoError(t, err)

	// prepare VCs for tests
	vcs := make(map[string]*verifiable.Credential, 2)
	walletForIssue, err := New(user, mockctx)
	require.NotEmpty(t, walletForIssue)
	require.NoError(t, err)

	issuerToken, err := walletForIssue.Open(WithUnlockByPassphrase(samplePassPhrase))
	require.NoError(t, err)
	require.NotEmpty(t, issuerToken)

	// import ED25519 & BLS12381G2Type keys manually
	session, err := sessionManager().getSession(issuerToken)
	require.NotEmpty(t, session)
	require.NoError(t, err)

	kmgr := session.KeyManager
	require.NotEmpty(t, kmgr)

	edPriv := ed25519.PrivateKey(base58.Decode(pkBase58))
	// nolint: errcheck, gosec
	kmgr.ImportPrivateKey(edPriv, kms.ED25519, kms.WithKeyID(kid))

	privKeyBBS, err := bbs12381g2pub.UnmarshalPrivateKey(base58.Decode(pkBBSBase58))
	require.NoError(t, err)
	// nolint: errcheck, gosec
	kmgr.ImportPrivateKey(privKeyBBS, kms.BLS12381G2Type, kms.WithKeyID(keyIDBBS))

	// issue a credential with Ed25519Signature2018
	result, err := walletForIssue.Issue(issuerToken, testdata.SampleUDCVC, &ProofOptions{
		Controller: didKey,
	})
	require.NoError(t, err)
	require.NotEmpty(t, result)
	require.Len(t, result.Proofs, 1)
	vcs["edvc"] = result

	// issue a credential with BbsBlsSignature2020
	proofRepr := verifiable.SignatureProofValue
	result, err = walletForIssue.Issue(issuerToken, testdata.SampleUDCVC, &ProofOptions{
		Controller:          didKeyBBS,
		ProofType:           BbsBlsSignature2020,
		ProofRepresentation: &proofRepr,
	})
	require.NoError(t, err)
	require.NotEmpty(t, result)
	require.Len(t, result.Proofs, 1)
	vcs["bbsvc"] = result

	templateCred, err := verifiable.ParseCredential(testdata.SampleUDCVC, verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(walletForIssue.jsonldDocumentLoader))
	require.NoError(t, err)

	templateCred.Issuer.ID = didKey

	templateData, err := templateCred.MarshalJSON()
	require.NoError(t, err)

	// issue a JWT credential
	result, err = walletForIssue.Issue(issuerToken, templateData, &ProofOptions{
		Controller:         didKey,
		VerificationMethod: sampleVerificationMethod,
		ProofFormat:        ExternalJWTProofFormat,
	})
	require.NoError(t, err)
	require.NotEmpty(t, result)
	require.NotEqual(t, "", result.JWT)
	require.True(t, jwt.IsJWS(result.JWT))

	vcs["jwtvc"] = result

	walletForIssue.Close()

	t.Run("Test prove using stored & raw credential - success", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		// unlock wallet
		authToken, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, authToken)

		defer walletInstance.Close()

		// save one VC in store
		cleanup := addCredentialsToWallet(t, walletInstance, authToken, vcs["edvc"])
		defer cleanup()

		// import keys manually for signing presentation
		session, err := sessionManager().getSession(authToken)
		require.NotEmpty(t, session)
		require.NoError(t, err)

		kmgr := session.KeyManager
		require.NotEmpty(t, kmgr)

		edPriv := ed25519.PrivateKey(base58.Decode(pkBase58))
		// nolint: errcheck, gosec
		kmgr.ImportPrivateKey(edPriv, kms.ED25519, kms.WithKeyID(kid))

		edVCBytes, err := json.Marshal(vcs["edvc"])
		require.NoError(t, err)

		bbsVCBytes, err := json.Marshal(vcs["bbsvc"])
		require.NoError(t, err)

		jwtVCBytes, err := json.Marshal(vcs["jwtvc"])
		require.NoError(t, err)

		// sign with just controller (one stored & one raw bytes)
		result, err := walletInstance.Prove(authToken,
			&ProofOptions{Controller: didKey},
			WithStoredCredentialsToProve(vcs["edvc"].ID),
			WithRawCredentialsToProve(bbsVCBytes, jwtVCBytes),
			WithCredentialsToProve(vcs["edvc"]),
		)
		require.NoError(t, err)
		require.NotEmpty(t, result)
		require.Len(t, result.Proofs, 1)
		require.Len(t, result.Credentials(), 4)
		require.Equal(t, result.Holder, didKey)

		// sign with just controller with all raw credentials
		result, err = walletInstance.Prove(authToken,
			&ProofOptions{Controller: didKey},
			WithRawCredentialsToProve(edVCBytes, bbsVCBytes, jwtVCBytes),
		)
		require.NoError(t, err)
		require.NotEmpty(t, result)
		require.Len(t, result.Proofs, 1)
		require.Equal(t, result.Holder, didKey)
	})

	t.Run("Test prove using presentation - success", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		// unlock wallet
		authToken, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, authToken)

		defer walletInstance.Close()

		// save one VC in store
		cleanup := addCredentialsToWallet(t, walletInstance, authToken, vcs["edvc"])
		defer cleanup()

		// import keys manually for signing presentation
		session, err := sessionManager().getSession(authToken)
		require.NotEmpty(t, session)
		require.NoError(t, err)

		kmgr := session.KeyManager
		require.NotEmpty(t, kmgr)

		edPriv := ed25519.PrivateKey(base58.Decode(pkBase58))
		// nolint: errcheck, gosec
		kmgr.ImportPrivateKey(edPriv, kms.ED25519, kms.WithKeyID(kid))

		bbsVCBytes, err := json.Marshal(vcs["bbsvc"])
		require.NoError(t, err)

		pres, err := verifiable.NewPresentation(verifiable.WithCredentials(vcs["edvc"]))
		require.NoError(t, err)
		require.NotEmpty(t, pres)

		// sign with just controller
		result, err := walletInstance.Prove(authToken,
			&ProofOptions{Controller: didKey},
			WithPresentationToProve(pres),
		)
		require.NoError(t, err)
		require.NotEmpty(t, result)
		require.Len(t, result.Proofs, 1)
		require.Len(t, result.Credentials(), 1)
		require.Equal(t, result.Holder, didKey)

		// sign with just controller (sign with presentation & credentials)
		pres, err = verifiable.NewPresentation(verifiable.WithCredentials(vcs["edvc"]))
		require.NoError(t, err)
		require.NotEmpty(t, pres)

		result, err = walletInstance.Prove(authToken,
			&ProofOptions{Controller: didKey},
			WithPresentationToProve(pres),
			WithStoredCredentialsToProve(vcs["edvc"].ID),
			WithRawCredentialsToProve(bbsVCBytes),
		)

		require.NoError(t, err)
		require.NotEmpty(t, result)
		require.Len(t, result.Proofs, 1)
		require.Len(t, result.Credentials(), 3)
		require.Equal(t, result.Holder, didKey)
	})

	t.Run("Test prove using raw presentation - success", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		// unlock wallet
		authToken, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, authToken)

		defer walletInstance.Close()

		// save one VC in store
		cleanup := addCredentialsToWallet(t, walletInstance, authToken, vcs["edvc"])
		defer cleanup()

		// import keys manually for signing presentation
		session, err := sessionManager().getSession(authToken)
		require.NotEmpty(t, session)
		require.NoError(t, err)

		kmgr := session.KeyManager
		require.NotEmpty(t, kmgr)

		edPriv := ed25519.PrivateKey(base58.Decode(pkBase58))
		// nolint: errcheck, gosec
		kmgr.ImportPrivateKey(edPriv, kms.ED25519, kms.WithKeyID(kid))

		bbsVCBytes, err := json.Marshal(vcs["bbsvc"])
		require.NoError(t, err)

		pres, err := verifiable.NewPresentation(verifiable.WithCredentials(vcs["edvc"]))
		require.NoError(t, err)
		require.NotEmpty(t, pres)

		// sign with just controller
		result, err := walletInstance.Prove(authToken,
			&ProofOptions{Controller: didKey},
			WithPresentationToProve(pres),
		)
		require.NoError(t, err)
		require.NotEmpty(t, result)
		require.Len(t, result.Proofs, 1)
		require.Len(t, result.Credentials(), 1)
		require.Equal(t, result.Holder, didKey)

		// sign with just controller (sign with presentation & credentials)
		pres, err = verifiable.NewPresentation(verifiable.WithCredentials(vcs["edvc"]))
		require.NoError(t, err)
		require.NotEmpty(t, pres)

		rawPres, err := pres.MarshalJSON()
		require.NoError(t, err)

		result, err = walletInstance.Prove(authToken,
			&ProofOptions{Controller: didKey},
			WithRawPresentationToProve(rawPres),
			WithStoredCredentialsToProve(vcs["edvc"].ID),
			WithRawCredentialsToProve(bbsVCBytes),
		)

		require.NoError(t, err)
		require.NotEmpty(t, result)
		require.Len(t, result.Proofs, 1)
		require.Len(t, result.Credentials(), 3)
		require.Equal(t, result.Holder, didKey)
	})

	t.Run("Test prove using various proof options - success", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		// unlock wallet
		authToken, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, authToken)

		defer walletInstance.Close()

		// save all VCs in store
		cleanup := addCredentialsToWallet(t, walletInstance, authToken, vcs["edvc"], vcs["bbsvc"])
		defer cleanup()

		// import keys manually for signing presentation
		session, err := sessionManager().getSession(authToken)
		require.NotEmpty(t, session)
		require.NoError(t, err)

		kmgr := session.KeyManager
		require.NotEmpty(t, kmgr)

		edPriv := ed25519.PrivateKey(base58.Decode(pkBase58))
		// nolint: errcheck, gosec
		kmgr.ImportPrivateKey(edPriv, kms.ED25519, kms.WithKeyID(kid))

		// prepare opts
		proofRepr := verifiable.SignatureJWS
		vm := sampleVerificationMethod
		created, err := time.Parse("2006-01-02", sampleCreatedDate)
		require.NoError(t, err)

		// sign with just controller (one stored & one raw)
		result, err := walletInstance.Prove(authToken, &ProofOptions{
			Controller:          didKey,
			VerificationMethod:  vm,
			ProofType:           JSONWebSignature2020,
			Challenge:           sampleChallenge,
			Domain:              sampleDomain,
			Created:             &created,
			ProofRepresentation: &proofRepr,
		}, WithStoredCredentialsToProve(vcs["edvc"].ID, vcs["bbsvc"].ID))
		require.NoError(t, err)
		require.NotEmpty(t, result)
		require.Len(t, result.Proofs, 1)

		require.Equal(t, result.Proofs[0]["challenge"], sampleChallenge)
		require.Equal(t, result.Proofs[0]["created"], "2020-12-25T00:00:00Z")
		require.Equal(t, result.Proofs[0]["domain"], sampleDomain)
		require.NotEmpty(t, result.Proofs[0]["jws"])
		require.Equal(t, result.Proofs[0]["proofPurpose"], "authentication")
		require.Equal(t, result.Proofs[0]["type"], JSONWebSignature2020)
		require.Equal(t, result.Proofs[0]["verificationMethod"], vm)
	})

	t.Run("Test prove using JWT - success", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		// unlock wallet
		authToken, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, authToken)

		defer walletInstance.Close()

		// save one VC in store
		cleanup := addCredentialsToWallet(t, walletInstance, authToken, vcs["jwtvc"])
		defer cleanup()

		// import keys manually for signing presentation
		session, err := sessionManager().getSession(authToken)
		require.NotEmpty(t, session)
		require.NoError(t, err)

		kmgr := session.KeyManager
		require.NotEmpty(t, kmgr)

		edPriv := ed25519.PrivateKey(base58.Decode(pkBase58))
		// nolint: errcheck, gosec
		kmgr.ImportPrivateKey(edPriv, kms.ED25519, kms.WithKeyID(kid))

		// sign with just controller (one stored & one raw bytes)
		result, err := walletInstance.Prove(authToken,
			&ProofOptions{
				Controller:  didKey,
				ProofFormat: ExternalJWTProofFormat,
			},
			WithStoredCredentialsToProve(vcs["jwtvc"].ID),
		)
		require.NoError(t, err)
		require.NotEmpty(t, result)
		require.Len(t, result.Proofs, 0)
		require.Len(t, result.Credentials(), 1)
		require.Equal(t, result.Holder, didKey)
		require.NotEmpty(t, result.JWT)
	})

	t.Run("Test prove without credentials (DIDAuth) - success", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		// unlock wallet
		authToken, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, authToken)

		defer walletInstance.Close()

		// import keys manually for signing presentation
		session, err := sessionManager().getSession(authToken)
		require.NotEmpty(t, session)
		require.NoError(t, err)

		kmgr := session.KeyManager
		require.NotEmpty(t, kmgr)

		edPriv := ed25519.PrivateKey(base58.Decode(pkBase58))
		// nolint: errcheck, gosec
		kmgr.ImportPrivateKey(edPriv, kms.ED25519, kms.WithKeyID(kid))

		// prepare opts
		proofRepr := verifiable.SignatureJWS
		vm := sampleVerificationMethod
		created, err := time.Parse("2006-01-02", sampleCreatedDate)
		require.NoError(t, err)

		result, err := walletInstance.Prove(authToken, &ProofOptions{
			Controller:          didKey,
			VerificationMethod:  vm,
			ProofType:           JSONWebSignature2020,
			Challenge:           sampleChallenge,
			Domain:              sampleDomain,
			Created:             &created,
			ProofRepresentation: &proofRepr,
		})
		require.NoError(t, err)
		require.NotEmpty(t, result)
		require.Empty(t, result.Credentials())

		require.Len(t, result.Proofs, 1)
		require.Equal(t, result.Proofs[0]["challenge"], sampleChallenge)
		require.Equal(t, result.Proofs[0]["created"], "2020-12-25T00:00:00Z")
		require.Equal(t, result.Proofs[0]["domain"], sampleDomain)
		require.NotEmpty(t, result.Proofs[0]["jws"])
		require.Equal(t, result.Proofs[0]["proofPurpose"], "authentication")
		require.Equal(t, result.Proofs[0]["type"], JSONWebSignature2020)
		require.Equal(t, result.Proofs[0]["verificationMethod"], vm)
	})

	t.Run("Test prove failure - invalid credentials/presentation", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		// unlock wallet
		authToken, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, authToken)

		defer walletInstance.Close()

		result, err := walletInstance.Prove(authToken, &ProofOptions{}, WithRawCredentialsToProve([]byte("123")))
		require.Empty(t, result)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to resolve credentials from request")

		result, err = walletInstance.Prove(authToken, &ProofOptions{},
			WithStoredCredentialsToProve("non-existing-credential"))
		require.Empty(t, result)
		require.Error(t, err)
		require.Contains(t, err.Error(), "data not found")

		// save invalid VC in store
		require.NoError(t, walletInstance.Add(authToken, Credential, []byte(sampleInvalidDIDContent)))
		result, err = walletInstance.Prove(authToken, &ProofOptions{},
			WithStoredCredentialsToProve("did:example:sampleInvalidDIDContent"))
		require.Empty(t, result)
		require.Error(t, err)
		require.Contains(t, err.Error(), "build new credential")

		result, err = walletInstance.Prove(authToken, &ProofOptions{},
			WithRawPresentationToProve([]byte(sampleInvalidDIDContent)))
		require.Contains(t, err.Error(), "verifiable presentation is not valid")
		require.Empty(t, result)
	})

	t.Run("Test prove failures - proof option validation", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		// unlock wallet
		authToken, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, authToken)

		defer walletInstance.Close()

		// save all VCs in store
		cleanup := addCredentialsToWallet(t, walletInstance, authToken, vcs["edvc"], vcs["bbsvc"])
		defer cleanup()

		// no controller
		result, err := walletInstance.Prove(authToken, &ProofOptions{},
			WithStoredCredentialsToProve(vcs["edvc"].ID, vcs["bbsvc"].ID))
		require.Empty(t, result)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid proof option, 'controller' is required")

		// DID not found
		result, err = walletInstance.Prove(authToken, &ProofOptions{Controller: "did:example:1234"},
			WithStoredCredentialsToProve(vcs["edvc"].ID, vcs["bbsvc"].ID))
		require.Empty(t, result)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to prepare proof: did not found")

		// no assertion method
		result, err = walletInstance.Prove(authToken, &ProofOptions{Controller: sampleInvalidDIDID},
			WithStoredCredentialsToProve(vcs["edvc"].ID, vcs["bbsvc"].ID))
		require.Empty(t, result)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to find 'authentication' for given verification method")
	})

	t.Run("Test prove using JWT - fail to generate JWT claims from invalid presentation", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		// unlock wallet
		authToken, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, authToken)

		defer walletInstance.Close()

		// sign with invalid Presentation
		_, err = walletInstance.Prove(authToken,
			&ProofOptions{
				Controller:  didKey,
				ProofFormat: ExternalJWTProofFormat,
			},
			WithPresentationToProve(&verifiable.Presentation{
				Proofs: []verifiable.Proof{
					{
						"invalid": new(chan<- int), // can't marshal a channel
					},
				},
			}),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to generate JWT claims for VP")
	})

	t.Run("Test prove using JWT - fail to sign VP", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		// unlock wallet
		_, err = walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, issuerToken)

		defer walletInstance.Close()

		_, err = walletInstance.Prove("invalid auth token",
			&ProofOptions{
				Controller:  didKey,
				ProofFormat: ExternalJWTProofFormat,
			},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to generate JWT VP")
	})

	t.Run("Test VC wallet prove failure - add LD proof errors", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		// wallet locked
		result, err := walletInstance.Prove(sampleFakeTkn, &ProofOptions{Controller: didKey},
			WithStoredCredentialsToProve(vcs["edvc"].ID, vcs["bbsvc"].ID))
		require.Empty(t, result)
		require.Error(t, err)
		require.Contains(t, err.Error(), "wallet locked")

		// get token
		authToken, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, authToken)

		defer walletInstance.Close()

		cleanup := addCredentialsToWallet(t, walletInstance, authToken, vcs["edvc"], vcs["bbsvc"])
		defer cleanup()

		// key not found
		result, err = walletInstance.Prove(authToken, &ProofOptions{
			Controller: "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
		},
			WithStoredCredentialsToProve(vcs["edvc"].ID, vcs["bbsvc"].ID))
		require.Empty(t, result)
		require.Contains(t, err.Error(), "cannot read data for keysetID")

		// import keys manually
		session, err := sessionManager().getSession(authToken)
		require.NotEmpty(t, session)
		require.NoError(t, err)

		kmgr := session.KeyManager
		require.NotEmpty(t, kmgr)

		edPriv := ed25519.PrivateKey(base58.Decode(pkBase58))
		// nolint: errcheck, gosec
		kmgr.ImportPrivateKey(edPriv, kms.ED25519, kms.WithKeyID(kid))

		// invalid signature type
		result, err = walletInstance.Prove(authToken, &ProofOptions{
			Controller: didKey,
			ProofType:  "invalid",
		}, WithStoredCredentialsToProve(vcs["edvc"].ID, vcs["bbsvc"].ID))
		require.Empty(t, result)
		require.Contains(t, err.Error(), " unsupported signature type 'invalid'")

		// wrong key type
		result, err = walletInstance.Prove(authToken, &ProofOptions{
			Controller: didKey,
			ProofType:  BbsBlsSignature2020,
		}, WithStoredCredentialsToProve(vcs["edvc"].ID, vcs["bbsvc"].ID))
		require.Empty(t, result)
		require.Contains(t, err.Error(), "failed to add linked data proof")
	})
}

func Test_AddContext(t *testing.T) {
	loader, err := ldtestutil.DocumentLoader()
	require.NoError(t, err)

	vc, err := verifiable.ParseCredential(testdata.SampleUDCVC, verifiable.WithJSONLDDocumentLoader(loader))
	require.NoError(t, err)
	require.NotEmpty(t, vc)

	require.Len(t, vc.Context, 3)
	addContext(vc, bbsContext)
	require.Len(t, vc.Context, 3)
	addContext(vc, bbsContext+".01")
	require.Len(t, vc.Context, 4)
}

func TestWallet_Verify(t *testing.T) {
	user := uuid.New().String()
	customVDR := &mockvdr.MockVDRegistry{
		ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
			if didID == sampleInvalidDIDID {
				d, e := did.ParseDocument(testdata.SampleInvalidDID)
				require.NoError(t, e)

				return &did.DocResolution{DIDDocument: d}, nil
			} else if strings.HasPrefix(didID, "did:key:") {
				k := key.New()

				d, e := k.Read(didID)
				if e != nil {
					return nil, e
				}

				return d, nil
			}

			return nil, fmt.Errorf("did not found")
		},
	}

	sampleCrypto, err := tinkcrypto.New()
	require.NoError(t, err)

	mockctx := newMockProvider(t)
	mockctx.VDRegistryValue = customVDR
	mockctx.CryptoValue = sampleCrypto

	err = CreateProfile(user, mockctx, WithPassphrase(samplePassPhrase))
	require.NoError(t, err)

	walletForIssue, err := New(user, mockctx)
	require.NoError(t, err)

	tkn, err := walletForIssue.Open(WithUnlockByPassphrase(samplePassPhrase))
	require.NoError(t, err)
	require.NotEmpty(t, tkn)

	// import keys manually
	session, err := sessionManager().getSession(tkn)
	require.NotEmpty(t, session)
	require.NoError(t, err)

	kmgr := session.KeyManager
	require.NotEmpty(t, kmgr)

	edPriv := ed25519.PrivateKey(base58.Decode(pkBase58))
	// nolint: errcheck, gosec
	kmgr.ImportPrivateKey(edPriv, kms.ED25519, kms.WithKeyID(kid))

	// issue a credential
	sampleVC, err := walletForIssue.Issue(tkn, testdata.SampleUDCVC, &ProofOptions{
		Controller: didKey,
	})
	require.NoError(t, err)
	require.NotEmpty(t, sampleVC)
	require.Len(t, sampleVC.Proofs, 1)

	templateCred, err := verifiable.ParseCredential(testdata.SampleUDCVC, verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(walletForIssue.jsonldDocumentLoader))
	require.NoError(t, err)

	templateCred.Issuer.ID = didKey

	templateData, err := templateCred.MarshalJSON()
	require.NoError(t, err)

	// issue a JWT credential
	sampleJWTVC, err := walletForIssue.Issue(tkn, templateData, &ProofOptions{
		Controller:         didKey,
		VerificationMethod: sampleVerificationMethod,
		ProofFormat:        ExternalJWTProofFormat,
	})
	require.NoError(t, err)
	require.NotEmpty(t, sampleJWTVC)
	require.NotEqual(t, "", sampleJWTVC.JWT)
	require.True(t, jwt.IsJWS(sampleJWTVC.JWT))

	// present a credential
	sampleVP, err := walletForIssue.Prove(tkn, &ProofOptions{Controller: didKey},
		WithCredentialsToProve(sampleVC))
	require.NoError(t, err)
	require.NotEmpty(t, sampleVP)
	require.Len(t, sampleVP.Proofs, 1)

	// present a tampered credential
	invalidVC := *sampleVC
	invalidVC.Issuer.ID += "."
	sampleInvalidVP, err := walletForIssue.Prove(tkn, &ProofOptions{Controller: didKey},
		WithCredentialsToProve(&invalidVC))
	require.NoError(t, err)
	require.NotEmpty(t, sampleInvalidVP)
	require.Len(t, sampleInvalidVP.Proofs, 1)

	require.True(t, walletForIssue.Close())

	t.Run("Test VC wallet verifying a credential - success", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		tkn, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, tkn)

		// save it in store
		vcBytes, err := sampleVC.MarshalJSON()
		require.NoError(t, err)
		require.NoError(t, walletInstance.Add(tkn, Credential, vcBytes))

		// verify stored credential
		ok, err := walletInstance.Verify(tkn, WithStoredCredentialToVerify(sampleVC.ID))
		require.NoError(t, err)
		require.True(t, ok)

		// verify raw credential
		rawBytes, err := sampleVC.MarshalJSON()
		require.NoError(t, err)
		ok, err = walletInstance.Verify(tkn, WithRawCredentialToVerify(rawBytes))
		require.NoError(t, err)
		require.True(t, ok)

		require.NoError(t, walletInstance.Remove(tkn, Credential, "http://example.edu/credentials/1872"))

		// verify JWT Credential object
		jwtBytes, err := sampleJWTVC.MarshalJSON()
		require.NoError(t, err)
		ok, err = walletInstance.Verify(tkn, WithRawCredentialToVerify(jwtBytes))
		require.NoError(t, err)
		require.True(t, ok)

		// verify raw JWT credential
		ok, err = walletInstance.Verify(tkn, WithRawCredentialToVerify([]byte(sampleJWTVC.JWT)))
		require.NoError(t, err)
		require.True(t, ok)

		require.True(t, walletInstance.Close())
	})

	t.Run("Test VC wallet verifying a presentation - success", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		tkn, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, tkn)

		// verify a raw presentation
		rawBytes, err := sampleVP.MarshalJSON()
		require.NoError(t, err)
		ok, err := walletInstance.Verify(tkn, WithRawPresentationToVerify(rawBytes))
		require.NoError(t, err)
		require.True(t, ok)

		require.True(t, walletInstance.Close())
	})

	t.Run("Test VC wallet verifying a credential - invalid signature", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		tkn, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, tkn)

		// save tampered VC in store
		// save it in store
		tamperedVC := *sampleVC
		tamperedVC.Issuer.ID += "."
		vcBytes, err := tamperedVC.MarshalJSON()
		require.NoError(t, err)
		require.NoError(t, walletInstance.Add(tkn, Credential, vcBytes))

		ok, err := walletInstance.Verify(tkn, WithStoredCredentialToVerify("http://example.edu/credentials/1872"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid signature")
		require.False(t, ok)

		// verify raw credential
		rawBytes, err := tamperedVC.MarshalJSON()
		require.NoError(t, err)
		ok, err = walletInstance.Verify(tkn, WithRawCredentialToVerify(rawBytes))
		require.Contains(t, err.Error(), "invalid signature")
		require.False(t, ok)

		require.True(t, walletInstance.Close())
	})

	t.Run("Test VC wallet verifying a presentation - invalid signature", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		tkn, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, tkn)

		// verify a raw presentation
		tamperedVP := *sampleVP
		tamperedVP.Holder += "."
		rawBytes, err := tamperedVP.MarshalJSON()
		require.NoError(t, err)
		ok, err := walletInstance.Verify(tkn, WithRawPresentationToVerify(rawBytes))
		require.Contains(t, err.Error(), "invalid signature")
		require.False(t, ok)

		require.True(t, walletInstance.Close())
	})

	t.Run("Test VC wallet verifying a presentation - invalid credential signature", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		tkn, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, tkn)

		// verify a raw presentation
		rawBytes, err := sampleInvalidVP.MarshalJSON()
		require.NoError(t, err)
		ok, err := walletInstance.Verify(tkn, WithRawPresentationToVerify(rawBytes))
		require.Contains(t, err.Error(), "presentation verification failed: credential verification failed:")
		require.Contains(t, err.Error(), "invalid signature")
		require.False(t, ok)

		require.True(t, walletInstance.Close())
	})

	t.Run("Test VC wallet verifying a credential - invalid credential ID", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		tkn, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, tkn)

		// verify non existent credential.
		ok, err := walletInstance.Verify(tkn, WithStoredCredentialToVerify("invalid-ID"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get credential")
		require.False(t, ok)

		require.True(t, walletInstance.Close())
	})

	t.Run("Test VC wallet verifying a credential - invalid request", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		tkn, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, tkn)

		// verify non existent credential.
		ok, err := walletInstance.Verify(tkn, WithStoredCredentialToVerify(""))
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid verify request")
		require.False(t, ok)

		require.True(t, walletInstance.Close())
	})
}

func TestWallet_Derive(t *testing.T) {
	user := uuid.New().String()
	customVDR := &mockvdr.MockVDRegistry{
		ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
			if didID == sampleInvalidDIDID {
				d, e := did.ParseDocument(testdata.SampleInvalidDID)
				require.NoError(t, e)

				return &did.DocResolution{DIDDocument: d}, nil
			} else if strings.HasPrefix(didID, "did:key:") {
				k := key.New()

				d, e := k.Read(didID)
				if e != nil {
					return nil, e
				}

				return d, nil
			}

			return nil, fmt.Errorf("did not found")
		},
	}

	mockctx := newMockProvider(t)
	mockctx.VDRegistryValue = customVDR

	customCrypto, err := tinkcrypto.New()
	require.NoError(t, err)

	mockctx.CryptoValue = customCrypto

	// create profile
	err = CreateProfile(user, mockctx, WithPassphrase(samplePassPhrase))
	require.NoError(t, err)

	// prepare VCs for tests
	vcs := make(map[string]*verifiable.Credential, 2)
	walletForIssue, err := New(user, mockctx)
	require.NotEmpty(t, walletForIssue)
	require.NoError(t, err)

	authToken, err := walletForIssue.Open(WithUnlockByPassphrase(samplePassPhrase))
	require.NoError(t, err)
	require.NotEmpty(t, authToken)

	// import ED25519 & BLS12381G2Type keys manually
	session, err := sessionManager().getSession(authToken)
	require.NotEmpty(t, session)
	require.NoError(t, err)

	kmgr := session.KeyManager
	require.NotEmpty(t, kmgr)

	edPriv := ed25519.PrivateKey(base58.Decode(pkBase58))
	// nolint: errcheck, gosec
	kmgr.ImportPrivateKey(edPriv, kms.ED25519, kms.WithKeyID(kid))

	privKeyBBS, err := bbs12381g2pub.UnmarshalPrivateKey(base58.Decode(pkBBSBase58))
	require.NoError(t, err)
	// nolint: errcheck, gosec
	kmgr.ImportPrivateKey(privKeyBBS, kms.BLS12381G2Type, kms.WithKeyID(keyIDBBS))

	// issue a credential with Ed25519Signature2018
	result, err := walletForIssue.Issue(authToken, testdata.SampleUDCVC, &ProofOptions{
		Controller: didKey,
	})
	require.NoError(t, err)
	require.NotEmpty(t, result)
	require.Len(t, result.Proofs, 1)
	vcs["edvc"] = result

	// issue a credential with BbsBlsSignature2020
	proofRepr := verifiable.SignatureProofValue
	result, err = walletForIssue.Issue(authToken, testdata.SampleUDCVC, &ProofOptions{
		Controller:          didKeyBBS,
		ProofType:           BbsBlsSignature2020,
		ProofRepresentation: &proofRepr,
	})
	require.NoError(t, err)
	require.NotEmpty(t, result)
	require.Len(t, result.Proofs, 1)
	vcs["bbsvc"] = result

	require.True(t, walletForIssue.Close())

	// prepare frame
	var frameDoc map[string]interface{}

	require.NoError(t, json.Unmarshal(testdata.SampleFrame, &frameDoc))

	t.Run("Test derive a credential from wallet - success", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		tkn, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)

		// save BBS VC in store
		vcBytes, err := vcs["bbsvc"].MarshalJSON()
		require.NoError(t, err)
		require.NoError(t, walletInstance.Add(tkn, Credential, vcBytes))

		sampleNonce := uuid.New().String()

		verifyBBSProof := func(proofs []verifiable.Proof) {
			require.Len(t, proofs, 1)
			require.NotEmpty(t, proofs[0])
			require.Equal(t, proofs[0]["type"], "BbsBlsSignatureProof2020")
			require.NotEmpty(t, proofs[0]["nonce"])
			require.EqualValues(t, proofs[0]["nonce"], base64.StdEncoding.EncodeToString([]byte(sampleNonce)))
			require.NotEmpty(t, proofs[0]["proofValue"])
		}

		// derive stored credential
		vc, err := walletInstance.Derive(tkn, FromStoredCredential(vcs["bbsvc"].ID), &DeriveOptions{
			Nonce: sampleNonce,
			Frame: frameDoc,
		})
		require.NoError(t, err)
		require.NotEmpty(t, vc)
		verifyBBSProof(vc.Proofs)

		// derive raw credential
		vc, err = walletInstance.Derive(tkn, FromRawCredential(vcBytes), &DeriveOptions{
			Nonce: sampleNonce,
			Frame: frameDoc,
		})
		require.NoError(t, err)
		require.NotEmpty(t, vc)
		verifyBBSProof(vc.Proofs)

		// derive from credential instance
		vc, err = walletInstance.Derive(tkn, FromCredential(vcs["bbsvc"]), &DeriveOptions{
			Nonce: sampleNonce,
			Frame: frameDoc,
		})
		require.NoError(t, err)
		require.NotEmpty(t, vc)
		verifyBBSProof(vc.Proofs)

		require.True(t, walletInstance.Close())
	})

	t.Run("Test derive credential failures", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		tkn, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)

		// invalid request
		vc, err := walletInstance.Derive(tkn, FromStoredCredential(""), &DeriveOptions{})
		require.Empty(t, vc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid request to derive credential")

		// credential not found in store
		vc, err = walletInstance.Derive(tkn, FromStoredCredential("invalid-id"), &DeriveOptions{})
		require.Empty(t, vc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "data not found")

		// invalid credential in store
		require.NoError(t, walletInstance.Add(tkn, Credential, []byte(sampleInvalidDIDContent)))

		vc, err = walletInstance.Derive(tkn, FromStoredCredential("did:example:sampleInvalidDIDContent"), &DeriveOptions{})
		require.Empty(t, vc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "credential type of unknown structure")

		// invalid raw credential
		vc, err = walletInstance.Derive(tkn, FromRawCredential([]byte(sampleInvalidDIDContent)), &DeriveOptions{})
		require.Empty(t, vc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "credential type of unknown structure")

		// invalid raw credential
		vc, err = walletInstance.Derive(tkn, FromCredential(vcs["bbsvc"]), &DeriveOptions{})
		require.Empty(t, vc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to derive credential")

		// try deriving wrong proof type - no BbsBlsSignature2020 proof present
		vc, err = walletInstance.Derive(tkn, FromCredential(vcs["edvc"]), &DeriveOptions{
			Frame: frameDoc,
		})
		require.Empty(t, vc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no BbsBlsSignature2020 proof present")

		require.True(t, walletInstance.Close())
	})
}

func TestWallet_CreateKeyPair(t *testing.T) {
	sampleKeyPairUser := uuid.New().String()
	mockctx := newMockProvider(t)
	err := CreateProfile(sampleKeyPairUser, mockctx, WithPassphrase(samplePassPhrase))
	require.NoError(t, err)

	wallet, err := New(sampleKeyPairUser, mockctx)
	require.NoError(t, err)
	require.NotEmpty(t, wallet)

	token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase), WithUnlockExpiry(500*time.Millisecond))
	require.NoError(t, err)
	require.NotEmpty(t, token)

	defer wallet.Close()

	t.Run("test creating key pair", func(t *testing.T) {
		keyPair, err := wallet.CreateKeyPair(token, kms.ED25519)
		require.NoError(t, err)
		require.NotEmpty(t, keyPair)
		require.NotEmpty(t, keyPair.KeyID)
		require.NotEmpty(t, keyPair.PublicKey)
	})

	t.Run("test creating key pair with invalid auth", func(t *testing.T) {
		keyPair, err := wallet.CreateKeyPair(sampleFakeTkn, kms.ED25519)
		require.True(t, errors.Is(err, ErrInvalidAuthToken))
		require.Empty(t, keyPair)
	})

	t.Run("test failure while creating key pair", func(t *testing.T) {
		keyPair, err := wallet.CreateKeyPair(token, kms.KeyType("invalid"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create new key")
		require.Empty(t, keyPair)
	})
}

func TestWallet_ResolveCredentialManifest(t *testing.T) {
	mockctx := newMockProvider(t)
	user := uuid.New().String()

	// create a wallet
	err := CreateProfile(user, mockctx, WithPassphrase(samplePassPhrase))
	require.NoError(t, err)

	wallet, err := New(user, mockctx)
	require.NoError(t, err)
	require.NotEmpty(t, wallet)

	// get token
	token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase), WithUnlockExpiry(500*time.Millisecond))
	require.NoError(t, err)
	require.NotEmpty(t, token)

	responseVP, err := verifiable.ParsePresentation(testdata.CredentialResponseWithMultipleVCs,
		verifiable.WithPresDisabledProofCheck(),
		verifiable.WithPresJSONLDDocumentLoader(mockctx.JSONLDDocumentLoader()))
	require.NoError(t, err)

	vc, err := verifiable.ParseCredential(testdata.SampleUDCVC,
		verifiable.WithJSONLDDocumentLoader(mockctx.JSONLDDocumentLoader()))
	require.NoError(t, err)

	require.NoError(t, wallet.Add(token, Credential, testdata.SampleUDCVC))

	t.Run("Test Resolving credential manifests", func(t *testing.T) {
		testTable := map[string]struct {
			manifest    []byte
			resolve     ResolveManifestOption
			resultCount int
			error       string
		}{
			"testing resolve by raw credential response": {
				manifest:    testdata.CredentialManifestMultipleVCs,
				resolve:     ResolveRawResponse(testdata.CredentialResponseWithMultipleVCs),
				resultCount: 2,
			},
			"testing resolve by credential response": {
				manifest:    testdata.CredentialManifestMultipleVCs,
				resolve:     ResolveResponse(responseVP),
				resultCount: 2,
			},
			"testing resolve by raw credential": {
				manifest:    testdata.CredentialManifestMultipleVCs,
				resolve:     ResolveRawCredential("udc_output", testdata.SampleUDCVC),
				resultCount: 1,
			},
			"testing resolve by raw JWT credential": {
				manifest:    testdata.CredentialManifestMultipleVCs,
				resolve:     ResolveRawCredential("udc_output", testdata.SampleUDCJWTVC),
				resultCount: 1,
			},
			"testing resolve by credential": {
				manifest:    testdata.CredentialManifestMultipleVCs,
				resolve:     ResolveCredential("udc_output", vc),
				resultCount: 1,
			},
			"testing resolve by credential ID": {
				manifest:    testdata.CredentialManifestMultipleVCs,
				resolve:     ResolveCredentialID("udc_output", vc.ID),
				resultCount: 1,
			},
			"testing failure - resolve by empty resolve option": {
				manifest:    testdata.CredentialManifestMultipleVCs,
				resolve:     ResolveCredential("udc_output", nil),
				resultCount: 0,
				error:       "invalid option",
			},
			"testing failure - resolve by invalid raw response": {
				manifest:    testdata.CredentialManifestMultipleVCs,
				resolve:     ResolveRawResponse([]byte("{}")),
				resultCount: 0,
				error:       "verifiable presentation is not valid",
			},
			"testing failure - resolve by invalid raw credential": {
				manifest:    testdata.CredentialManifestMultipleVCs,
				resolve:     ResolveRawCredential("", []byte("{}")),
				resultCount: 0,
				error:       "credential type of unknown structure",
			},
			"testing failure - invalid credential manifest": {
				manifest:    []byte("{}"),
				resolve:     ResolveResponse(responseVP),
				resultCount: 0,
				error:       "invalid credential manifest",
			},
			"testing failure  - resolve raw credential by invalid descriptor ID": {
				manifest:    testdata.CredentialManifestMultipleVCs,
				resolve:     ResolveRawCredential("invalid", testdata.SampleUDCVC),
				resultCount: 0,
				error:       "unable to find matching descriptor",
			},
			"testing failure  - resolve credential by invalid descriptor ID": {
				manifest:    testdata.CredentialManifestMultipleVCs,
				resolve:     ResolveCredential("invalid", vc),
				resultCount: 0,
				error:       "unable to find matching descriptor",
			},
			"testing failure  - resolve credential by invalid credential ID": {
				manifest:    testdata.CredentialManifestMultipleVCs,
				resolve:     ResolveCredentialID("udc_output", "incorrect"),
				resultCount: 0,
				error:       "failed to get credential to resolve from wallet",
			},
		}

		t.Parallel()

		for testName, testData := range testTable {
			t.Run(testName, func(t *testing.T) {
				resolved, err := wallet.ResolveCredentialManifest(token, testData.manifest, testData.resolve)

				if testData.error != "" {
					require.Error(t, err)
					require.Contains(t, err.Error(), testData.error)
					require.Len(t, resolved, testData.resultCount)

					return
				}

				require.NoError(t, err)
				require.NotEmpty(t, resolved)
				require.Len(t, resolved, testData.resultCount)

				for _, result := range resolved {
					require.NotEmpty(t, result.DescriptorID)
					require.NotEmpty(t, result.Title)
					require.NotEmpty(t, result.Properties)
				}
			})
		}
	})
}

func TestWallet_verifiableClaimsToJWT(t *testing.T) {
	customVDR := &mockvdr.MockVDRegistry{
		ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
			if didID == sampleInvalidDIDID {
				d, e := did.ParseDocument(testdata.SampleInvalidDID)
				require.NoError(t, e)

				return &did.DocResolution{DIDDocument: d}, nil
			} else if strings.HasPrefix(didID, "did:key:") {
				k := key.New()

				d, e := k.Read(didID)
				if e != nil {
					return nil, e
				}

				return d, nil
			}

			return nil, fmt.Errorf("did not found")
		},
	}

	user := uuid.New().String()

	mockctx := newMockProvider(t)
	mockctx.VDRegistryValue = customVDR
	mockctx.CryptoValue = &cryptomock.Crypto{}

	err := CreateProfile(user, mockctx, WithPassphrase(samplePassPhrase))
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		type keyImporterFunc func(kmgr kms.KeyManager) (string, string, error)

		ecKeyTestCase := func(
			curve elliptic.Curve,
			fpCodec uint64,
			kt kms.KeyType,
		) keyImporterFunc {
			return func(kmgr kms.KeyManager) (string, string, error) {
				priv, err := ecdsa.GenerateKey(curve, rand.Reader)
				if err != nil {
					return "", "", err
				}

				pubKeyBytes := elliptic.MarshalCompressed(priv.Curve, priv.X, priv.Y)

				fp := fingerprint.KeyFingerprint(fpCodec, pubKeyBytes)
				k, vm := fingerprint.CreateDIDKeyByCode(fpCodec, pubKeyBytes)

				// nolint: errcheck, gosec
				kmgr.ImportPrivateKey(priv, kt, kms.WithKeyID(fp))

				return k, vm, nil
			}
		}

		testCases := []struct {
			name    string
			keyFunc keyImporterFunc
		}{
			{
				name: "Ed25519",
				keyFunc: func(kmgr kms.KeyManager) (string, string, error) {
					edPriv := ed25519.PrivateKey(base58.Decode(pkBase58))
					// nolint: errcheck, gosec
					kmgr.ImportPrivateKey(edPriv, kms.ED25519, kms.WithKeyID(kid))

					return didKey, sampleVerificationMethod, nil
				},
			},
			{
				name:    "P256",
				keyFunc: ecKeyTestCase(elliptic.P256(), fingerprint.P256PubKeyMultiCodec, kms.ECDSAP256TypeIEEEP1363),
			},
			{
				name:    "P384",
				keyFunc: ecKeyTestCase(elliptic.P384(), fingerprint.P384PubKeyMultiCodec, kms.ECDSAP384TypeIEEEP1363),
			},
			{
				name:    "P521",
				keyFunc: ecKeyTestCase(elliptic.P521(), fingerprint.P521PubKeyMultiCodec, kms.ECDSAP521TypeIEEEP1363),
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				walletInstance, err := New(user, mockctx)
				require.NotEmpty(t, walletInstance)
				require.NoError(t, err)

				// unlock wallet
				authToken, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
				require.NoError(t, err)
				require.NotEmpty(t, authToken)

				defer walletInstance.Close()

				// add private key
				session, err := sessionManager().getSession(authToken)
				require.NotEmpty(t, session)
				require.NoError(t, err)

				kmgr := session.KeyManager
				require.NotEmpty(t, kmgr)

				k, vm, err := tc.keyFunc(kmgr)
				require.NoError(t, err)

				_, err = walletInstance.verifiableClaimsToJWT(authToken, &verifiable.JWTCredClaims{}, &ProofOptions{
					Controller:         k,
					VerificationMethod: vm,
				})
				require.NoError(t, err)
			})
		}
	})

	t.Run("error initializing KMS signer", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		// unlock wallet
		authToken, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, authToken)

		defer walletInstance.Close()

		_, err = walletInstance.verifiableClaimsToJWT(authToken, nil, &ProofOptions{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "initializing signer")
	})

	t.Run("unsupported keytype", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		// unlock wallet
		authToken, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, authToken)

		defer walletInstance.Close()

		// add private key
		session, err := sessionManager().getSession(authToken)
		require.NotEmpty(t, session)
		require.NoError(t, err)

		kmgr := session.KeyManager
		require.NotEmpty(t, kmgr)

		privKeyBBS, err := bbs12381g2pub.UnmarshalPrivateKey(base58.Decode(pkBBSBase58))
		require.NoError(t, err)
		// nolint: errcheck, gosec
		kmgr.ImportPrivateKey(privKeyBBS, kms.BLS12381G2Type, kms.WithKeyID(keyIDBBS))

		_, err = walletInstance.verifiableClaimsToJWT(authToken, &verifiable.JWTCredClaims{}, &ProofOptions{
			Controller:         didKeyBBS,
			VerificationMethod: didKeyBBS + "#" + keyIDBBS,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported keytype for JWT")
	})

	t.Run("fail to sign", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		expectErr := errors.New("expected error")

		walletInstance.walletCrypto = &cryptomock.Crypto{
			SignErr: expectErr,
		}

		// unlock wallet
		authToken, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, authToken)

		defer walletInstance.Close()

		// add private key
		session, err := sessionManager().getSession(authToken)
		require.NotEmpty(t, session)
		require.NoError(t, err)

		kmgr := session.KeyManager
		require.NotEmpty(t, kmgr)

		edPriv := ed25519.PrivateKey(base58.Decode(pkBase58))
		// nolint: errcheck, gosec
		kmgr.ImportPrivateKey(edPriv, kms.ED25519, kms.WithKeyID(kid))

		_, err = walletInstance.verifiableClaimsToJWT(authToken, &verifiable.JWTCredClaims{}, &ProofOptions{
			Controller:         didKey,
			VerificationMethod: sampleVerificationMethod,
		})
		require.Error(t, err)
		require.ErrorIs(t, err, expectErr)
		require.Contains(t, err.Error(), "failed to sign JWS")
	})
}

func newMockProvider(t *testing.T) *mockprovider.Provider {
	t.Helper()

	loader, err := ldtestutil.DocumentLoader()
	require.NoError(t, err)

	return &mockprovider.Provider{
		StorageProviderValue:              mockstorage.NewMockStoreProvider(),
		ProtocolStateStorageProviderValue: mockstorage.NewMockStoreProvider(),
		DocumentLoaderValue:               loader,
	}
}

func createSampleProfile(t *testing.T, mockctx *mockprovider.Provider) {
	err := CreateProfile(sampleUserID, mockctx, WithPassphrase(samplePassPhrase))
	require.NoError(t, err)

	wallet, err := New(sampleUserID, mockctx)
	require.NoError(t, err)
	require.NotEmpty(t, wallet)
	require.NotEmpty(t, wallet.profile.MasterLockCipher)
}

// adds credentials to wallet and returns handle for cleanup.
func addCredentialsToWallet(t *testing.T, walletInstance *Wallet, auth string, vcs ...*verifiable.Credential) func() {
	for _, vc := range vcs {
		vcBytes, err := vc.MarshalJSON()
		require.NoError(t, err)
		require.NoError(t, walletInstance.Remove(auth, Credential, vc.ID))
		require.NoError(t, walletInstance.Add(auth, Credential, vcBytes))
	}

	return func() {
		for _, vc := range vcs {
			err := walletInstance.Remove(auth, Credential, vc.ID)
			if err != nil {
				t.Logf("failed to cleanup wallet instance store: %s", err)
			}
		}
	}
}

const testPD = `
{
  "id": "32f54163-7166-48f1-93d8-ff217bdb0654",
  "input_descriptors": [
    {
      "id": "type",
      "name": "type",
      "purpose": "We can only interact with specific status information for Verifiable Credentials",
      "schema": [
        {
          "uri": "https://www.w3.org/2018/credentials#VerifiableCredential"
        }
      ],
      "constraints": {
        "fields": [
          {
            "path": [
              "$.credentialStatus.type",
              "$.vc.credentialStatus.type"
            ],
            "purpose": "We can only interact with specific status information for Verifiable Credentials",
            "filter": {
              "type": "string",
              "enum": [
                "StatusList2021Entry",
                "RevocationList2021Status",
                "RevocationList2020Status"
              ]
            }
          }
        ]
      }
    },
    {
      "id": "degree",
      "name": "degree",
      "purpose": "We can only hire with bachelor degree.",
      "schema": [
        {
          "uri": "https://www.w3.org/2018/credentials#VerifiableCredential"
        }
      ],
      "constraints": {
        "fields": [
          {
            "path": [
              "$.credentialSubject.degree.type",
              "$.vc.credentialSubject.degree.type"
            ],
            "purpose": "We can only hire with bachelor degree.",
            "filter": {
              "type": "string",
              "const": "BachelorDegree"
            }
          }
        ]
      }
    }
  ]
}`

//nolint:lll
const testJSONLD = `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/vc/status-list/2021/v1"
  ],
  "credentialStatus": {
    "id": "urn:uuid:1d8e36ae-6334-4bbf-bf33-8df69191b163",
    "statusListCredential": "http://vc-rest-echo.trustbloc.local:8075/issuer/profiles/i_myprofile_cp_p384/credentials/status/1",
    "statusListIndex": "28",
    "statusPurpose": "revocation",
    "type": "StatusList2021Entry"
  },
  "credentialSubject": {
    "id": "did:orb:uAAA:EiBmZDwNdNMN6eh96dTakcdN8EPjmGoLHOijLw-NGY84Yg",
    "identifier": "3a185b8f-078a-4646-8343-76a45c2856a5",
    "name": "Heavy Sour Dilbit"
  },
  "description": "Crude oil stream, produced from diluted bitumen.",
  "id": "urn:uuid:urn:uuid:ec57b5a1-d986-4268-9c55-de23e936aa46",
  "issuanceDate": "2020-05-01T00:45:04.789Z",
  "issuer": {
    "id": "did:orb:uAAA:EiA34UbWMH_0iKQfgcJ1jBPWvQvXZHuxpZ1g13PUw4xysw",
    "name": "i_myprofile_cp_p384"
  },
  "name": "Heavy Sour Dilbit",
  "type": [
    "VerifiableCredential"
  ]
}`

//nolint:lll
const testSDJWT = "eyJhbGciOiJFUzM4NCIsImtpZCI6ImRpZDpvcmI6dUFBQTpFaUQ2STdvMHhzUVBCakxsVXhwSC0xM3ptNkZnbXpiQWs5cHhSRlFSdTZDT2J3IzM4MzczODZjLWJiODYtNDExYS05ODljLTZmMzMwZTQ1MzQxNiJ9.eyJpYXQiOjEuNTg0Mzk4MjQ2ZSswOSwiaXNzIjoiZGlkOm9yYjp1QUFBOkVpRDZJN28weHNRUEJqTGxVeHBILTEzem02RmdtemJBazlweFJGUVJ1NkNPYnciLCJqdGkiOiJ1cm46dXVpZDp1cm46dXVpZDpkNmE3NDIyNy1iMzljLTRhOGUtOWI3OS1hNmRiNjE0MWUzNDYiLCJuYmYiOjEuNTg0Mzk4MjQ2ZSswOSwic3ViIjoiZGlkOm9yYjp1QUFBOkVpQm1aRHdOZE5NTjZlaDk2ZFRha2NkTjhFUGptR29MSE9pakx3LU5HWTg0WWciLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxIiwiaHR0cHM6Ly93M2MtY2NnLmdpdGh1Yi5pby92Yy1yZXZvY2F0aW9uLWxpc3QtMjAyMS9jb250ZXh0cy92MS5qc29ubGQiXSwiX3NkX2FsZyI6InNoYS0zODQiLCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoidXJuOnV1aWQ6NDE0YzZlNDUtNTQzZC00NDUyLWEwYzEtMGM3MWRhYjczMGY1Iiwic3RhdHVzTGlzdENyZWRlbnRpYWwiOiJodHRwOi8vdmMtcmVzdC1lY2hvLnRydXN0YmxvYy5sb2NhbDo4MDc1L2lzc3Vlci9wcm9maWxlcy9pX215cHJvZmlsZV91ZF9lczM4NF9zZGp3dC9jcmVkZW50aWFscy9zdGF0dXMvMSIsInN0YXR1c0xpc3RJbmRleCI6IjI3IiwidHlwZSI6IlJldm9jYXRpb25MaXN0MjAyMVN0YXR1cyJ9LCJjcmVkZW50aWFsU3ViamVjdCI6eyJfc2QiOlsiLWEwRmdBU3FEekZMRjg1bXc3WXFGVmh6cmlUaTFVWjV0d2V4d3otczc4ZVhUYWV1YmZ4TjVsRjFmS3FFMkRxbyIsImI2TDR2ZlFMYUNRWkZZTExfT21SeXhSQTcxVkRGMnVPMXZMdTkxbzVmTlV2YlNja0Y4X29fTU53S3RwUHBIWFIiXSwiZGVncmVlIjp7Il9zZCI6WyJZZ0RxNHNkbDdSQ3FOQnI0bTI0REhwS3RCdzZLUUk0OXhkalBWa0hhVm9DZmNtYUJiMkJlTVB4SVMwS2djcjlUIiwiNVg0czdRdkZZR2VzRmRMTjE0VjA3Zy0yUjBHWFZMWTVzNG5RclB1MFNsM3VBZHA4ZVJxTFlnX3dkLU1nLVF0XyJdfSwiaWQiOiJkaWQ6b3JiOnVBQUE6RWlCbVpEd05kTk1ONmVoOTZkVGFrY2ROOEVQam1Hb0xIT2lqTHctTkdZODRZZyJ9LCJpZCI6InVybjp1dWlkOnVybjp1dWlkOmQ2YTc0MjI3LWIzOWMtNGE4ZS05Yjc5LWE2ZGI2MTQxZTM0NiIsImlzc3VhbmNlRGF0ZSI6IjIwMjAtMDMtMTZUMjI6Mzc6MjZaIiwiaXNzdWVyIjp7ImlkIjoiZGlkOm9yYjp1QUFBOkVpRDZJN28weHNRUEJqTGxVeHBILTEzem02RmdtemJBazlweFJGUVJ1NkNPYnciLCJuYW1lIjoiaV9teXByb2ZpbGVfdWRfZXMzODRfc2Rqd3QifSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlVuaXZlcnNpdHlEZWdyZWVDcmVkZW50aWFsIl19fQ.MGYCMQCQKQuj6IHGMSxsv_Jip3Ne8NkyqDMPcigsOk07LEBa1W9tiv_KdAcSz4LB3hM03dcCMQCiPRF2tJ0QvWXANq6QFLsGQrSLi8UyN57kOXn_WEln_JrN0BkpimA3Cx3d09e4pCU~WyJnSjBJRUxtRFpwQnFkLXJMM3I5NmN3IiwiZGVncmVlIiwiTUlUIl0~WyI2RHdTR3VqVnhCVUdwblhPRlowX0dBIiwidHlwZSIsIkJhY2hlbG9yRGVncmVlIl0~WyJ0d2ZzaXVSM00xNTNCUDB2U2ptWkd3IiwibmFtZSIsIkpheWRlbiBEb2UiXQ~WyI3Q0lzNFNPWGNnYnVjSkZONXFJdDlBIiwic3BvdXNlIiwiZGlkOmV4YW1wbGU6YzI3NmUxMmVjMjFlYmZlYjFmNzEyZWJjNmYxIl0~"
