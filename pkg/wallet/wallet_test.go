/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"crypto/ed25519"
	"crypto/sha256"
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
	"github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/internal/jsonldtest"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/webkms"
	cryptomock "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	"github.com/hyperledger/aries-framework-go/pkg/mock/secretlock"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local/masterlock/pbkdf2"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// nolint: lll
const (
	sampleUserID       = "sample-user01"
	sampleFakeTkn      = "fake-auth-tkn"
	toBeImplementedErr = "to be implemented"
	sampleWalletErr    = "sample wallet err"
	sampleCreatedDate  = "2020-12-25"
	sampleChallenge    = "sample-challenge"
	sampleDomain       = "sample-domain"
	sampleUDCVC        = `{
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1",
		"https://w3id.org/security/bbs/v1"
      ],
     "credentialSchema": [],
      "credentialSubject": {
        "degree": {
          "type": "BachelorDegree",
          "university": "MIT"
        },
        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "name": "Jayden Doe",
        "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
      },
      "expirationDate": "2020-01-01T19:23:24Z",
      "id": "http://example.edu/credentials/1872",
      "issuanceDate": "2010-01-01T19:23:24Z",
      "issuer": {
        "id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
        "name": "Example University"
      },
      "referenceNumber": 83294847,
      "type": [
        "VerifiableCredential",
        "UniversityDegreeCredential"
      ]
    }`
	sampleInvalidDIDID = "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHdI"
	sampleInvalidDID   = `{
    	"@context": ["https://w3id.org/did/v1"],
    	"id": "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHdI",
    	"verificationMethod": [{
        	"controller": "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
        	"id": "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd#z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
        	"publicKeyBase58": "5yKdnU7ToTjAoRNDzfuzVTfWBH38qyhE1b9xh4v8JaWF",
        	"type": "Ed25519VerificationKey2018"
    	}],
    	"capabilityDelegation": ["did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd#z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd"],
    	"capabilityInvocation": ["did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd#z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd"],
    	"keyAgreement": [{
        	"controller": "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
        	"id": "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd#z6LShKMZ117txS1WuExddVM2rbJ2zy3AKFtZVY5WNi44aKzA",
        	"publicKeyBase58": "6eBPUhK2ryHmoras6qq5Y15Z9pW3ceiQcZMptFQXrxDQ",
        	"type": "X25519KeyAgreementKey2019"
    	}],
    	"created": "2021-03-23T16:23:39.682869-04:00",
    	"updated": "2021-03-23T16:23:39.682869-04:00"
		}`
	sampleInvalidDIDContent = `{
    	"@context": ["https://w3id.org/did/v1"],
    	"id": "did:example:sampleInvalidDIDContent"
		}`
	sampleDocResolutionResponse = `{
  		"@context": [
    		"https://w3id.org/wallet/v1",
	    	"https://w3id.org/did-resolution/v1"
  		],
  		"id": "did:example:123",
  		"type": ["DIDResolutionResponse"],
  		"name": "Farming Sensor DID Document",
  		"image": "https://via.placeholder.com/150",
  		"description": "An IoT device in the middle of a corn field.",
  		"tags": ["professional"],
  		"correlation": ["4058a72a-9523-11ea-bb37-0242ac130002"],
  		"created": "2017-06-18T21:19:10Z",
  		"expires": "2026-06-18T21:19:10Z",
  		"didDocument": {
    		"@context": ["https://w3id.org/did/v1"],
    		"id": "did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5",
    		"verificationMethod": [{
        		"controller": "did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5",
        		"id": "did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5#z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5",
        		"publicKeyBase58": "8jkuMBqmu1TRA6is7TT5tKBksTZamrLhaXrg9NAczqeh",
        		"type": "Ed25519VerificationKey2018"
    		}],
    		"authentication": ["did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5#z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5"],
    		"assertionMethod": ["did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5#z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5"],
    		"capabilityDelegation": ["did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5#z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5"],
    		"capabilityInvocation": ["did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5#z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5"],
    		"keyAgreement": [{
        		"controller": "did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5",
        		"id": "did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5#z6LSmjNfS5FC9W59JtPZq7fHgrjThxsidjEhZeMxCarbR998",
        		"publicKeyBase58": "B4CVumSL43MQDW1oJU9LNGWyrpLbw84YgfeGi8D4hmNN",
        		"type": "X25519KeyAgreementKey2019"
    		}],
    		"created": "2021-03-23T19:25:18.513655-04:00",
    		"updated": "2021-03-23T19:25:18.513655-04:00"
		} 
	}`

	sampleFrame = `
		{
			"@context": [
    			"https://www.w3.org/2018/credentials/v1",
        		"https://www.w3.org/2018/credentials/examples/v1",
				"https://w3id.org/security/bbs/v1"
			],
  			"type": ["VerifiableCredential", "UniversityDegreeCredential"],
  			"@explicit": true,
  			"identifier": {},
  			"issuer": {},
  			"issuanceDate": {},
  			"credentialSubject": {
    			"@explicit": true,
    			"degree": {},
    			"name": {}
  			}
		}
	`

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

	t.Run("test update wallet failure - save profile error", func(t *testing.T) {
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

		wallet, err := New(user, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		// create test key IDS for EDV use & update profile
		tkn, err := keyManager().createKeyManager(wallet.profile, wallet.storeProvider,
			&unlockOpts{passphrase: samplePassPhrase})
		require.NoError(t, err)

		wallet.profile.EDVConf.EncryptionKeyID = ""
		wallet.profile.EDVConf.MACKeyID = ""
		ok, err := wallet.profile.setupEDVKeys(tkn, "", "")
		require.True(t, ok)
		require.NoError(t, err)
		require.True(t, wallet.Close())

		// get token
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
		}, wallet.profile)

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

	// save test data without collection
	for i := 0; i < count; i++ {
		require.NoError(t, walletInstance.Add(tkn,
			Credential, []byte(fmt.Sprintf(vcContent, uuid.New().String()))))
	}

	// save a collection
	require.NoError(t, walletInstance.Add(tkn, Collection, []byte(orgCollection)))

	// save contents by collection
	for i := 0; i < count; i++ {
		require.NoError(t, walletInstance.Add(tkn,
			Credential, []byte(fmt.Sprintf(vcContent, uuid.New().String())), AddByCollection(collectionID)))
	}

	// get all by content
	vcs, err := walletInstance.GetAll(tkn, Credential)
	require.NoError(t, err)
	require.Len(t, vcs, count*2)

	// get all by content & collection
	vcs, err = walletInstance.GetAll(tkn, Credential, FilterByCollection(collectionID))
	require.NoError(t, err)
	require.Len(t, vcs, count)
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
		Issued: &util.TimeWithTrailingZeroMsec{
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
				URI: fmt.Sprintf("%s#%s", verifiable.ContextURI, verifiable.VCType),
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

func TestWallet_Issue(t *testing.T) {
	user := uuid.New().String()
	customVDR := &mockvdr.MockVDRegistry{
		ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
			if didID == sampleInvalidDIDID {
				d, e := did.ParseDocument([]byte(sampleInvalidDID))
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
		kmgr, err := keyManager().getKeyManger(authToken)
		require.NoError(t, err)
		edPriv := ed25519.PrivateKey(base58.Decode(pkBase58))
		// nolint: errcheck, gosec
		kmgr.ImportPrivateKey(edPriv, kms.ED25519, kms.WithKeyID(kid))

		// sign with just controller
		result, err := walletInstance.Issue(authToken, []byte(sampleUDCVC), &ProofOptions{
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
		kmgr, err := keyManager().getKeyManger(authToken)
		require.NoError(t, err)
		edPriv := ed25519.PrivateKey(base58.Decode(pkBase58))
		// nolint: errcheck, gosec
		kmgr.ImportPrivateKey(edPriv, kms.ED25519, kms.WithKeyID(kid))

		// sign with just controller
		result, err := walletInstance.Issue(authToken, []byte(sampleUDCVC), &ProofOptions{
			Controller: didKey,
			ProofType:  JSONWebSignature2020,
		})
		require.NoError(t, err)
		require.NotEmpty(t, result)
		require.Len(t, result.Proofs, 1)
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
		kmgr, err := keyManager().getKeyManger(authToken)
		require.NoError(t, err)
		edPriv := ed25519.PrivateKey(base58.Decode(pkBase58))
		// nolint: errcheck, gosec
		kmgr.ImportPrivateKey(edPriv, kms.ED25519, kms.WithKeyID(kid))

		// issue
		result, err := walletInstance.Issue(authToken, []byte(sampleUDCVC), &ProofOptions{
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
		kmgr, err := keyManager().getKeyManger(authToken)
		require.NoError(t, err)
		edPriv := ed25519.PrivateKey(base58.Decode(pkBase58))
		// nolint: errcheck, gosec
		kmgr.ImportPrivateKey(edPriv, kms.ED25519, kms.WithKeyID(kid))

		// issue credential
		proofRepr := verifiable.SignatureJWS
		vm := sampleVerificationMethod
		created, err := time.Parse("2006-01-02", sampleCreatedDate)
		require.NoError(t, err)

		result, err := walletInstance.Issue(authToken, []byte(sampleUDCVC), &ProofOptions{
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
		kmgr, err := keyManager().getKeyManger(authToken)
		require.NoError(t, err)
		privKeyBBS, err := bbs12381g2pub.UnmarshalPrivateKey(base58.Decode(pkBBSBase58))
		require.NoError(t, err)
		// nolint: errcheck, gosec
		kmgr.ImportPrivateKey(privKeyBBS, kms.BLS12381G2Type, kms.WithKeyID(keyIDBBS))

		// sign with just controller
		proofRepr := verifiable.SignatureProofValue
		result, err := walletInstance.Issue(authToken, []byte(sampleUDCVC), &ProofOptions{
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
		kmgr, err := keyManager().getKeyManger(authToken)
		require.NoError(t, err)
		edPriv := ed25519.PrivateKey(base58.Decode(pkBase58))
		// nolint: errcheck, gosec
		kmgr.ImportPrivateKey(edPriv, kms.ED25519, kms.WithKeyID(kid))

		// save DID Resolution response
		err = walletInstance.Add(authToken, DIDResolutionResponse, []byte(sampleDocResolutionResponse))
		require.NoError(t, err)

		// sign with just controller
		result, err := walletInstance.Issue(authToken, []byte(sampleUDCVC), &ProofOptions{
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
		result, err := walletInstance.Issue(authToken, []byte(sampleUDCVC), &ProofOptions{})
		require.Empty(t, result)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid proof option, 'controller' is required")

		// DID not found
		result, err = walletInstance.Issue(authToken, []byte(sampleUDCVC), &ProofOptions{
			Controller: "did:example:1234",
		})
		require.Empty(t, result)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to prepare proof: did not found")

		// no assertion method
		result, err = walletInstance.Issue(authToken, []byte(sampleUDCVC), &ProofOptions{
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
		result, err := walletInstance.Issue(sampleFakeTkn, []byte(sampleUDCVC), &ProofOptions{
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
		result, err = walletInstance.Issue(authToken, []byte(sampleUDCVC), &ProofOptions{
			Controller: "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
		})
		require.Empty(t, result)
		require.Contains(t, err.Error(), "cannot read data for keysetID")

		// import keys manually
		kmgr, err := keyManager().getKeyManger(authToken)
		require.NoError(t, err)
		edPriv := ed25519.PrivateKey(base58.Decode(pkBase58))
		// nolint: errcheck, gosec
		kmgr.ImportPrivateKey(edPriv, kms.ED25519, kms.WithKeyID(kid))

		// invalid signature type
		result, err = walletInstance.Issue(authToken, []byte(sampleUDCVC), &ProofOptions{
			Controller: didKey,
			ProofType:  "invalid",
		})
		require.Empty(t, result)
		require.Contains(t, err.Error(), " unsupported signature type 'invalid'")

		// wrong key type
		result, err = walletInstance.Issue(authToken, []byte(sampleUDCVC), &ProofOptions{
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
				d, e := did.ParseDocument([]byte(sampleInvalidDID))
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

	// create profile
	err := CreateProfile(user, mockctx, WithPassphrase(samplePassPhrase))
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
	kmgr, err := keyManager().getKeyManger(authToken)
	require.NoError(t, err)

	edPriv := ed25519.PrivateKey(base58.Decode(pkBase58))
	// nolint: errcheck, gosec
	kmgr.ImportPrivateKey(edPriv, kms.ED25519, kms.WithKeyID(kid))

	privKeyBBS, err := bbs12381g2pub.UnmarshalPrivateKey(base58.Decode(pkBBSBase58))
	require.NoError(t, err)
	// nolint: errcheck, gosec
	kmgr.ImportPrivateKey(privKeyBBS, kms.BLS12381G2Type, kms.WithKeyID(keyIDBBS))

	// issue a credential with Ed25519Signature2018
	result, err := walletForIssue.Issue(authToken, []byte(sampleUDCVC), &ProofOptions{
		Controller: didKey,
	})
	require.NoError(t, err)
	require.NotEmpty(t, result)
	require.Len(t, result.Proofs, 1)
	vcs["edvc"] = result

	// issue a credential with BbsBlsSignature2020
	proofRepr := verifiable.SignatureProofValue
	result, err = walletForIssue.Issue(authToken, []byte(sampleUDCVC), &ProofOptions{
		Controller:          didKeyBBS,
		ProofType:           BbsBlsSignature2020,
		ProofRepresentation: &proofRepr,
	})
	require.NoError(t, err)
	require.NotEmpty(t, result)
	require.Len(t, result.Proofs, 1)
	vcs["bbsvc"] = result

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
		kmgr, err := keyManager().getKeyManger(authToken)
		require.NoError(t, err)
		edPriv := ed25519.PrivateKey(base58.Decode(pkBase58))
		// nolint: errcheck, gosec
		kmgr.ImportPrivateKey(edPriv, kms.ED25519, kms.WithKeyID(kid))

		edVCBytes, err := json.Marshal(vcs["edvc"])
		require.NoError(t, err)

		bbsVCBytes, err := json.Marshal(vcs["bbsvc"])
		require.NoError(t, err)

		// sign with just controller (one stored & one raw bytes)
		result, err := walletInstance.Prove(authToken,
			&ProofOptions{Controller: didKey},
			WithStoredCredentialsToPresent(vcs["edvc"].ID),
			WithRawCredentialsToPresent(bbsVCBytes),
			WithCredentialsToPresent(vcs["edvc"]),
		)
		require.NoError(t, err)
		require.NotEmpty(t, result)
		require.Len(t, result.Proofs, 1)
		require.Len(t, result.Credentials(), 3)
		require.Equal(t, result.Holder, didKey)

		// sign with just controller with all raw credentials
		result, err = walletInstance.Prove(authToken,
			&ProofOptions{Controller: didKey},
			WithRawCredentialsToPresent(edVCBytes, bbsVCBytes),
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
		kmgr, err := keyManager().getKeyManger(authToken)
		require.NoError(t, err)
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
			WithPresentation(pres),
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
			WithPresentation(pres),
			WithStoredCredentialsToPresent(vcs["edvc"].ID),
			WithRawCredentialsToPresent(bbsVCBytes),
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
		kmgr, err := keyManager().getKeyManger(authToken)
		require.NoError(t, err)
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
		}, WithStoredCredentialsToPresent(vcs["edvc"].ID, vcs["bbsvc"].ID))
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
		kmgr, err := keyManager().getKeyManger(authToken)
		require.NoError(t, err)
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

	t.Run("Test prove failure - invalid credentials", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		// unlock wallet
		authToken, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, authToken)

		defer walletInstance.Close()

		result, err := walletInstance.Prove(authToken, &ProofOptions{}, WithRawCredentialsToPresent([]byte("123")))
		require.Empty(t, result)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to resolve credentials from request")

		result, err = walletInstance.Prove(authToken, &ProofOptions{},
			WithStoredCredentialsToPresent("non-existing-credential"))
		require.Empty(t, result)
		require.Error(t, err)
		require.Contains(t, err.Error(), "data not found")

		// save invalid VC in store
		require.NoError(t, walletInstance.Add(authToken, Credential, []byte(sampleInvalidDIDContent)))
		result, err = walletInstance.Prove(authToken, &ProofOptions{},
			WithStoredCredentialsToPresent("did:example:sampleInvalidDIDContent"))
		require.Empty(t, result)
		require.Error(t, err)
		require.Contains(t, err.Error(), "build new credential")
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
			WithStoredCredentialsToPresent(vcs["edvc"].ID, vcs["bbsvc"].ID))
		require.Empty(t, result)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid proof option, 'controller' is required")

		// DID not found
		result, err = walletInstance.Prove(authToken, &ProofOptions{Controller: "did:example:1234"},
			WithStoredCredentialsToPresent(vcs["edvc"].ID, vcs["bbsvc"].ID))
		require.Empty(t, result)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to prepare proof: did not found")

		// no assertion method
		result, err = walletInstance.Prove(authToken, &ProofOptions{Controller: sampleInvalidDIDID},
			WithStoredCredentialsToPresent(vcs["edvc"].ID, vcs["bbsvc"].ID))
		require.Empty(t, result)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to find 'authentication' for given verification method")
	})

	t.Run("Test VC wallet issue failure - add proof errors", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		// wallet locked
		result, err := walletInstance.Prove(sampleFakeTkn, &ProofOptions{Controller: didKey},
			WithStoredCredentialsToPresent(vcs["edvc"].ID, vcs["bbsvc"].ID))
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
			WithStoredCredentialsToPresent(vcs["edvc"].ID, vcs["bbsvc"].ID))
		require.Empty(t, result)
		require.Contains(t, err.Error(), "cannot read data for keysetID")

		// import keys manually
		kmgr, err := keyManager().getKeyManger(authToken)
		require.NoError(t, err)
		edPriv := ed25519.PrivateKey(base58.Decode(pkBase58))
		// nolint: errcheck, gosec
		kmgr.ImportPrivateKey(edPriv, kms.ED25519, kms.WithKeyID(kid))

		// invalid signature type
		result, err = walletInstance.Prove(authToken, &ProofOptions{
			Controller: didKey,
			ProofType:  "invalid",
		}, WithStoredCredentialsToPresent(vcs["edvc"].ID, vcs["bbsvc"].ID))
		require.Empty(t, result)
		require.Contains(t, err.Error(), " unsupported signature type 'invalid'")

		// wrong key type
		result, err = walletInstance.Prove(authToken, &ProofOptions{
			Controller: didKey,
			ProofType:  BbsBlsSignature2020,
		}, WithStoredCredentialsToPresent(vcs["edvc"].ID, vcs["bbsvc"].ID))
		require.Empty(t, result)
		require.Contains(t, err.Error(), "failed to add linked data proof")
	})
}

func Test_AddContext(t *testing.T) {
	loader, err := jsonldtest.DocumentLoader()
	require.NoError(t, err)

	vc, err := verifiable.ParseCredential([]byte(sampleUDCVC), verifiable.WithJSONLDDocumentLoader(loader))
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
				d, e := did.ParseDocument([]byte(sampleInvalidDID))
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
	kmgr, err := keyManager().getKeyManger(tkn)
	require.NoError(t, err)

	edPriv := ed25519.PrivateKey(base58.Decode(pkBase58))
	// nolint: errcheck, gosec
	kmgr.ImportPrivateKey(edPriv, kms.ED25519, kms.WithKeyID(kid))

	// issue a credential
	sampleVC, err := walletForIssue.Issue(tkn, []byte(sampleUDCVC), &ProofOptions{
		Controller: didKey,
	})
	require.NoError(t, err)
	require.NotEmpty(t, sampleVC)
	require.Len(t, sampleVC.Proofs, 1)

	// present a credential
	sampleVP, err := walletForIssue.Prove(tkn, &ProofOptions{Controller: didKey},
		WithCredentialsToPresent(sampleVC))
	require.NoError(t, err)
	require.NotEmpty(t, sampleVP)
	require.Len(t, sampleVP.Proofs, 1)

	// present a tampered credential
	invalidVC := *sampleVC
	invalidVC.Issuer.ID += "."
	sampleInvalidVP, err := walletForIssue.Prove(tkn, &ProofOptions{Controller: didKey},
		WithCredentialsToPresent(&invalidVC))
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
				d, e := did.ParseDocument([]byte(sampleInvalidDID))
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
	kmgr, err := keyManager().getKeyManger(authToken)
	require.NoError(t, err)

	edPriv := ed25519.PrivateKey(base58.Decode(pkBase58))
	// nolint: errcheck, gosec
	kmgr.ImportPrivateKey(edPriv, kms.ED25519, kms.WithKeyID(kid))

	privKeyBBS, err := bbs12381g2pub.UnmarshalPrivateKey(base58.Decode(pkBBSBase58))
	require.NoError(t, err)
	// nolint: errcheck, gosec
	kmgr.ImportPrivateKey(privKeyBBS, kms.BLS12381G2Type, kms.WithKeyID(keyIDBBS))

	// issue a credential with Ed25519Signature2018
	result, err := walletForIssue.Issue(authToken, []byte(sampleUDCVC), &ProofOptions{
		Controller: didKey,
	})
	require.NoError(t, err)
	require.NotEmpty(t, result)
	require.Len(t, result.Proofs, 1)
	vcs["edvc"] = result

	// issue a credential with BbsBlsSignature2020
	proofRepr := verifiable.SignatureProofValue
	result, err = walletForIssue.Issue(authToken, []byte(sampleUDCVC), &ProofOptions{
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

	require.NoError(t, json.Unmarshal([]byte(sampleFrame), &frameDoc))

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

func newMockProvider(t *testing.T) *mockprovider.Provider {
	t.Helper()

	loader, err := jsonldtest.DocumentLoader()
	require.NoError(t, err)

	return &mockprovider.Provider{
		StorageProviderValue:      mockstorage.NewMockStoreProvider(),
		JSONLDDocumentLoaderValue: loader,
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
