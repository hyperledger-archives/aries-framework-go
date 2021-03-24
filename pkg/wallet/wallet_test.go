/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
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
  		"id": "did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5",
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
)

func TestCreate(t *testing.T) {
	t.Run("test create new wallet using local kms passphrase", func(t *testing.T) {
		mockctx := newMockProvider()
		err := CreateProfile(sampleUserID, mockctx, WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		wallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)
	})

	t.Run("test create new wallet using local kms secret lock service", func(t *testing.T) {
		mockctx := newMockProvider()
		err := CreateProfile(sampleUserID, mockctx, WithSecretLockService(&secretlock.MockSecretLock{}))
		require.NoError(t, err)

		wallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)
	})

	t.Run("test create new wallet using remote kms key server URL", func(t *testing.T) {
		mockctx := newMockProvider()
		err := CreateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL))
		require.NoError(t, err)

		wallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)
	})

	t.Run("test create new wallet failure", func(t *testing.T) {
		mockctx := newMockProvider()
		err := CreateProfile(sampleUserID, mockctx)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid create profile options")

		wallet, err := New(sampleUserID, mockctx)
		require.Error(t, err)
		require.Empty(t, wallet)
	})

	t.Run("test create new wallet failure - create store error", func(t *testing.T) {
		mockctx := newMockProvider()
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
		mockctx := newMockProvider()
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

	t.Run("test create new wallet failure - create content store error", func(t *testing.T) {
		mockctx := newMockProvider()
		mockctx.StorageProviderValue = &mockStorageProvider{
			MockStoreProvider: mockstorage.NewMockStoreProvider(),
			failure:           fmt.Errorf(sampleWalletErr),
		}

		err := CreateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL))
		require.NoError(t, err)

		wallet, err := New(sampleUserID, mockctx)
		require.Error(t, err)
		require.Empty(t, wallet)
		require.Contains(t, err.Error(), "failed to get wallet content store:")
	})
}

func TestUpdate(t *testing.T) {
	t.Run("test update wallet using local kms passphrase", func(t *testing.T) {
		mockctx := newMockProvider()
		createSampleProfile(t, mockctx)

		err := UpdateProfile(sampleUserID, mockctx, WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		wallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)
		require.NotEmpty(t, wallet.profile.MasterLockCipher)
	})

	t.Run("test update wallet using local kms secret lock service", func(t *testing.T) {
		mockctx := newMockProvider()
		createSampleProfile(t, mockctx)

		err := UpdateProfile(sampleUserID, mockctx, WithSecretLockService(&secretlock.MockSecretLock{}))
		require.NoError(t, err)

		wallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)
	})

	t.Run("test update wallet using remote kms key server URL", func(t *testing.T) {
		mockctx := newMockProvider()
		createSampleProfile(t, mockctx)

		err := UpdateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL))
		require.NoError(t, err)

		wallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)
		require.Empty(t, wallet.profile.MasterLockCipher)
		require.NotEmpty(t, wallet.profile.KeyServerURL)
	})

	t.Run("test update wallet failure", func(t *testing.T) {
		mockctx := newMockProvider()
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
		mockctx := newMockProvider()
		err := UpdateProfile(sampleUserID, mockctx)
		require.Error(t, err)
		require.Contains(t, err.Error(), "profile does not exist")

		wallet, err := New(sampleUserID, mockctx)
		require.Error(t, err)
		require.Empty(t, wallet)
	})

	t.Run("test update wallet failure - create store error", func(t *testing.T) {
		mockctx := newMockProvider()
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
		mockctx := newMockProvider()
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
}

func TestNew(t *testing.T) {
	t.Run("test get wallet by user", func(t *testing.T) {
		mockctx := newMockProvider()
		// create a wallet
		err := CreateProfile(sampleUserID, mockctx, WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		wallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)
	})

	t.Run("test get wallet by invalid userID", func(t *testing.T) {
		mockctx := newMockProvider()
		err := CreateProfile(sampleUserID, mockctx, WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		wallet, err := New(sampleUserID+"invalid", mockctx)
		require.Empty(t, wallet)
		require.Error(t, err)
		require.Contains(t, err.Error(), "profile does not exist")
	})

	t.Run("test update wallet failure - save profile error", func(t *testing.T) {
		mockctx := newMockProvider()
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
		mockctx := newMockProvider()
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
		mockctx := newMockProvider()
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

	t.Run("test open & close wallet using remote kms URL", func(t *testing.T) {
		mockctx := newMockProvider()
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
}

func TestWallet_Export(t *testing.T) {
	mockctx := newMockProvider()
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
	mockctx := newMockProvider()
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
	mockctx := newMockProvider()
	err := CreateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL))
	require.NoError(t, err)

	walletInstance, err := New(sampleUserID, mockctx)
	require.NotEmpty(t, walletInstance)
	require.NoError(t, err)

	err = walletInstance.Add(Metadata, []byte(sampleContentValid))
	require.NoError(t, err)
}

func TestWallet_Get(t *testing.T) {
	mockctx := newMockProvider()
	err := CreateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL))
	require.NoError(t, err)

	walletInstance, err := New(sampleUserID, mockctx)
	require.NotEmpty(t, walletInstance)
	require.NoError(t, err)

	err = walletInstance.Add(Metadata, []byte(sampleContentValid))
	require.NoError(t, err)

	content, err := walletInstance.Get(Metadata, "did:example:123456789abcdefghi")
	require.NoError(t, err)
	require.NotEmpty(t, content)
	require.Equal(t, sampleContentValid, string(content))
}

func TestWallet_Remove(t *testing.T) {
	mockctx := newMockProvider()
	err := CreateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL))
	require.NoError(t, err)

	walletInstance, err := New(sampleUserID, mockctx)
	require.NotEmpty(t, walletInstance)
	require.NoError(t, err)

	err = walletInstance.Add(Metadata, []byte(sampleContentValid))
	require.NoError(t, err)

	content, err := walletInstance.Get(Metadata, "did:example:123456789abcdefghi")
	require.NoError(t, err)
	require.NotEmpty(t, content)

	err = walletInstance.Remove(Metadata, "did:example:123456789abcdefghi")
	require.NoError(t, err)

	content, err = walletInstance.Get(Metadata, "did:example:123456789abcdefghi")
	require.Empty(t, content)
	require.Error(t, err)
	require.True(t, errors.Is(err, storage.ErrDataNotFound))
}

func TestWallet_Query(t *testing.T) {
	mockctx := newMockProvider()
	err := CreateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL))
	require.NoError(t, err)

	walletInstance, err := New(sampleUserID, mockctx)
	require.NotEmpty(t, walletInstance)
	require.NoError(t, err)

	results, err := walletInstance.Query(&QueryParams{})
	require.Empty(t, results)
	require.Error(t, err)
	require.EqualError(t, err, toBeImplementedErr)
}

func TestWallet_Issue(t *testing.T) {
	didKey := "did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5"
	pkBase58 := "2MP5gWCnf67jvW3E4Lz8PpVrDWAXMYY1sDxjnkEnKhkkbKD7yP2mkVeyVpu5nAtr3TeDgMNjBPirk2XcQacs3dvZ"
	kid := "z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5"

	customVDR := &mockvdr.MockVDRegistry{
		ResolveFunc: func(didID string, opts ...vdrapi.ResolveOption) (*did.DocResolution, error) {
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

	mockctx := newMockProvider()
	mockctx.VDRegistryValue = customVDR
	mockctx.CryptoValue = &cryptomock.Crypto{}

	err := CreateProfile(sampleUserID, mockctx, WithPassphrase(samplePassPhrase))
	require.NoError(t, err)

	t.Run("Test VC wallet issue using controller - success", func(t *testing.T) {
		walletInstance, err := New(sampleUserID, mockctx)
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

	t.Run("Test VC wallet issue using verification method - success", func(t *testing.T) {
		walletInstance, err := New(sampleUserID, mockctx)
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
			VerificationMethod: "did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5#z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5", //nolint:lll
		})
		require.NoError(t, err)
		require.NotEmpty(t, result)
		require.Len(t, result.Proofs, 1)
	})

	t.Run("Test VC wallet issue using all options - success", func(t *testing.T) {
		walletInstance, err := New(sampleUserID, mockctx)
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
		vm := "did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5#z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5"
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

	// nolint:lll
	t.Run("Test VC wallet issue using BBS - success", func(t *testing.T) {
		didKeyBBS := "did:key:zUC72c7u4BYVmfYinDceXkNAwzPEyuEE23kUmJDjLy8495KH3pjLwFhae1Fww9qxxRdLnS2VNNwni6W3KbYZKsicDtiNNEp76fYWR6HCD8jAz6ihwmLRjcHH6kB294Xfg1SL1qQ"
		pkBBSBase58 := "6gsgGpdx7p1nYoKJ4b5fKt1xEomWdnemg9nJFX6mqNCh"
		keyIDBBS := "zUC72c7u4BYVmfYinDceXkNAwzPEyuEE23kUmJDjLy8495KH3pjLwFhae1Fww9qxxRdLnS2VNNwni6W3KbYZKsicDtiNNEp76fYWR6HCD8jAz6ihwmLRjcHH6kB294Xfg1SL1qQ"

		walletInstance, err := New(sampleUserID, mockctx)
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
		mockctx1 := newMockProvider()
		mockctx1.VDRegistryValue = &mockvdr.MockVDRegistry{}
		mockctx1.CryptoValue = &cryptomock.Crypto{}

		err := CreateProfile(sampleUserID, mockctx1, WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		walletInstance, err := New(sampleUserID, mockctx1)
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
		err = walletInstance.Add(DIDResolutionResponse, []byte(sampleDocResolutionResponse))
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
		walletInstance, err := New(sampleUserID, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		result, err := walletInstance.Issue(sampleFakeTkn, []byte("--"), &ProofOptions{})
		require.Empty(t, result)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse credential")
	})

	t.Run("Test VC wallet issue failure - proof option validation", func(t *testing.T) {
		walletInstance, err := New(sampleUserID, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		// no controller
		result, err := walletInstance.Issue(sampleFakeTkn, []byte(sampleUDCVC), &ProofOptions{})
		require.Empty(t, result)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid proof option, 'controller' is required")

		// DID not found
		result, err = walletInstance.Issue(sampleFakeTkn, []byte(sampleUDCVC), &ProofOptions{
			Controller: "did:example:1234",
		})
		require.Empty(t, result)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to read DID document from wallet store or from VDR")

		// no assertion method
		result, err = walletInstance.Issue(sampleFakeTkn, []byte(sampleUDCVC), &ProofOptions{
			Controller: sampleInvalidDIDID,
		})
		require.Empty(t, result)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to find 'assertionMethod' for given verification method")

		// invalid DID in store
		err = walletInstance.Add(DIDResolutionResponse, []byte(sampleInvalidDIDContent))
		require.NoError(t, err)

		result, err = walletInstance.Issue(sampleFakeTkn, []byte(sampleUDCVC), &ProofOptions{
			Controller: "did:example:sampleInvalidDIDContent",
		})
		require.Empty(t, result)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse stored DID")
	})

	t.Run("Test VC wallet issue failure - add proof errors", func(t *testing.T) {
		walletInstance, err := New(sampleUserID, mockctx)
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

func Test_AddContext(t *testing.T) {
	vc, err := verifiable.ParseCredential([]byte(sampleUDCVC))
	require.NoError(t, err)
	require.NotEmpty(t, vc)

	require.Len(t, vc.Context, 3)
	addContext(vc, bbsContext)
	require.Len(t, vc.Context, 3)
	addContext(vc, bbsContext+".01")
	require.Len(t, vc.Context, 4)
}

func TestWallet_Prove(t *testing.T) {
	mockctx := newMockProvider()
	err := CreateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL))
	require.NoError(t, err)

	walletInstance, err := New(sampleUserID, mockctx)
	require.NotEmpty(t, walletInstance)
	require.NoError(t, err)

	result, err := walletInstance.Prove(nil, &ProofOptions{})
	require.Empty(t, result)
	require.Error(t, err)
	require.EqualError(t, err, toBeImplementedErr)
}

func TestWallet_Verify(t *testing.T) {
	mockctx := newMockProvider()
	err := CreateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL))
	require.NoError(t, err)

	walletInstance, err := New(sampleUserID, mockctx)
	require.NotEmpty(t, walletInstance)
	require.NoError(t, err)

	result, err := walletInstance.Verify(nil)
	require.Empty(t, result)
	require.Error(t, err)
	require.EqualError(t, err, toBeImplementedErr)
}

func newMockProvider() *mockprovider.Provider {
	return &mockprovider.Provider{StorageProviderValue: mockstorage.NewMockStoreProvider()}
}

func createSampleProfile(t *testing.T, mockctx *mockprovider.Provider) {
	err := CreateProfile(sampleUserID, mockctx, WithPassphrase(samplePassPhrase))
	require.NoError(t, err)

	wallet, err := New(sampleUserID, mockctx)
	require.NoError(t, err)
	require.NotEmpty(t, wallet)
	require.NotEmpty(t, wallet.profile.MasterLockCipher)
}
