/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcwallet

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	cryptomock "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	"github.com/hyperledger/aries-framework-go/pkg/mock/secretlock"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local/masterlock/pbkdf2"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// nolint: lll
const (
	samplePassPhrase    = "fakepassphrase"
	sampleRemoteKMSAuth = "sample-auth-token"
	sampleKeyServerURL  = "sample/keyserver/test"
	sampleUserID        = "sample-user01"
	toBeImplementedErr  = "to be implemented"
	sampleClientErr     = "sample client err"
	sampleDIDKey        = "did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5"
	sampleContentValid  = `{
  			"@context": ["https://w3id.org/wallet/v1"],
  		  	"id": "did:example:123456789abcdefghi",
    		"type": "Person",
    		"name": "John Smith",
    		"image": "https://via.placeholder.com/150",
    		"description" : "Professional software developer for Acme Corp.",
    		"tags": ["professional", "person"],
    		"correlation": ["4058a72a-9523-11ea-bb37-0242ac130002"]
  		}`
	sampleUDCVC = `{
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

	sampleUDCVCWithProof = `{
    "@context": ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1", "https://w3id.org/security/bbs/v1"],
    "credentialSubject": {
        "degree": {"type": "BachelorDegree", "university": "MIT"},
        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "name": "Jayden Doe",
        "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
    },
    "expirationDate": "2020-01-01T19:23:24Z",
    "id": "http://example.edu/credentials/1872",
    "issuanceDate": "2010-01-01T19:23:24Z",
    "issuer": {"id": "did:example:76e12ec712ebc6f1c221ebfeb1f", "name": "Example University"},
    "proof": {
        "created": "2021-03-26T11:25:14.170037-04:00",
        "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..5iUqLMjUbPy2Sp5RvtoKW4kWlSfpX35VyoC6rGkxNW5r3a3M7I7qBK5hpJGi2H4cf2TZizQnJXCJs6EH6ijSDw",
        "proofPurpose": "assertionMethod",
        "type": "Ed25519Signature2018",
        "verificationMethod": "did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5#z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5"
    },
    "referenceNumber": 83294847,
    "type": ["VerifiableCredential", "UniversityDegreeCredential"]
}`
)

func TestCreateProfile(t *testing.T) {
	t.Run("test create new wallet client using local kms passphrase", func(t *testing.T) {
		mockctx := newMockProvider()
		err := CreateProfile(sampleUserID, mockctx, wallet.WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		vcWallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, vcWallet)
	})

	t.Run("test create new wallet client using local kms secret lock service", func(t *testing.T) {
		mockctx := newMockProvider()
		err := CreateProfile(sampleUserID, mockctx, wallet.WithSecretLockService(&secretlock.MockSecretLock{}))
		require.NoError(t, err)

		vcWallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, vcWallet)
	})

	t.Run("test create new wallet client using remote kms key server URL", func(t *testing.T) {
		mockctx := newMockProvider()
		err := CreateProfile(sampleUserID, mockctx, wallet.WithKeyServerURL(sampleKeyServerURL))
		require.NoError(t, err)

		vcWallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, vcWallet)
	})

	t.Run("test create new wallet failure", func(t *testing.T) {
		mockctx := newMockProvider()
		err := CreateProfile(sampleUserID, mockctx)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid create profile options")

		vcWallet, err := New(sampleUserID, mockctx)
		require.Error(t, err)
		require.Empty(t, vcWallet)
	})

	t.Run("test create new wallet failure - create store error", func(t *testing.T) {
		mockctx := newMockProvider()
		mockctx.StorageProviderValue = &mockstorage.MockStoreProvider{
			ErrOpenStoreHandle: fmt.Errorf(sampleClientErr),
		}

		err := CreateProfile(sampleUserID, mockctx, wallet.WithKeyServerURL(sampleKeyServerURL))
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleClientErr)

		vcWallet, err := New(sampleUserID, mockctx)
		require.Error(t, err)
		require.Empty(t, vcWallet)
	})

	t.Run("test create new wallet failure - save profile error", func(t *testing.T) {
		mockctx := newMockProvider()
		mockctx.StorageProviderValue = &mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{
				ErrPut: fmt.Errorf(sampleClientErr),
			},
		}

		err := CreateProfile(sampleUserID, mockctx, wallet.WithKeyServerURL(sampleKeyServerURL))
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleClientErr)

		vcWallet, err := New(sampleUserID, mockctx)
		require.Error(t, err)
		require.Empty(t, vcWallet)
	})

	t.Run("test create new wallet failure - create content store error", func(t *testing.T) {
		mockctx := newMockProvider()
		mockctx.StorageProviderValue = &mockStorageProvider{
			MockStoreProvider: mockstorage.NewMockStoreProvider(),
			failure:           fmt.Errorf(sampleClientErr),
		}

		err := CreateProfile(sampleUserID, mockctx, wallet.WithKeyServerURL(sampleKeyServerURL))
		require.NoError(t, err)

		vcWallet, err := New(sampleUserID, mockctx)
		require.Error(t, err)
		require.Empty(t, vcWallet)
		require.Contains(t, err.Error(), "failed to get wallet content store:")
	})
}

func TestUpdate(t *testing.T) {
	t.Run("test update wallet client using local kms passphrase", func(t *testing.T) {
		mockctx := newMockProvider()
		createSampleProfile(t, mockctx)

		err := UpdateProfile(sampleUserID, mockctx, wallet.WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		vcWallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, vcWallet)
	})

	t.Run("test update wallet client using local kms secret lock service", func(t *testing.T) {
		mockctx := newMockProvider()
		createSampleProfile(t, mockctx)

		err := UpdateProfile(sampleUserID, mockctx, wallet.WithSecretLockService(&secretlock.MockSecretLock{}))
		require.NoError(t, err)

		vcWallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, vcWallet)
	})

	t.Run("test update wallet client using remote kms key server URL", func(t *testing.T) {
		mockctx := newMockProvider()
		createSampleProfile(t, mockctx)

		err := UpdateProfile(sampleUserID, mockctx, wallet.WithKeyServerURL(sampleKeyServerURL))
		require.NoError(t, err)

		vcWallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, vcWallet)
	})

	t.Run("test update wallet failure", func(t *testing.T) {
		mockctx := newMockProvider()
		createSampleProfile(t, mockctx)

		err := UpdateProfile(sampleUserID, mockctx)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid create profile options")

		vcWallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, vcWallet)
	})

	t.Run("test update wallet failure - profile doesn't exists", func(t *testing.T) {
		mockctx := newMockProvider()
		err := UpdateProfile(sampleUserID, mockctx)
		require.Error(t, err)
		require.Contains(t, err.Error(), "profile does not exist")

		vcWallet, err := New(sampleUserID, mockctx)
		require.Error(t, err)
		require.Empty(t, vcWallet)
	})

	t.Run("test update wallet failure - create store error", func(t *testing.T) {
		mockctx := newMockProvider()
		mockctx.StorageProviderValue = &mockstorage.MockStoreProvider{
			ErrOpenStoreHandle: fmt.Errorf(sampleClientErr),
		}

		err := UpdateProfile(sampleUserID, mockctx, wallet.WithKeyServerURL(sampleKeyServerURL))
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleClientErr)

		vcWallet, err := New(sampleUserID, mockctx)
		require.Error(t, err)
		require.Empty(t, vcWallet)
	})

	t.Run("test update wallet failure - save profile error", func(t *testing.T) {
		mockctx := newMockProvider()
		createSampleProfile(t, mockctx)

		mockctx.StorageProviderValue.(*mockstorage.MockStoreProvider).Store.ErrPut = fmt.Errorf(sampleClientErr)

		err := UpdateProfile(sampleUserID, mockctx, wallet.WithKeyServerURL(sampleKeyServerURL))
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleClientErr)

		vcWallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, vcWallet)
	})
}

func TestNew(t *testing.T) {
	t.Run("test get client", func(t *testing.T) {
		mockctx := newMockProvider()
		// create a wallet
		err := CreateProfile(sampleUserID, mockctx, wallet.WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		vcWallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, vcWallet)
	})

	t.Run("test get client unlocked", func(t *testing.T) {
		mockctx := newMockProvider()
		// create a wallet
		err := CreateProfile(sampleUserID, mockctx, wallet.WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		vcWallet, err := New(sampleUserID, mockctx, wallet.WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, vcWallet)

		token, err := vcWallet.auth()
		require.NoError(t, err)
		require.NotEmpty(t, token)
	})

	t.Run("test get client unlock failure - wrong passphrase", func(t *testing.T) {
		mockctx := newMockProvider()
		// create a wallet
		err := CreateProfile(sampleUserID, mockctx, wallet.WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		vcWallet, err := New(sampleUserID, mockctx, wallet.WithUnlockByPassphrase(samplePassPhrase+"ss"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "message authentication failed")
		require.Empty(t, vcWallet)
	})

	t.Run("test get client by invalid userID", func(t *testing.T) {
		mockctx := newMockProvider()
		err := CreateProfile(sampleUserID, mockctx, wallet.WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		vcWallet, err := New(sampleUserID+"invalid", mockctx)
		require.Empty(t, vcWallet)
		require.Error(t, err)
		require.Contains(t, err.Error(), "profile does not exist")
	})

	t.Run("test update wallet failure - save profile error", func(t *testing.T) {
		mockctx := newMockProvider()
		mockctx.StorageProviderValue = &mockstorage.MockStoreProvider{
			ErrOpenStoreHandle: fmt.Errorf(sampleClientErr),
		}

		vcWallet, err := New(sampleUserID, mockctx)
		require.Error(t, err)
		require.Empty(t, vcWallet)
		require.Contains(t, err.Error(), sampleClientErr)
	})
}

func TestClient_OpenClose(t *testing.T) {
	t.Run("test open & close wallet using local kms passphrase", func(t *testing.T) {
		sampleUser := uuid.New().String()
		mockctx := newMockProvider()

		err := CreateProfile(sampleUser, mockctx, wallet.WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		vcWallet, err := New(sampleUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, vcWallet)

		// get token
		err = vcWallet.Open(wallet.WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		token, err := vcWallet.auth()
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer vcWallet.Close()

		// try again
		err = vcWallet.Open(wallet.WithUnlockByPassphrase(samplePassPhrase))
		require.Error(t, err)
		require.True(t, errors.Is(err, wallet.ErrAlreadyUnlocked))
		token, err = vcWallet.auth()
		require.NoError(t, err)
		require.NotEmpty(t, token)

		// close wallet
		require.True(t, vcWallet.Close())
		require.False(t, vcWallet.Close())

		// try to open with wrong passphrase
		err = vcWallet.Open(wallet.WithUnlockByPassphrase(samplePassPhrase + "wrong"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "message authentication failed")
		token, err = vcWallet.auth()
		require.Empty(t, token)
		require.Error(t, err)
		require.True(t, errors.Is(err, ErrWalletLocked))
	})

	t.Run("test open & close wallet using secret lock service", func(t *testing.T) {
		sampleUser := uuid.New().String()
		mockctx := newMockProvider()

		masterLock, err := pbkdf2.NewMasterLock(samplePassPhrase, sha256.New, 0, nil)
		require.NoError(t, err)

		err = CreateProfile(sampleUser, mockctx, wallet.WithSecretLockService(masterLock))
		require.NoError(t, err)

		vcWallet, err := New(sampleUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, vcWallet)

		// get token
		err = vcWallet.Open(wallet.WithUnlockBySecretLockService(masterLock))
		require.NoError(t, err)
		token, err := vcWallet.auth()
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer vcWallet.Close()

		// try again
		err = vcWallet.Open(wallet.WithUnlockBySecretLockService(masterLock))
		require.Error(t, err)
		require.True(t, errors.Is(err, wallet.ErrAlreadyUnlocked))
		token, err = vcWallet.auth()
		require.NoError(t, err)
		require.NotEmpty(t, token)

		// close wallet
		require.True(t, vcWallet.Close())
		require.False(t, vcWallet.Close())

		// try to open with wrong secret lock service
		badLock, err := pbkdf2.NewMasterLock(samplePassPhrase+"wrong", sha256.New, 0, nil)
		require.NoError(t, err)

		err = vcWallet.Open(wallet.WithUnlockBySecretLockService(badLock))
		require.Error(t, err)
		require.Contains(t, err.Error(), "message authentication failed")
		token, err = vcWallet.auth()
		require.Empty(t, token)
		require.Error(t, err)
		require.True(t, errors.Is(err, ErrWalletLocked))
	})

	t.Run("test open & close wallet using remote kms URL", func(t *testing.T) {
		sampleUser := uuid.New().String()
		mockctx := newMockProvider()

		err := CreateProfile(sampleUser, mockctx, wallet.WithKeyServerURL(sampleKeyServerURL))
		require.NoError(t, err)

		vcWallet, err := New(sampleUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, vcWallet)

		// get token
		err = vcWallet.Open(wallet.WithUnlockByAuthorizationToken(sampleRemoteKMSAuth))
		require.NoError(t, err)
		token, err := vcWallet.auth()
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer vcWallet.Close()

		// try again
		err = vcWallet.Open(wallet.WithUnlockByAuthorizationToken(sampleRemoteKMSAuth))
		require.Error(t, err)
		require.True(t, errors.Is(err, wallet.ErrAlreadyUnlocked))
		token, err = vcWallet.auth()
		require.NoError(t, err)
		require.NotEmpty(t, token)

		// close wallet
		require.True(t, vcWallet.Close())
		require.False(t, vcWallet.Close())
		token, err = vcWallet.auth()
		require.Empty(t, token)
		require.Error(t, err)
		require.True(t, errors.Is(err, ErrWalletLocked))
	})
}

func TestClient_Export(t *testing.T) {
	mockctx := newMockProvider()
	err := CreateProfile(sampleUserID, mockctx, wallet.WithKeyServerURL(sampleKeyServerURL))
	require.NoError(t, err)

	vcWalletClient, err := New(sampleUserID, mockctx)
	require.NotEmpty(t, vcWalletClient)
	require.NoError(t, err)

	result, err := vcWalletClient.Export("")
	require.Empty(t, result)
	require.Error(t, err)
	require.EqualError(t, err, toBeImplementedErr)
}

func TestClient_Import(t *testing.T) {
	mockctx := newMockProvider()
	err := CreateProfile(sampleUserID, mockctx, wallet.WithKeyServerURL(sampleKeyServerURL))
	require.NoError(t, err)

	vcWalletClient, err := New(sampleUserID, mockctx)
	require.NotEmpty(t, vcWalletClient)
	require.NoError(t, err)

	err = vcWalletClient.Import("", nil)
	require.Error(t, err)
	require.EqualError(t, err, toBeImplementedErr)
}

func TestClient_Add(t *testing.T) {
	mockctx := newMockProvider()
	err := CreateProfile(sampleUserID, mockctx, wallet.WithKeyServerURL(sampleKeyServerURL))
	require.NoError(t, err)

	vcWalletClient, err := New(sampleUserID, mockctx)
	require.NotEmpty(t, vcWalletClient)
	require.NoError(t, err)

	err = vcWalletClient.Add(wallet.Metadata, []byte(sampleContentValid))
	require.NoError(t, err)
}

func TestClient_Get(t *testing.T) {
	mockctx := newMockProvider()
	err := CreateProfile(sampleUserID, mockctx, wallet.WithKeyServerURL(sampleKeyServerURL))
	require.NoError(t, err)

	vcWalletClient, err := New(sampleUserID, mockctx)
	require.NotEmpty(t, vcWalletClient)
	require.NoError(t, err)

	err = vcWalletClient.Add(wallet.Metadata, []byte(sampleContentValid))
	require.NoError(t, err)

	content, err := vcWalletClient.Get(wallet.Metadata, "did:example:123456789abcdefghi")
	require.NoError(t, err)
	require.NotEmpty(t, content)
	require.Equal(t, sampleContentValid, string(content))
}

func TestClient_Remove(t *testing.T) {
	mockctx := newMockProvider()
	err := CreateProfile(sampleUserID, mockctx, wallet.WithKeyServerURL(sampleKeyServerURL))
	require.NoError(t, err)

	vcWalletClient, err := New(sampleUserID, mockctx)
	require.NotEmpty(t, vcWalletClient)
	require.NoError(t, err)

	err = vcWalletClient.Add(wallet.Metadata, []byte(sampleContentValid))
	require.NoError(t, err)

	content, err := vcWalletClient.Get(wallet.Metadata, "did:example:123456789abcdefghi")
	require.NoError(t, err)
	require.NotEmpty(t, content)

	err = vcWalletClient.Remove(wallet.Metadata, "did:example:123456789abcdefghi")
	require.NoError(t, err)

	content, err = vcWalletClient.Get(wallet.Metadata, "did:example:123456789abcdefghi")
	require.Empty(t, content)
	require.Error(t, err)
	require.True(t, errors.Is(err, storage.ErrDataNotFound))
}

func TestClient_Query(t *testing.T) {
	mockctx := newMockProvider()
	err := CreateProfile(sampleUserID, mockctx, wallet.WithKeyServerURL(sampleKeyServerURL))
	require.NoError(t, err)

	vcWalletClient, err := New(sampleUserID, mockctx)
	require.NotEmpty(t, vcWalletClient)
	require.NoError(t, err)

	results, err := vcWalletClient.Query(&wallet.QueryParams{})
	require.Empty(t, results)
	require.Error(t, err)
	require.EqualError(t, err, toBeImplementedErr)
}

func TestClient_Issue(t *testing.T) {
	customVDR := &mockvdr.MockVDRegistry{
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

	mockctx := newMockProvider()
	mockctx.VDRegistryValue = customVDR
	mockctx.CryptoValue = &cryptomock.Crypto{}

	err := CreateProfile(sampleUserID, mockctx, wallet.WithPassphrase(samplePassPhrase))
	require.NoError(t, err)

	t.Run("Test VC wallet client issue using controller - failure", func(t *testing.T) {
		vcWalletClient, err := New(sampleUserID, mockctx, wallet.WithUnlockByPassphrase(samplePassPhrase))
		require.NotEmpty(t, vcWalletClient)
		require.NoError(t, err)

		defer vcWalletClient.Close()

		// sign with just controller
		result, err := vcWalletClient.Issue([]byte(sampleUDCVC), &wallet.ProofOptions{
			Controller: sampleDIDKey,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to read json keyset from reader")
		require.Empty(t, result)
	})

	t.Run("Test VC wallet client issue using controller - wallet locked", func(t *testing.T) {
		vcWalletClient, err := New(sampleUserID, mockctx)
		require.NotEmpty(t, vcWalletClient)
		require.NoError(t, err)

		defer vcWalletClient.Close()

		// sign with just controller
		result, err := vcWalletClient.Issue([]byte(sampleUDCVC), &wallet.ProofOptions{
			Controller: sampleDIDKey,
		})
		require.Error(t, err)
		require.True(t, errors.Is(err, ErrWalletLocked))
		require.Empty(t, result)
	})
}

func TestClient_Prove(t *testing.T) {
	customVDR := &mockvdr.MockVDRegistry{
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

	mockctx := newMockProvider()
	mockctx.VDRegistryValue = customVDR
	mockctx.CryptoValue = &cryptomock.Crypto{}

	err := CreateProfile(sampleUserID, mockctx, wallet.WithPassphrase(samplePassPhrase))
	require.NoError(t, err)

	t.Run("Test VC wallet client prove using controller - failure", func(t *testing.T) {
		vcWalletClient, err := New(sampleUserID, mockctx, wallet.WithUnlockByPassphrase(samplePassPhrase))
		require.NotEmpty(t, vcWalletClient)
		require.NoError(t, err)

		defer vcWalletClient.Close()

		require.NoError(t, vcWalletClient.Add(wallet.Credential, []byte(sampleUDCVC)))

		result, err := vcWalletClient.Prove(&wallet.ProofOptions{Controller: sampleDIDKey},
			wallet.WithStoredCredentialsToPresent("http://example.edu/credentials/1872"),
			wallet.WithRawCredentialsToPresent([]byte(sampleUDCVC)),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to read json keyset from reader")
		require.Empty(t, result)
	})

	t.Run("Test VC wallet client prove using controller - wallet locked", func(t *testing.T) {
		vcWalletClient, err := New(sampleUserID, mockctx)
		require.NotEmpty(t, vcWalletClient)
		require.NoError(t, err)

		defer vcWalletClient.Close()

		require.NoError(t, vcWalletClient.Add(wallet.Credential, []byte(sampleUDCVC)))

		result, err := vcWalletClient.Prove(&wallet.ProofOptions{Controller: sampleDIDKey},
			wallet.WithStoredCredentialsToPresent("http://example.edu/credentials/1872"),
			wallet.WithRawCredentialsToPresent([]byte(sampleUDCVC)),
		)
		require.Error(t, err)
		require.True(t, errors.Is(err, ErrWalletLocked))
		require.Empty(t, result)
	})
}

func TestClient_Verify(t *testing.T) {
	customVDR := &mockvdr.MockVDRegistry{
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

	mockctx := newMockProvider()
	mockctx.VDRegistryValue = customVDR
	mockctx.CryptoValue = &cryptomock.Crypto{}

	err := CreateProfile(sampleUserID, mockctx, wallet.WithPassphrase(samplePassPhrase))
	require.NoError(t, err)

	t.Run("Test VC wallet verify credential - success", func(t *testing.T) {
		vcWalletClient, err := New(sampleUserID, mockctx, wallet.WithUnlockByPassphrase(samplePassPhrase))
		require.NotEmpty(t, vcWalletClient)
		require.NoError(t, err)

		defer vcWalletClient.Close()

		// store credential in wallet
		require.NoError(t, vcWalletClient.Add(wallet.Credential, []byte(sampleUDCVCWithProof)))

		ok, err := vcWalletClient.Verify("http://example.edu/credentials/1872")
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("Test VC wallet verify credential - invalid signature", func(t *testing.T) {
		vcWalletClient, err := New(sampleUserID, mockctx, wallet.WithUnlockByPassphrase(samplePassPhrase))
		require.NotEmpty(t, vcWalletClient)
		require.NoError(t, err)

		defer vcWalletClient.Close()

		// store tampered credential in wallet
		tamperedVC := strings.ReplaceAll(sampleUDCVCWithProof, `"name": "Example University"`, `"name": "Fake University"`)
		require.NoError(t, vcWalletClient.Add(wallet.Credential, []byte(tamperedVC)))

		ok, err := vcWalletClient.Verify("http://example.edu/credentials/1872")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid signature")
		require.False(t, ok)
	})
}

func newMockProvider() *mockprovider.Provider {
	return &mockprovider.Provider{StorageProviderValue: mockstorage.NewMockStoreProvider()}
}

func createSampleProfile(t *testing.T, mockctx *mockprovider.Provider) {
	err := CreateProfile(sampleUserID, mockctx, wallet.WithPassphrase(samplePassPhrase))
	require.NoError(t, err)

	vcWallet, err := New(sampleUserID, mockctx)
	require.NoError(t, err)
	require.NotEmpty(t, vcWallet)
}

type mockStorageProvider struct {
	*mockstorage.MockStoreProvider
	config  storage.StoreConfiguration
	failure error
}

func (s *mockStorageProvider) SetStoreConfig(name string, config storage.StoreConfiguration) error {
	s.config = config

	return s.failure
}

func (s *mockStorageProvider) GetStoreConfig(name string) (storage.StoreConfiguration, error) {
	return s.config, nil
}
