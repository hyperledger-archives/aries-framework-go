/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcwallet

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/mock/secretlock"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local/masterlock/pbkdf2"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	sampleUserID       = "sample-user01"
	toBeImplementedErr = "to be implemented"
	sampleClientErr    = "sample client err"
)

func TestCreate(t *testing.T) {
	t.Run("test create new wallet client using local kms passphrase", func(t *testing.T) {
		mockctx := newMockProvider()
		err := CreateProfile(sampleUserID, mockctx, WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		wallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)
	})

	t.Run("test create new wallet client using local kms secret lock service", func(t *testing.T) {
		mockctx := newMockProvider()
		err := CreateProfile(sampleUserID, mockctx, WithSecretLockService(&secretlock.MockSecretLock{}))
		require.NoError(t, err)

		wallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)
	})

	t.Run("test create new wallet client using remote kms key server URL", func(t *testing.T) {
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
		mockctx.storeProvider = &mockstorage.MockStoreProvider{
			ErrOpenStoreHandle: fmt.Errorf(sampleClientErr),
		}

		err := CreateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL))
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleClientErr)

		wallet, err := New(sampleUserID, mockctx)
		require.Error(t, err)
		require.Empty(t, wallet)
	})

	t.Run("test create new wallet failure - save profile error", func(t *testing.T) {
		mockctx := newMockProvider()
		mockctx.storeProvider = &mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{
				ErrPut: fmt.Errorf(sampleClientErr),
			},
		}

		err := CreateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL))
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleClientErr)

		wallet, err := New(sampleUserID, mockctx)
		require.Error(t, err)
		require.Empty(t, wallet)
	})
}

func TestUpdate(t *testing.T) {
	t.Run("test update wallet client using local kms passphrase", func(t *testing.T) {
		mockctx := newMockProvider()
		err := UpdateProfile(sampleUserID, mockctx, WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		wallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)
	})

	t.Run("test update wallet client using local kms secret lock service", func(t *testing.T) {
		mockctx := newMockProvider()
		err := UpdateProfile(sampleUserID, mockctx, WithSecretLockService(&secretlock.MockSecretLock{}))
		require.NoError(t, err)

		wallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)
	})

	t.Run("test update wallet client using remote kms key server URL", func(t *testing.T) {
		mockctx := newMockProvider()
		err := UpdateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL))
		require.NoError(t, err)

		wallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)
	})

	t.Run("test update wallet failure", func(t *testing.T) {
		mockctx := newMockProvider()
		err := UpdateProfile(sampleUserID, mockctx)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid create profile options")

		wallet, err := New(sampleUserID, mockctx)
		require.Error(t, err)
		require.Empty(t, wallet)
	})

	t.Run("test update wallet failure - create store error", func(t *testing.T) {
		mockctx := newMockProvider()
		mockctx.storeProvider = &mockstorage.MockStoreProvider{
			ErrOpenStoreHandle: fmt.Errorf(sampleClientErr),
		}

		err := UpdateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL))
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleClientErr)

		wallet, err := New(sampleUserID, mockctx)
		require.Error(t, err)
		require.Empty(t, wallet)
	})

	t.Run("test update wallet failure - save profile error", func(t *testing.T) {
		mockctx := newMockProvider()
		mockctx.storeProvider = &mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{
				ErrPut: fmt.Errorf(sampleClientErr),
			},
		}

		err := UpdateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL))
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleClientErr)

		wallet, err := New(sampleUserID, mockctx)
		require.Error(t, err)
		require.Empty(t, wallet)
	})
}

func TestNew(t *testing.T) {
	t.Run("test get client by user", func(t *testing.T) {
		mockctx := newMockProvider()
		// create a wallet
		err := CreateProfile(sampleUserID, mockctx, WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		wallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)
	})

	t.Run("test get client by invalid userID", func(t *testing.T) {
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
		mockctx.storeProvider = &mockstorage.MockStoreProvider{
			ErrOpenStoreHandle: fmt.Errorf(sampleClientErr),
		}

		wallet, err := New(sampleUserID, mockctx)
		require.Error(t, err)
		require.Empty(t, wallet)
		require.Contains(t, err.Error(), sampleClientErr)
	})
}

func TestClient_OpenClose(t *testing.T) {
	t.Run("test open & close wallet using local kms passphrase", func(t *testing.T) {
		mockctx := newMockProvider()
		err := CreateProfile(sampleUserID, mockctx, WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		wallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		// get token
		token, err := wallet.Open(samplePassPhrase, nil, 0)
		require.NoError(t, err)
		require.NotEmpty(t, token)

		// try again
		token, err = wallet.Open(samplePassPhrase, nil, 0)
		require.Empty(t, token)
		require.Error(t, err)
		require.Equal(t, err, ErrAlreadyUnlocked)

		// close wallet
		require.True(t, wallet.Close())
		require.False(t, wallet.Close())

		// try to open with wrong passphrase
		token, err = wallet.Open(samplePassPhrase+"wrong", nil, 0)
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
		token, err := wallet.Open("", masterLock, 0)
		require.NoError(t, err)
		require.NotEmpty(t, token)

		// try again
		token, err = wallet.Open("", masterLock, 0)
		require.Empty(t, token)
		require.Error(t, err)
		require.Equal(t, err, ErrAlreadyUnlocked)

		// close wallet
		require.True(t, wallet.Close())
		require.False(t, wallet.Close())

		// try to open with wrong secret lock service
		badLock, err := pbkdf2.NewMasterLock(samplePassPhrase+"wrong", sha256.New, 0, nil)
		require.NoError(t, err)

		token, err = wallet.Open("", badLock, 0)
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
		token, err := wallet.Open(sampleRemoteKMSAuth, nil, 0)
		require.NoError(t, err)
		require.NotEmpty(t, token)

		// try again
		token, err = wallet.Open(sampleRemoteKMSAuth, nil, 0)
		require.Empty(t, token)
		require.Error(t, err)
		require.Equal(t, err, ErrAlreadyUnlocked)

		// close wallet
		require.True(t, wallet.Close())
		require.False(t, wallet.Close())
	})
}

func TestClient_Export(t *testing.T) {
	mockctx := newMockProvider()
	err := CreateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL))
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
	err := CreateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL))
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
	err := CreateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL))
	require.NoError(t, err)

	vcWalletClient, err := New(sampleUserID, mockctx)
	require.NotEmpty(t, vcWalletClient)
	require.NoError(t, err)

	err = vcWalletClient.Add(nil)
	require.Error(t, err)
	require.EqualError(t, err, toBeImplementedErr)
}

func TestClient_Remove(t *testing.T) {
	mockctx := newMockProvider()
	err := CreateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL))
	require.NoError(t, err)

	vcWalletClient, err := New(sampleUserID, mockctx)
	require.NotEmpty(t, vcWalletClient)
	require.NoError(t, err)

	err = vcWalletClient.Remove("")
	require.Error(t, err)
	require.EqualError(t, err, toBeImplementedErr)
}

func TestClient_Get(t *testing.T) {
	mockctx := newMockProvider()
	err := CreateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL))
	require.NoError(t, err)

	vcWalletClient, err := New(sampleUserID, mockctx)
	require.NotEmpty(t, vcWalletClient)
	require.NoError(t, err)

	result, err := vcWalletClient.Get("")
	require.Empty(t, result)
	require.Error(t, err)
	require.EqualError(t, err, toBeImplementedErr)
}

func TestClient_Query(t *testing.T) {
	mockctx := newMockProvider()
	err := CreateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL))
	require.NoError(t, err)

	vcWalletClient, err := New(sampleUserID, mockctx)
	require.NotEmpty(t, vcWalletClient)
	require.NoError(t, err)

	results, err := vcWalletClient.Query(&QueryParams{})
	require.Empty(t, results)
	require.Error(t, err)
	require.EqualError(t, err, toBeImplementedErr)
}

func TestClient_Issue(t *testing.T) {
	mockctx := newMockProvider()
	err := CreateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL))
	require.NoError(t, err)

	vcWalletClient, err := New(sampleUserID, mockctx)
	require.NotEmpty(t, vcWalletClient)
	require.NoError(t, err)

	result, err := vcWalletClient.Issue(nil, &ProofOptions{})
	require.Empty(t, result)
	require.Error(t, err)
	require.EqualError(t, err, toBeImplementedErr)
}

func TestClient_Prove(t *testing.T) {
	mockctx := newMockProvider()
	err := CreateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL))
	require.NoError(t, err)

	vcWalletClient, err := New(sampleUserID, mockctx)
	require.NotEmpty(t, vcWalletClient)
	require.NoError(t, err)

	result, err := vcWalletClient.Prove(nil, &ProofOptions{})
	require.Empty(t, result)
	require.Error(t, err)
	require.EqualError(t, err, toBeImplementedErr)
}

func TestClient_Verify(t *testing.T) {
	mockctx := newMockProvider()
	err := CreateProfile(sampleUserID, mockctx, WithKeyServerURL(sampleKeyServerURL))
	require.NoError(t, err)

	vcWalletClient, err := New(sampleUserID, mockctx)
	require.NotEmpty(t, vcWalletClient)
	require.NoError(t, err)

	result, err := vcWalletClient.Verify(nil)
	require.Empty(t, result)
	require.Error(t, err)
	require.EqualError(t, err, toBeImplementedErr)
}

type mockProvider struct {
	storeProvider storage.Provider
}

// StorageProvider returns the mock storage provider.
func (p *mockProvider) StorageProvider() storage.Provider {
	return p.storeProvider
}

func newMockProvider() *mockProvider {
	return &mockProvider{storeProvider: mockstorage.NewMockStoreProvider()}
}
