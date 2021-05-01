/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcwallet

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/internal/jsonldtest"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

const (
	sampleUserID           = "sample-user01"
	samplePassPhrase       = "fakepassphrase"
	sampleKeyStoreURL      = "sample/keyserver/test"
	sampleEDVServerURL     = "sample-edv-url"
	sampleEDVVaultID       = "sample-edv-vault-id"
	sampleEDVEncryptionKID = "sample-edv-encryption-kid"
	sampleEDVMacKID        = "sample-edv-mac-kid"
	sampleCommandError     = "sample-command-error-01"
)

func TestNew(t *testing.T) {
	t.Run("successfully create new command instance", func(t *testing.T) {
		cmd := New(newMockProvider(t))
		require.NotNil(t, cmd)

		handlers := cmd.GetHandlers()
		require.Equal(t, 2, len(handlers))
	})
}

func TestCommand_CreateProfile(t *testing.T) {
	t.Run("successfully create a new wallet profile (localkms)", func(t *testing.T) {
		mockctx := newMockProvider(t)

		cmd := New(mockctx)
		require.NotNil(t, cmd)

		request := &CreateOrUpdateProfileRequest{
			UserID:             sampleUserID,
			LocalKMSPassphrase: samplePassPhrase,
		}

		var b bytes.Buffer
		cmdErr := cmd.CreateProfile(&b, getReader(t, &request))
		require.NoError(t, cmdErr)

		// if wallet instance can be creates it means profile exists
		walletInstance, err := wallet.New(request.UserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, walletInstance)
	})

	t.Run("successfully create a new wallet profile (webkms/remotekms)", func(t *testing.T) {
		mockctx := newMockProvider(t)

		cmd := New(mockctx)
		require.NotNil(t, cmd)

		request := &CreateOrUpdateProfileRequest{
			UserID:      sampleUserID,
			KeyStoreURL: sampleKeyStoreURL,
		}

		var b bytes.Buffer
		cmdErr := cmd.CreateProfile(&b, getReader(t, &request))
		require.NoError(t, cmdErr)

		// if wallet instance can be creates it means profile exists
		walletInstance, err := wallet.New(request.UserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, walletInstance)
	})

	t.Run("successfully create a new wallet profile with EDV configuration", func(t *testing.T) {
		mockctx := newMockProvider(t)

		cmd := New(mockctx)
		require.NotNil(t, cmd)

		// create with remote kms.
		request := &CreateOrUpdateProfileRequest{
			UserID:      uuid.New().String(),
			KeyStoreURL: sampleKeyStoreURL,
			EDVConfiguration: &EDVConfiguration{
				ServerURL:       sampleEDVServerURL,
				VaultID:         sampleEDVVaultID,
				MACKeyID:        sampleEDVMacKID,
				EncryptionKeyID: sampleEDVEncryptionKID,
			},
		}

		var b1 bytes.Buffer
		cmdErr := cmd.CreateProfile(&b1, getReader(t, &request))
		require.NoError(t, cmdErr)

		// if wallet instance can be creates it means profile exists
		walletInstance, err := wallet.New(request.UserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, walletInstance)

		// create with local kms.
		request = &CreateOrUpdateProfileRequest{
			UserID:             uuid.New().String(),
			LocalKMSPassphrase: samplePassPhrase,
			EDVConfiguration: &EDVConfiguration{
				ServerURL: sampleEDVServerURL,
				VaultID:   sampleEDVVaultID,
			},
		}

		var b2 bytes.Buffer
		cmdErr = cmd.CreateProfile(&b2, getReader(t, &request))
		require.NoError(t, cmdErr)

		// if wallet instance can be creates it means profile exists
		walletInstance, err = wallet.New(request.UserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, walletInstance)
	})

	t.Run("failed to create duplicate profile", func(t *testing.T) {
		mockctx := newMockProvider(t)

		cmd := New(mockctx)
		require.NotNil(t, cmd)

		request := &CreateOrUpdateProfileRequest{
			UserID:             sampleUserID,
			LocalKMSPassphrase: samplePassPhrase,
		}

		var b1 bytes.Buffer
		cmdErr := cmd.CreateProfile(&b1, getReader(t, &request))
		require.NoError(t, cmdErr)

		request = &CreateOrUpdateProfileRequest{
			UserID:      sampleUserID,
			KeyStoreURL: sampleKeyStoreURL,
		}

		var b2 bytes.Buffer
		cmdErr = cmd.CreateProfile(&b2, getReader(t, &request))
		require.Error(t, cmdErr)
		require.Equal(t, cmdErr.Type(), command.ExecuteError)
		require.Equal(t, cmdErr.Code(), CreateProfileErrorCode)
	})

	t.Run("failed to create profile due to invalid settings", func(t *testing.T) {
		mockctx := newMockProvider(t)

		cmd := New(mockctx)
		require.NotNil(t, cmd)

		request := &CreateOrUpdateProfileRequest{
			UserID: sampleUserID,
		}

		var b1 bytes.Buffer
		cmdErr := cmd.CreateProfile(&b1, getReader(t, &request))
		require.Error(t, cmdErr)
		require.Equal(t, cmdErr.Code(), CreateProfileErrorCode)
		require.Equal(t, cmdErr.Type(), command.ExecuteError)
	})

	t.Run("failed to create profile due to invalid request", func(t *testing.T) {
		mockctx := newMockProvider(t)

		cmd := New(mockctx)
		require.NotNil(t, cmd)

		var b1 bytes.Buffer
		cmdErr := cmd.CreateProfile(&b1, bytes.NewBufferString("--"))
		require.Error(t, cmdErr)
		require.Equal(t, cmdErr.Code(), InvalidRequestErrorCode)
		require.Equal(t, cmdErr.Type(), command.ValidationError)
	})

	t.Run("failed to create profile due to EDV key set creation failure", func(t *testing.T) {
		mockctx := newMockProvider(t)

		cmd := New(mockctx)
		require.NotNil(t, cmd)

		mockStProv, ok := mockctx.StorageProviderValue.(*mockstorage.MockStoreProvider)
		require.True(t, ok)
		require.NotEmpty(t, mockStProv)

		mockStProv.Store.ErrGet = errors.New(sampleCommandError)

		request := &CreateOrUpdateProfileRequest{
			UserID:             uuid.New().String(),
			LocalKMSPassphrase: samplePassPhrase,
			EDVConfiguration: &EDVConfiguration{
				ServerURL: sampleEDVServerURL,
				VaultID:   sampleEDVVaultID,
			},
		}

		var b1 bytes.Buffer
		cmdErr := cmd.CreateProfile(&b1, getReader(t, &request))
		require.Error(t, cmdErr)
		require.Equal(t, cmdErr.Code(), CreateProfileErrorCode)
		require.Equal(t, cmdErr.Type(), command.ExecuteError)
		require.Contains(t, cmdErr.Error(), sampleCommandError)
	})
}

func TestCommand_UpdateProfile(t *testing.T) {
	mockctx := newMockProvider(t)

	cmd := New(mockctx)
	require.NotNil(t, cmd)

	createRqst := &CreateOrUpdateProfileRequest{
		UserID:             sampleUserID,
		LocalKMSPassphrase: samplePassPhrase,
	}

	var c bytes.Buffer
	cmdErr := cmd.CreateProfile(&c, getReader(t, &createRqst))
	require.NoError(t, cmdErr)

	t.Run("successfully update a wallet profile", func(t *testing.T) {
		request := &CreateOrUpdateProfileRequest{
			UserID:      sampleUserID,
			KeyStoreURL: sampleKeyStoreURL,
		}

		var b bytes.Buffer
		cmdErr := cmd.UpdateProfile(&b, getReader(t, &createRqst))
		require.NoError(t, cmdErr)

		// if wallet instance can be creates it means profile exists
		walletInstance, err := wallet.New(request.UserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, walletInstance)
	})

	t.Run("successfully update a wallet profile with EDV configuration", func(t *testing.T) {
		// create with remote kms.
		request := &CreateOrUpdateProfileRequest{
			UserID:      sampleUserID,
			KeyStoreURL: sampleKeyStoreURL,
			EDVConfiguration: &EDVConfiguration{
				ServerURL:       sampleEDVServerURL,
				VaultID:         sampleEDVVaultID,
				MACKeyID:        sampleEDVMacKID,
				EncryptionKeyID: sampleEDVEncryptionKID,
			},
		}

		var b1 bytes.Buffer
		cmdErr := cmd.UpdateProfile(&b1, getReader(t, &request))
		require.NoError(t, cmdErr)

		// if wallet instance can be creates it means profile exists
		walletInstance, err := wallet.New(request.UserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, walletInstance)
	})

	t.Run("failed to update profile due to invalid settings", func(t *testing.T) {
		request := &CreateOrUpdateProfileRequest{
			UserID: sampleUserID,
		}

		var b1 bytes.Buffer
		cmdErr := cmd.UpdateProfile(&b1, getReader(t, &request))
		require.Error(t, cmdErr)
		require.Equal(t, cmdErr.Code(), UpdateProfileErrorCode)
		require.Equal(t, cmdErr.Type(), command.ExecuteError)
	})

	t.Run("failed to update profile due to invalid request", func(t *testing.T) {
		var b1 bytes.Buffer
		cmdErr := cmd.UpdateProfile(&b1, bytes.NewBufferString("--"))
		require.Error(t, cmdErr)
		require.Equal(t, cmdErr.Code(), InvalidRequestErrorCode)
		require.Equal(t, cmdErr.Type(), command.ValidationError)
	})
}

func getReader(t *testing.T, v interface{}) io.Reader {
	vcReqBytes, err := json.Marshal(v)
	require.NoError(t, err)

	return bytes.NewBuffer(vcReqBytes)
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
