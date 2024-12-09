/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcwallet

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/internal/testdata"
	outofbandClient "github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/didcommwallet"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/vcwallet"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	issuecredentialsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	outofbandSvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"
	oobv2 "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofbandv2"
	presentproofSvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	mockoutofbandv2 "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/client/outofbandv2"
	"github.com/hyperledger/aries-framework-go/pkg/internal/ldtestutil"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockdidexchange "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/didexchange"
	mockissuecredential "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/issuecredential"
	mockmediator "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/mediator"
	mockoutofband "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/outofband"
	mockpresentproof "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/presentproof"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"
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
	sampleFakeTkn          = "sample-fake-token-01"
	sampleDIDKey           = "did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5"
	webRedirectStatusKey   = "status"
	webRedirectURLKey      = "url"
	exampleWebRedirect     = "http://example.com/sample"
)

func TestNew(t *testing.T) {
	t.Run("successfully create rest command instance", func(t *testing.T) {
		cmd := New(newMockProvider(t), &vcwallet.Config{})
		require.NotNil(t, cmd)

		require.Len(t, cmd.GetRESTHandlers(), 21)
	})
}

func TestOperation_CreateProfile(t *testing.T) {
	t.Run("successfully create a new wallet profile (localkms)", func(t *testing.T) {
		mockctx := newMockProvider(t)

		cmd := New(mockctx, &vcwallet.Config{})
		require.NotNil(t, cmd)

		request := &vcwallet.CreateOrUpdateProfileRequest{
			UserID:             sampleUserID,
			LocalKMSPassphrase: samplePassPhrase,
		}

		rq := httptest.NewRequest(http.MethodPost, CreateProfilePath, getReader(t, &request))
		rw := httptest.NewRecorder()
		cmd.CreateProfile(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)
	})

	t.Run("successfully create a new wallet profile (webkms/remotekms)", func(t *testing.T) {
		mockctx := newMockProvider(t)

		cmd := New(mockctx, &vcwallet.Config{})
		require.NotNil(t, cmd)

		request := &vcwallet.CreateOrUpdateProfileRequest{
			UserID:      sampleUserID,
			KeyStoreURL: sampleKeyStoreURL,
		}

		rq := httptest.NewRequest(http.MethodPost, CreateProfilePath, getReader(t, &request))
		rw := httptest.NewRecorder()
		cmd.CreateProfile(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)
	})

	t.Run("successfully create a new wallet profile with EDV configuration", func(t *testing.T) {
		mockctx := newMockProvider(t)

		cmd := New(mockctx, &vcwallet.Config{})
		require.NotNil(t, cmd)

		// create with remote kms.
		request := &vcwallet.CreateOrUpdateProfileRequest{
			UserID:      uuid.New().String(),
			KeyStoreURL: sampleKeyStoreURL,
			EDVConfiguration: &vcwallet.EDVConfiguration{
				ServerURL:       sampleEDVServerURL,
				VaultID:         sampleEDVVaultID,
				MACKeyID:        sampleEDVMacKID,
				EncryptionKeyID: sampleEDVEncryptionKID,
			},
		}

		rq := httptest.NewRequest(http.MethodPost, CreateProfilePath, getReader(t, &request))
		rw := httptest.NewRecorder()
		cmd.CreateProfile(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)

		// if wallet instance can be creates it means profile exists
		walletInstance, err := wallet.New(request.UserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, walletInstance)

		// create with local kms.
		request = &vcwallet.CreateOrUpdateProfileRequest{
			UserID:             uuid.New().String(),
			LocalKMSPassphrase: samplePassPhrase,
			EDVConfiguration: &vcwallet.EDVConfiguration{
				ServerURL: sampleEDVServerURL,
				VaultID:   sampleEDVVaultID,
			},
		}

		rq = httptest.NewRequest(http.MethodPost, CreateProfilePath, getReader(t, &request))
		rw = httptest.NewRecorder()
		cmd.CreateProfile(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)
	})

	t.Run("failed to create duplicate profile", func(t *testing.T) {
		mockctx := newMockProvider(t)

		cmd := New(mockctx, &vcwallet.Config{})
		require.NotNil(t, cmd)

		request := &vcwallet.CreateOrUpdateProfileRequest{
			UserID:             sampleUserID,
			LocalKMSPassphrase: samplePassPhrase,
		}

		rq := httptest.NewRequest(http.MethodPost, CreateProfilePath, getReader(t, &request))
		rw := httptest.NewRecorder()
		cmd.CreateProfile(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)

		request = &vcwallet.CreateOrUpdateProfileRequest{
			UserID:      sampleUserID,
			KeyStoreURL: sampleKeyStoreURL,
		}

		rq = httptest.NewRequest(http.MethodPost, CreateProfilePath, getReader(t, &request))
		rw = httptest.NewRecorder()
		cmd.CreateProfile(rw, rq)
		require.Equal(t, http.StatusInternalServerError, rw.Code)
	})

	t.Run("failed to create profile due to invalid settings", func(t *testing.T) {
		mockctx := newMockProvider(t)

		cmd := New(mockctx, &vcwallet.Config{})
		require.NotNil(t, cmd)

		request := &vcwallet.CreateOrUpdateProfileRequest{
			UserID: sampleUserID,
		}

		rq := httptest.NewRequest(http.MethodPost, CreateProfilePath, getReader(t, &request))
		rw := httptest.NewRecorder()
		cmd.CreateProfile(rw, rq)
		require.Equal(t, http.StatusInternalServerError, rw.Code)
	})

	t.Run("failed to create profile due to invalid request", func(t *testing.T) {
		mockctx := newMockProvider(t)

		cmd := New(mockctx, &vcwallet.Config{})
		require.NotNil(t, cmd)

		rq := httptest.NewRequest(http.MethodPost, CreateProfilePath, getReader(t, "--"))
		rw := httptest.NewRecorder()
		cmd.CreateProfile(rw, rq)
		require.Equal(t, http.StatusBadRequest, rw.Code)
	})

	t.Run("failed to create profile due to EDV key set creation failure", func(t *testing.T) {
		mockctx := newMockProvider(t)

		cmd := New(mockctx, &vcwallet.Config{})
		require.NotNil(t, cmd)

		mockStProv, ok := mockctx.StorageProviderValue.(*mockstorage.MockStoreProvider)
		require.True(t, ok)
		require.NotEmpty(t, mockStProv)

		mockStProv.Store.ErrGet = errors.New(sampleCommandError)

		request := &vcwallet.CreateOrUpdateProfileRequest{
			UserID:             uuid.New().String(),
			LocalKMSPassphrase: samplePassPhrase,
			EDVConfiguration: &vcwallet.EDVConfiguration{
				ServerURL: sampleEDVServerURL,
				VaultID:   sampleEDVVaultID,
			},
		}

		rq := httptest.NewRequest(http.MethodPost, CreateProfilePath, getReader(t, &request))
		rw := httptest.NewRecorder()
		cmd.CreateProfile(rw, rq)
		require.Equal(t, http.StatusInternalServerError, rw.Code)
	})
}

func TestOperation_UpdateProfile(t *testing.T) {
	mockctx := newMockProvider(t)

	cmd := New(mockctx, &vcwallet.Config{})
	require.NotNil(t, cmd)

	createRqst := &vcwallet.CreateOrUpdateProfileRequest{
		UserID:             sampleUserID,
		LocalKMSPassphrase: samplePassPhrase,
	}

	rq := httptest.NewRequest(http.MethodPost, UpdateProfilePath, getReader(t, &createRqst))
	rw := httptest.NewRecorder()
	cmd.CreateProfile(rw, rq)
	require.Equal(t, http.StatusOK, rw.Code)

	t.Run("successfully update a wallet profile", func(t *testing.T) {
		request := &vcwallet.CreateOrUpdateProfileRequest{
			UserID:      sampleUserID,
			KeyStoreURL: sampleKeyStoreURL,
		}

		rq := httptest.NewRequest(http.MethodPost, UpdateProfilePath, getReader(t, &request))
		rw := httptest.NewRecorder()
		cmd.UpdateProfile(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)
	})

	t.Run("successfully update a wallet profile with EDV configuration", func(t *testing.T) {
		// create with remote kms.
		request := &vcwallet.CreateOrUpdateProfileRequest{
			UserID:      sampleUserID,
			KeyStoreURL: sampleKeyStoreURL,
			EDVConfiguration: &vcwallet.EDVConfiguration{
				ServerURL:       sampleEDVServerURL,
				VaultID:         sampleEDVVaultID,
				MACKeyID:        sampleEDVMacKID,
				EncryptionKeyID: sampleEDVEncryptionKID,
			},
		}

		rq := httptest.NewRequest(http.MethodPost, UpdateProfilePath, getReader(t, &request))
		rw := httptest.NewRecorder()
		cmd.UpdateProfile(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)
	})

	t.Run("failed to update profile due to invalid settings", func(t *testing.T) {
		request := &vcwallet.CreateOrUpdateProfileRequest{
			UserID: sampleUserID,
		}

		rq := httptest.NewRequest(http.MethodPost, UpdateProfilePath, getReader(t, &request))
		rw := httptest.NewRecorder()
		cmd.UpdateProfile(rw, rq)
		require.Equal(t, http.StatusInternalServerError, rw.Code)
	})

	t.Run("failed to update profile due to invalid request", func(t *testing.T) {
		rq := httptest.NewRequest(http.MethodPost, UpdateProfilePath, getReader(t, "---"))
		rw := httptest.NewRecorder()
		cmd.UpdateProfile(rw, rq)
		require.Equal(t, http.StatusBadRequest, rw.Code)
	})
}

func TestCommand_ProfileExists(t *testing.T) {
	const (
		sampleUser1 = "sample-user-01"
		sampleUser2 = "sample-user-02"
	)

	mockctx := newMockProvider(t)

	createSampleUserProfile(t, mockctx, &vcwallet.CreateOrUpdateProfileRequest{
		UserID:             sampleUser1,
		LocalKMSPassphrase: samplePassPhrase,
	})

	t.Run("profile exists", func(t *testing.T) {
		cmd := New(mockctx, &vcwallet.Config{})
		require.NotNil(t, cmd)

		rw := httptest.NewRecorder()
		rq := mux.SetURLVars(httptest.NewRequest(http.MethodGet, ProfileExistsPath, nil), map[string]string{
			"id": sampleUser1,
		})

		cmd.ProfileExists(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)
		require.Empty(t, rw.Body.String())
	})

	t.Run("profile doesn't exists", func(t *testing.T) {
		cmd := New(mockctx, &vcwallet.Config{})
		require.NotNil(t, cmd)

		rw := httptest.NewRecorder()
		rq := mux.SetURLVars(httptest.NewRequest(http.MethodGet, ProfileExistsPath, nil), map[string]string{
			"id": sampleUser2,
		})

		cmd.ProfileExists(rw, rq)
		require.Equal(t, http.StatusInternalServerError, rw.Code)
		require.Contains(t, rw.Body.String(), wallet.ErrProfileNotFound.Error())
	})

	t.Run("invalid request", func(t *testing.T) {
		cmd := New(mockctx, &vcwallet.Config{})
		require.NotNil(t, cmd)

		rw := httptest.NewRecorder()
		rq := httptest.NewRequest(http.MethodGet, ProfileExistsPath, nil)

		cmd.ProfileExists(rw, rq)
		require.Equal(t, http.StatusBadRequest, rw.Code)
		require.Contains(t, rw.Body.String(), "empty profile ID")
	})
}

func TestOperation_OpenAndClose(t *testing.T) {
	const (
		sampleUser1 = "sample-user-01"
		sampleUser2 = "sample-user-02"
		sampleUser3 = "sample-user-03"
	)

	mockctx := newMockProvider(t)

	createSampleUserProfile(t, mockctx, &vcwallet.CreateOrUpdateProfileRequest{
		UserID:             sampleUser1,
		LocalKMSPassphrase: samplePassPhrase,
	})

	createSampleUserProfile(t, mockctx, &vcwallet.CreateOrUpdateProfileRequest{
		UserID:      sampleUser2,
		KeyStoreURL: sampleKeyStoreURL,
	})

	createSampleUserProfile(t, mockctx, &vcwallet.CreateOrUpdateProfileRequest{
		UserID:             sampleUser3,
		LocalKMSPassphrase: samplePassPhrase,
		EDVConfiguration: &vcwallet.EDVConfiguration{
			ServerURL: sampleEDVServerURL,
			VaultID:   sampleEDVVaultID,
		},
	})

	t.Run("successfully unlock & lock wallet (local kms)", func(t *testing.T) {
		cmd := New(mockctx, &vcwallet.Config{})

		request := &vcwallet.UnlockWalletRequest{
			UserID:             sampleUser1,
			LocalKMSPassphrase: samplePassPhrase,
		}

		// unlock wallet
		rq := httptest.NewRequest(http.MethodPost, OpenPath, getReader(t, request))
		rw := httptest.NewRecorder()
		cmd.Open(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)
		require.NotEmpty(t, getUnlockToken(t, rw.Body))

		// try again, should get error, wallet already unlocked
		rq = httptest.NewRequest(http.MethodPost, OpenPath, getReader(t, request))
		rw = httptest.NewRecorder()
		cmd.Open(rw, rq)
		require.Equal(t, http.StatusInternalServerError, rw.Code)

		// lock wallet
		rq = httptest.NewRequest(http.MethodPost, ClosePath,
			getReader(t, &vcwallet.LockWalletRequest{UserID: sampleUser1}))
		rw = httptest.NewRecorder()
		cmd.Close(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)
		require.Contains(t, rw.Body.String(), `{"closed":true}`)

		// lock wallet again
		rq = httptest.NewRequest(http.MethodPost, ClosePath,
			getReader(t, &vcwallet.LockWalletRequest{UserID: sampleUser1}))
		rw = httptest.NewRecorder()
		cmd.Close(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)
		require.Contains(t, rw.Body.String(), `{"closed":false}`)
	})

	t.Run("successfully unlock & lock wallet (remote kms)", func(t *testing.T) {
		cmd := New(mockctx, &vcwallet.Config{})

		request := &vcwallet.UnlockWalletRequest{
			UserID:     sampleUser2,
			WebKMSAuth: &vcwallet.UnlockAuth{AuthToken: sampleFakeTkn},
		}

		// unlock wallet
		rq := httptest.NewRequest(http.MethodPost, OpenPath, getReader(t, request))
		rw := httptest.NewRecorder()
		cmd.Open(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)
		require.NotEmpty(t, getUnlockToken(t, rw.Body))

		// try again, should get error, wallet already unlocked
		rq = httptest.NewRequest(http.MethodPost, OpenPath, getReader(t, request))
		rw = httptest.NewRecorder()
		cmd.Open(rw, rq)
		require.Equal(t, http.StatusInternalServerError, rw.Code)

		// lock wallet
		rq = httptest.NewRequest(http.MethodPost, ClosePath,
			getReader(t, &vcwallet.LockWalletRequest{UserID: sampleUser2}))
		rw = httptest.NewRecorder()
		cmd.Close(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)
		require.Contains(t, rw.Body.String(), `{"closed":true}`)

		// lock wallet again
		rq = httptest.NewRequest(http.MethodPost, ClosePath,
			getReader(t, &vcwallet.LockWalletRequest{UserID: sampleUser2}))
		rw = httptest.NewRecorder()
		cmd.Close(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)
		require.Contains(t, rw.Body.String(), `{"closed":false}`)
	})

	t.Run("successfully unlock & lock wallet (local kms, edv user)", func(t *testing.T) {
		cmd := New(mockctx, &vcwallet.Config{})

		request := &vcwallet.UnlockWalletRequest{
			UserID:             sampleUser3,
			LocalKMSPassphrase: samplePassPhrase,
			EDVUnlock: &vcwallet.UnlockAuth{
				AuthToken: sampleFakeTkn,
			},
		}

		// unlock wallet
		rq := httptest.NewRequest(http.MethodPost, OpenPath, getReader(t, request))
		rw := httptest.NewRecorder()
		cmd.Open(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)
		require.NotEmpty(t, getUnlockToken(t, rw.Body))

		// try again, should get error, wallet already unlocked
		rq = httptest.NewRequest(http.MethodPost, OpenPath, getReader(t, request))
		rw = httptest.NewRecorder()
		cmd.Open(rw, rq)
		require.Equal(t, http.StatusInternalServerError, rw.Code)

		// lock wallet
		rq = httptest.NewRequest(http.MethodPost, ClosePath,
			getReader(t, &vcwallet.LockWalletRequest{UserID: sampleUser3}))
		rw = httptest.NewRecorder()
		cmd.Close(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)
		require.Contains(t, rw.Body.String(), `{"closed":true}`)

		// lock wallet again
		rq = httptest.NewRequest(http.MethodPost, ClosePath,
			getReader(t, &vcwallet.LockWalletRequest{UserID: sampleUser3}))
		rw = httptest.NewRecorder()
		cmd.Close(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)
		require.Contains(t, rw.Body.String(), `{"closed":false}`)
	})

	t.Run("lock & unlock failures", func(t *testing.T) {
		cmd := New(mockctx, &vcwallet.Config{})

		rq := httptest.NewRequest(http.MethodPost, OpenPath, getReader(t, vcwallet.UnlockWalletRequest{}))
		rw := httptest.NewRecorder()
		cmd.Open(rw, rq)
		require.Equal(t, http.StatusInternalServerError, rw.Code)

		rq = httptest.NewRequest(http.MethodPost, OpenPath, nil)
		rw = httptest.NewRecorder()
		cmd.Open(rw, rq)
		require.Equal(t, http.StatusBadRequest, rw.Code)

		rq = httptest.NewRequest(http.MethodPost, ClosePath,
			getReader(t, &vcwallet.LockWalletRequest{}))
		rw = httptest.NewRecorder()
		cmd.Close(rw, rq)
		require.Equal(t, http.StatusInternalServerError, rw.Code)

		rq = httptest.NewRequest(http.MethodPost, ClosePath, nil)
		rw = httptest.NewRecorder()
		cmd.Close(rw, rq)
		require.Equal(t, http.StatusBadRequest, rw.Code)
	})
}

func TestOperation_AddRemoveGetGetAll(t *testing.T) {
	const (
		sampleUser1 = "sample-user-01"
		sampleUser2 = "sample-user-02"
	)

	mockctx := newMockProvider(t)

	createSampleUserProfile(t, mockctx, &vcwallet.CreateOrUpdateProfileRequest{
		UserID:             sampleUser1,
		LocalKMSPassphrase: samplePassPhrase,
	})

	token1, lock1 := unlockWallet(t, mockctx, &vcwallet.UnlockWalletRequest{
		UserID:             sampleUser1,
		LocalKMSPassphrase: samplePassPhrase,
	})

	defer lock1()

	createSampleUserProfile(t, mockctx, &vcwallet.CreateOrUpdateProfileRequest{
		UserID:      sampleUser2,
		KeyStoreURL: sampleKeyStoreURL,
	})

	t.Run("add a credential to wallet", func(t *testing.T) {
		request := &vcwallet.AddContentRequest{
			Content:     testdata.SampleUDCVC,
			ContentType: "credential",
			WalletAuth:  vcwallet.WalletAuth{UserID: sampleUser1, Auth: token1},
		}

		rq := httptest.NewRequest(http.MethodPost, AddPath, getReader(t, request))
		rw := httptest.NewRecorder()

		cmd := New(mockctx, &vcwallet.Config{})
		cmd.Add(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)
	})

	t.Run("add a metadata to wallet", func(t *testing.T) {
		request := &vcwallet.AddContentRequest{
			Content:     testdata.SampleWalletContentMetadata,
			ContentType: "metadata",
			WalletAuth:  vcwallet.WalletAuth{UserID: sampleUser1, Auth: token1},
		}

		rq := httptest.NewRequest(http.MethodPost, AddPath, getReader(t, request))
		rw := httptest.NewRecorder()

		cmd := New(mockctx, &vcwallet.Config{})
		cmd.Add(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)
	})

	t.Run("get a credential from wallet", func(t *testing.T) {
		request := &vcwallet.GetContentRequest{
			ContentID:   "http://example.edu/credentials/1872",
			ContentType: "credential",
			WalletAuth:  vcwallet.WalletAuth{UserID: sampleUser1, Auth: token1},
		}

		rq := httptest.NewRequest(http.MethodPost, GetPath, getReader(t, request))
		rw := httptest.NewRecorder()

		cmd := New(mockctx, &vcwallet.Config{})
		cmd.Get(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)
	})

	t.Run("get all credentials from wallet", func(t *testing.T) {
		cmd := New(mockctx, &vcwallet.Config{})

		// save multiple credentials, one already saved
		const count = 6
		for i := 1; i < count; i++ {
			request := &vcwallet.AddContentRequest{
				Content: []byte(strings.ReplaceAll(string(testdata.SampleUDCVC), `"http://example.edu/credentials/1872"`,
					fmt.Sprintf(`"http://example.edu/credentials/1872%d"`, i))),
				ContentType: "credential",
				WalletAuth:  vcwallet.WalletAuth{UserID: sampleUser1, Auth: token1},
			}

			rq := httptest.NewRequest(http.MethodPost, AddPath, getReader(t, request))
			rw := httptest.NewRecorder()

			cmd.Add(rw, rq)
			require.Equal(t, http.StatusOK, rw.Code)
		}

		request := &vcwallet.GetAllContentRequest{
			ContentType: "credential",
			WalletAuth:  vcwallet.WalletAuth{UserID: sampleUser1, Auth: token1},
		}

		rq := httptest.NewRequest(http.MethodPost, AddPath, getReader(t, request))
		rw := httptest.NewRecorder()

		cmd.GetAll(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)

		var response map[string]interface{}
		require.NoError(t, json.NewDecoder(rw.Body).Decode(&response))
		require.NotEmpty(t, response)
		require.Len(t, response["contents"], count)
	})

	t.Run("remove a credential from wallet", func(t *testing.T) {
		request := &vcwallet.RemoveContentRequest{
			ContentID:   "http://example.edu/credentials/1877",
			ContentType: "credential",
			WalletAuth:  vcwallet.WalletAuth{UserID: sampleUser1, Auth: token1},
		}

		cmd := New(mockctx, &vcwallet.Config{})

		rq := httptest.NewRequest(http.MethodPost, RemovePath, getReader(t, request))
		rw := httptest.NewRecorder()

		cmd.Remove(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)
	})

	t.Run("try content operations from invalid auth", func(t *testing.T) {
		cmd := New(mockctx, &vcwallet.Config{})

		const expectedErr = "invalid auth token"

		rw := httptest.NewRecorder()
		rq := httptest.NewRequest(http.MethodPost, RemovePath, getReader(t, &vcwallet.AddContentRequest{
			Content:     testdata.SampleUDCVC,
			ContentType: "credential",
			WalletAuth:  vcwallet.WalletAuth{UserID: sampleUser1, Auth: sampleFakeTkn},
		}))
		cmd.Add(rw, rq)
		require.Equal(t, http.StatusInternalServerError, rw.Code)
		require.Contains(t, rw.Body.String(), expectedErr)

		rw = httptest.NewRecorder()
		rq = httptest.NewRequest(http.MethodPost, RemovePath, getReader(t, &vcwallet.GetContentRequest{
			ContentID:   "http://example.edu/credentials/1877",
			ContentType: "credential",
			WalletAuth:  vcwallet.WalletAuth{UserID: sampleUser1, Auth: sampleFakeTkn},
		}))
		cmd.Get(rw, rq)
		require.Equal(t, http.StatusInternalServerError, rw.Code)
		require.Contains(t, rw.Body.String(), expectedErr)

		rw = httptest.NewRecorder()
		rq = httptest.NewRequest(http.MethodPost, RemovePath, getReader(t, &vcwallet.GetAllContentRequest{
			ContentType: "credential",
			WalletAuth:  vcwallet.WalletAuth{UserID: sampleUser1, Auth: sampleFakeTkn},
		}))
		cmd.GetAll(rw, rq)
		require.Equal(t, http.StatusInternalServerError, rw.Code)
		require.Contains(t, rw.Body.String(), expectedErr)

		rw = httptest.NewRecorder()
		rq = httptest.NewRequest(http.MethodPost, RemovePath, getReader(t, &vcwallet.RemoveContentRequest{
			ContentID:   "http://example.edu/credentials/1877",
			ContentType: "credential",
			WalletAuth:  vcwallet.WalletAuth{UserID: sampleUser1, Auth: sampleFakeTkn},
		}))
		cmd.Remove(rw, rq)
		require.Equal(t, http.StatusInternalServerError, rw.Code)
		require.Contains(t, rw.Body.String(), expectedErr)
	})
}

func TestOperation_Query(t *testing.T) {
	const sampleUser1 = "sample-user-01"

	mockctx := newMockProvider(t)
	mockctx.VDRegistryValue = getMockDIDKeyVDR()

	createSampleUserProfile(t, mockctx, &vcwallet.CreateOrUpdateProfileRequest{
		UserID:             sampleUser1,
		LocalKMSPassphrase: samplePassPhrase,
	})

	token, lock := unlockWallet(t, mockctx, &vcwallet.UnlockWalletRequest{
		UserID:             sampleUser1,
		LocalKMSPassphrase: samplePassPhrase,
	})

	defer lock()

	sampleNewUDCVc := strings.ReplaceAll(string(testdata.SampleUDCVC),
		"http://example.edu/credentials/1872", "http://example.edu/credentials/18722")

	addContent(t, mockctx, &vcwallet.AddContentRequest{
		Content:     []byte(sampleNewUDCVc),
		ContentType: "credential",
		WalletAuth:  vcwallet.WalletAuth{UserID: sampleUser1, Auth: token},
	})

	addContent(t, mockctx, &vcwallet.AddContentRequest{
		Content:     testdata.SampleUDCVCWithProofBBS,
		ContentType: "credential",
		WalletAuth:  vcwallet.WalletAuth{UserID: sampleUser1, Auth: token},
	})

	t.Run("successfully query credentials", func(t *testing.T) {
		request := &vcwallet.ContentQueryRequest{
			Query: []*wallet.QueryParams{
				{
					Type:  "QueryByExample",
					Query: []json.RawMessage{testdata.SampleWalletQueryByExample},
				},
				{
					Type:  "QueryByFrame",
					Query: []json.RawMessage{testdata.SampleWalletQueryByFrame},
				},
			},
			WalletAuth: vcwallet.WalletAuth{UserID: sampleUser1, Auth: token},
		}

		rq := httptest.NewRequest(http.MethodPost, QueryPath, getReader(t, request))
		rw := httptest.NewRecorder()

		cmd := New(mockctx, &vcwallet.Config{})
		cmd.Query(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)

		var response map[string]interface{}
		require.NoError(t, json.NewDecoder(rw.Body).Decode(&response))
		require.NotEmpty(t, response)
		require.NotEmpty(t, response["results"])
	})

	t.Run("query credentials with invalid auth", func(t *testing.T) {
		request := &vcwallet.ContentQueryRequest{
			Query: []*wallet.QueryParams{
				{
					Type:  "QueryByExample",
					Query: []json.RawMessage{testdata.SampleWalletQueryByExample},
				},
				{
					Type:  "QueryByFrame",
					Query: []json.RawMessage{testdata.SampleWalletQueryByFrame},
				},
			},
			WalletAuth: vcwallet.WalletAuth{UserID: sampleUser1, Auth: sampleFakeTkn},
		}

		rq := httptest.NewRequest(http.MethodPost, QueryPath, getReader(t, request))
		rw := httptest.NewRecorder()

		cmd := New(mockctx, &vcwallet.Config{})
		cmd.Query(rw, rq)
		require.Equal(t, http.StatusInternalServerError, rw.Code)
		require.Contains(t, rw.Body.String(), "invalid auth token")
	})

	t.Run("query credentials with invalid query type", func(t *testing.T) {
		request := &vcwallet.ContentQueryRequest{
			Query: []*wallet.QueryParams{
				{
					Type:  "QueryByMango",
					Query: []json.RawMessage{testdata.SampleWalletQueryByExample},
				},
				{
					Type:  "QueryByFrame",
					Query: []json.RawMessage{testdata.SampleWalletQueryByFrame},
				},
			},
			WalletAuth: vcwallet.WalletAuth{UserID: sampleUser1, Auth: token},
		}

		rq := httptest.NewRequest(http.MethodPost, QueryPath, getReader(t, request))
		rw := httptest.NewRecorder()

		cmd := New(mockctx, &vcwallet.Config{})
		cmd.Query(rw, rq)
		require.Equal(t, http.StatusInternalServerError, rw.Code)
		require.Contains(t, rw.Body.String(), "unsupported query type")
	})
}

func TestOperation_IssueProveVerify(t *testing.T) {
	const sampleUser1 = "sample-user-01"

	mockctx := newMockProvider(t)
	mockctx.VDRegistryValue = getMockDIDKeyVDR()

	tcrypto, err := tinkcrypto.New()
	require.NoError(t, err)

	mockctx.CryptoValue = tcrypto

	createSampleUserProfile(t, mockctx, &vcwallet.CreateOrUpdateProfileRequest{
		UserID:             sampleUser1,
		LocalKMSPassphrase: samplePassPhrase,
	})

	token, lock := unlockWallet(t, mockctx, &vcwallet.UnlockWalletRequest{
		UserID:             sampleUser1,
		LocalKMSPassphrase: samplePassPhrase,
	})

	defer lock()

	addContent(t, mockctx, &vcwallet.AddContentRequest{
		Content:     testdata.SampleWalletContentKeyBase58,
		ContentType: wallet.Key,
		WalletAuth:  vcwallet.WalletAuth{UserID: sampleUser1, Auth: token},
	})
	addContent(t, mockctx, &vcwallet.AddContentRequest{
		Content:     testdata.SampleDocResolutionResponse,
		ContentType: wallet.DIDResolutionResponse,
		WalletAuth:  vcwallet.WalletAuth{UserID: sampleUser1, Auth: token},
	})

	var rawCredentialToVerify json.RawMessage

	t.Run("issue a credential", func(t *testing.T) {
		request := &vcwallet.IssueRequest{
			WalletAuth: vcwallet.WalletAuth{UserID: sampleUser1, Auth: token},
			Credential: testdata.SampleUDCVC,
			ProofOptions: &wallet.ProofOptions{
				Controller: sampleDIDKey,
			},
		}

		rq := httptest.NewRequest(http.MethodPost, IssuePath, getReader(t, request))
		rw := httptest.NewRecorder()

		cmd := New(mockctx, &vcwallet.Config{})
		cmd.Issue(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)

		credentialIssued := parseCredential(t, rw.Body)
		require.Len(t, credentialIssued.Proofs, 1)

		rawCredentialToVerify, err = credentialIssued.MarshalJSON()
		require.NoError(t, err)
	})

	// save it in store for next tests
	addContent(t, mockctx, &vcwallet.AddContentRequest{
		Content:     rawCredentialToVerify,
		ContentType: wallet.Credential,
		WalletAuth:  vcwallet.WalletAuth{UserID: sampleUser1, Auth: token},
	})

	t.Run("verify a credential from store", func(t *testing.T) {
		request := &vcwallet.VerifyRequest{
			WalletAuth:         vcwallet.WalletAuth{UserID: sampleUser1, Auth: token},
			StoredCredentialID: "http://example.edu/credentials/1872",
		}

		rq := httptest.NewRequest(http.MethodPost, VerifyPath, getReader(t, request))
		rw := httptest.NewRecorder()

		cmd := New(mockctx, &vcwallet.Config{})
		cmd.Verify(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)

		var response verifyResponse
		require.NoError(t, json.NewDecoder(rw.Body).Decode(&response))
		require.True(t, response.Verified)
		require.Empty(t, response.Error)
	})

	t.Run("verify a raw credential", func(t *testing.T) {
		request := &vcwallet.VerifyRequest{
			WalletAuth:    vcwallet.WalletAuth{UserID: sampleUser1, Auth: token},
			RawCredential: rawCredentialToVerify,
		}

		rq := httptest.NewRequest(http.MethodPost, VerifyPath, getReader(t, request))
		rw := httptest.NewRecorder()

		cmd := New(mockctx, &vcwallet.Config{})
		cmd.Verify(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)

		var response verifyResponse
		require.NoError(t, json.NewDecoder(rw.Body).Decode(&response))
		require.True(t, response.Verified)
		require.Empty(t, response.Error)
	})

	t.Run("verify a invalid credential", func(t *testing.T) {
		// tamper a credential
		invalidVC := string(rawCredentialToVerify)
		invalidVC = strings.ReplaceAll(invalidVC, "Jayden Doe", "John Smith")

		request := &vcwallet.VerifyRequest{
			WalletAuth:    vcwallet.WalletAuth{UserID: sampleUser1, Auth: token},
			RawCredential: []byte(invalidVC),
		}

		rq := httptest.NewRequest(http.MethodPost, VerifyPath, getReader(t, request))
		rw := httptest.NewRecorder()

		cmd := New(mockctx, &vcwallet.Config{})
		cmd.Verify(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)

		var response verifyResponse
		require.NoError(t, json.NewDecoder(rw.Body).Decode(&response))
		require.False(t, response.Verified)
		require.NotEmpty(t, response.Error)
		require.Contains(t, response.Error, "invalid signature")
	})

	var presentation *verifiable.Presentation

	t.Run("prove credentials", func(t *testing.T) {
		request := &vcwallet.ProveRequest{
			WalletAuth:        vcwallet.WalletAuth{UserID: sampleUser1, Auth: token},
			RawCredentials:    []json.RawMessage{rawCredentialToVerify},
			StoredCredentials: []string{"http://example.edu/credentials/1872"},
			ProofOptions: &wallet.ProofOptions{
				Controller: sampleDIDKey,
			},
		}

		rq := httptest.NewRequest(http.MethodPost, ProvePath, getReader(t, request))
		rw := httptest.NewRecorder()

		cmd := New(mockctx, &vcwallet.Config{})
		cmd.Prove(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)

		presentation = parsePresentation(t, rw.Body)
		require.NotEmpty(t, presentation.Proofs)
		require.Len(t, presentation.Credentials(), 2)
		require.Len(t, presentation.Proofs, 1)

		// prove using raw presentation
		rawPresentation, err := presentation.MarshalJSON()
		require.NoError(t, err)

		request = &vcwallet.ProveRequest{
			WalletAuth:        vcwallet.WalletAuth{UserID: sampleUser1, Auth: token},
			StoredCredentials: []string{"http://example.edu/credentials/1872"},
			Presentation:      rawPresentation,
			ProofOptions: &wallet.ProofOptions{
				Controller: sampleDIDKey,
			},
		}

		rq = httptest.NewRequest(http.MethodPost, ProvePath, getReader(t, request))
		rw = httptest.NewRecorder()

		cmd.Prove(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)

		presentation2 := parsePresentation(t, rw.Body)
		require.NotEmpty(t, presentation2.Proofs)
		require.Len(t, presentation2.Credentials(), 3)
		require.Len(t, presentation2.Proofs, 2)
	})

	t.Run("verify a raw presentation", func(t *testing.T) {
		vpBytes, err := presentation.MarshalJSON()
		require.NoError(t, err)

		request := &vcwallet.VerifyRequest{
			WalletAuth:   vcwallet.WalletAuth{UserID: sampleUser1, Auth: token},
			Presentation: vpBytes,
		}

		rq := httptest.NewRequest(http.MethodPost, VerifyPath, getReader(t, request))
		rw := httptest.NewRecorder()

		cmd := New(mockctx, &vcwallet.Config{})
		cmd.Verify(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)

		var response verifyResponse
		require.NoError(t, json.NewDecoder(rw.Body).Decode(&response))
		require.True(t, response.Verified)
		require.Empty(t, response.Error)

		// tamper it and try
		invalidVP := string(vpBytes)
		invalidVP = strings.ReplaceAll(invalidVP, "Jayden Doe", "John Smith")

		request = &vcwallet.VerifyRequest{
			WalletAuth:   vcwallet.WalletAuth{UserID: sampleUser1, Auth: token},
			Presentation: []byte(invalidVP),
		}

		rq = httptest.NewRequest(http.MethodPost, VerifyPath, getReader(t, request))
		rw = httptest.NewRecorder()

		cmd.Verify(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)

		require.NoError(t, json.NewDecoder(rw.Body).Decode(&response))
		require.False(t, response.Verified)
		require.NotEmpty(t, response.Error)
		require.Contains(t, response.Error, "invalid signature")
	})

	t.Run("issue,prove,verify with invalid auth", func(t *testing.T) {
		request := &vcwallet.ProveRequest{
			WalletAuth:        vcwallet.WalletAuth{UserID: sampleUser1, Auth: sampleFakeTkn},
			StoredCredentials: []string{"http://example.edu/credentials/1872"},
			ProofOptions: &wallet.ProofOptions{
				Controller: "did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv464",
			},
		}

		rq := httptest.NewRequest(http.MethodPost, ProvePath, getReader(t, request))
		rw := httptest.NewRecorder()

		cmd := New(mockctx, &vcwallet.Config{})
		cmd.Prove(rw, rq)
		require.Equal(t, http.StatusInternalServerError, rw.Code)
		require.Contains(t, rw.Body.String(), "invalid auth token")

		issuerRqst := &vcwallet.IssueRequest{
			WalletAuth: vcwallet.WalletAuth{UserID: sampleUser1, Auth: sampleFakeTkn},
			Credential: testdata.SampleUDCVC,
			ProofOptions: &wallet.ProofOptions{
				Controller: sampleDIDKey,
			},
		}

		rq = httptest.NewRequest(http.MethodPost, IssuePath, getReader(t, issuerRqst))
		rw = httptest.NewRecorder()

		cmd.Issue(rw, rq)
		require.Equal(t, http.StatusInternalServerError, rw.Code)
		require.Contains(t, rw.Body.String(), "wallet locked")
	})
}

func TestOperation_Derive(t *testing.T) {
	const sampleUser1 = "sample-user-01"

	mockctx := newMockProvider(t)
	mockctx.VDRegistryValue = getMockDIDKeyVDR()

	createSampleUserProfile(t, mockctx, &vcwallet.CreateOrUpdateProfileRequest{
		UserID:             sampleUser1,
		LocalKMSPassphrase: samplePassPhrase,
	})

	token, lock := unlockWallet(t, mockctx, &vcwallet.UnlockWalletRequest{
		UserID:             sampleUser1,
		LocalKMSPassphrase: samplePassPhrase,
	})

	defer lock()

	addContent(t, mockctx, &vcwallet.AddContentRequest{
		Content:     testdata.SampleUDCVCWithProofBBS,
		ContentType: "credential",
		WalletAuth:  vcwallet.WalletAuth{UserID: sampleUser1, Auth: token},
	})

	// prepare frame
	var frameDoc map[string]interface{}

	require.NoError(t, json.Unmarshal(testdata.SampleFrame, &frameDoc))

	t.Run("derive a credential from stored credential", func(t *testing.T) {
		request := &vcwallet.DeriveRequest{
			WalletAuth:         vcwallet.WalletAuth{UserID: sampleUser1, Auth: token},
			StoredCredentialID: "http://example.edu/credentials/1872",
			DeriveOptions: &wallet.DeriveOptions{
				Frame: frameDoc,
				Nonce: uuid.New().String(),
			},
		}

		rq := httptest.NewRequest(http.MethodPost, DerivePath, getReader(t, request))
		rw := httptest.NewRecorder()

		cmd := New(mockctx, &vcwallet.Config{})
		cmd.Derive(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)

		var response deriveResponse
		require.NoError(t, json.NewDecoder(rw.Body).Decode(&response))
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.Credential)
	})

	t.Run("derive a credential from raw credential", func(t *testing.T) {
		request := &vcwallet.DeriveRequest{
			WalletAuth:    vcwallet.WalletAuth{UserID: sampleUser1, Auth: token},
			RawCredential: testdata.SampleUDCVCWithProofBBS,
			DeriveOptions: &wallet.DeriveOptions{
				Frame: frameDoc,
				Nonce: uuid.New().String(),
			},
		}

		rq := httptest.NewRequest(http.MethodPost, DerivePath, getReader(t, request))
		rw := httptest.NewRecorder()

		cmd := New(mockctx, &vcwallet.Config{})
		cmd.Derive(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)

		var response deriveResponse
		require.NoError(t, json.NewDecoder(rw.Body).Decode(&response))
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.Credential)
	})

	t.Run("derive a credential using invalid auth", func(t *testing.T) {
		request := &vcwallet.DeriveRequest{
			WalletAuth:         vcwallet.WalletAuth{UserID: sampleUser1, Auth: sampleFakeTkn},
			StoredCredentialID: "http://example.edu/credentials/1872",
			DeriveOptions: &wallet.DeriveOptions{
				Frame: frameDoc,
				Nonce: uuid.New().String(),
			},
		}

		rq := httptest.NewRequest(http.MethodPost, DerivePath, getReader(t, request))
		rw := httptest.NewRecorder()

		cmd := New(mockctx, &vcwallet.Config{})
		cmd.Derive(rw, rq)
		require.Equal(t, http.StatusInternalServerError, rw.Code)
		require.Contains(t, rw.Body.String(), "invalid auth token")
	})
}

func TestOperation_CreateKeyPair(t *testing.T) {
	const sampleUser1 = "sample-user-01"

	mockctx := newMockProvider(t)
	mockctx.VDRegistryValue = getMockDIDKeyVDR()

	createSampleUserProfile(t, mockctx, &vcwallet.CreateOrUpdateProfileRequest{
		UserID:             sampleUser1,
		LocalKMSPassphrase: samplePassPhrase,
	})

	token, lock := unlockWallet(t, mockctx, &vcwallet.UnlockWalletRequest{
		UserID:             sampleUser1,
		LocalKMSPassphrase: samplePassPhrase,
	})

	defer lock()

	t.Run("create a key pair from wallet", func(t *testing.T) {
		request := &vcwallet.CreateKeyPairRequest{
			WalletAuth: vcwallet.WalletAuth{UserID: sampleUser1, Auth: token},
			KeyType:    kms.ED25519,
		}

		rq := httptest.NewRequest(http.MethodPost, CreateKeyPairPath, getReader(t, request))
		rw := httptest.NewRecorder()

		cmd := New(mockctx, &vcwallet.Config{})
		cmd.CreateKeyPair(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)

		var r createKeyPairResponse
		require.NoError(t, json.NewDecoder(rw.Body).Decode(&r.Response))
		require.NotEmpty(t, r)
		require.NotEmpty(t, r.Response)
		require.NotEmpty(t, r.Response.PublicKey)
		require.NotEmpty(t, r.Response.KeyID)
	})

	t.Run("create a key pair from wallet using invalid auth", func(t *testing.T) {
		request := &vcwallet.CreateKeyPairRequest{
			WalletAuth: vcwallet.WalletAuth{UserID: sampleUser1, Auth: sampleFakeTkn},
			KeyType:    kms.ED25519,
		}

		rq := httptest.NewRequest(http.MethodPost, CreateKeyPairPath, getReader(t, request))
		rw := httptest.NewRecorder()

		cmd := New(mockctx, &vcwallet.Config{})
		cmd.CreateKeyPair(rw, rq)
		require.Equal(t, http.StatusInternalServerError, rw.Code)
		require.Contains(t, rw.Body.String(), "invalid auth token")
	})
}

func TestOperation_Connect(t *testing.T) {
	const sampleDIDCommUser = "sample-didcomm-user-01"

	mockctx := newMockProvider(t)

	createSampleUserProfile(t, mockctx, &vcwallet.CreateOrUpdateProfileRequest{
		UserID:             sampleDIDCommUser,
		LocalKMSPassphrase: samplePassPhrase,
	})

	token, lock := unlockWallet(t, mockctx, &vcwallet.UnlockWalletRequest{
		UserID:             sampleDIDCommUser,
		LocalKMSPassphrase: samplePassPhrase,
	})

	defer lock()

	t.Run("wallet connect operation success", func(t *testing.T) {
		sampleConnID := uuid.New().String()

		oobSvc := &mockoutofband.MockOobService{
			AcceptInvitationHandle: func(*outofbandSvc.Invitation, outofbandSvc.Options) (string, error) {
				return sampleConnID, nil
			},
		}
		mockctx.ServiceMap[outofbandSvc.Name] = oobSvc

		didexSvc := &mockdidexchange.MockDIDExchangeSvc{
			RegisterMsgEventHandle: func(ch chan<- service.StateMsg) error {
				ch <- service.StateMsg{
					Type:       service.PostState,
					StateID:    didexchange.StateIDCompleted,
					Properties: &mockdidexchange.MockEventProperties{ConnID: sampleConnID},
				}

				return nil
			},
		}
		mockctx.ServiceMap[didexchange.DIDExchange] = didexSvc

		request := &didcommwallet.ConnectRequest{
			WalletAuth: vcwallet.WalletAuth{UserID: sampleDIDCommUser, Auth: token},
			Invitation: &outofbandClient.Invitation{},
			ConnectOpts: didcommwallet.ConnectOpts{
				MyLabel: "sample-label",
			},
		}

		rq := httptest.NewRequest(http.MethodPost, ConnectPath, getReader(t, request))
		rw := httptest.NewRecorder()

		cmd := New(mockctx, &vcwallet.Config{})
		cmd.Connect(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)

		var r connectResponse
		require.NoError(t, json.NewDecoder(rw.Body).Decode(&r.Response))
		require.NotEmpty(t, r)
		require.NotEmpty(t, r.Response)
		require.Equal(t, sampleConnID, r.Response.ConnectionID)
	})

	t.Run("wallet connect operation failure", func(t *testing.T) {
		didexSvc := &mockdidexchange.MockDIDExchangeSvc{
			RegisterMsgEventHandle: func(ch chan<- service.StateMsg) error {
				return fmt.Errorf(sampleCommandError)
			},
		}
		mockctx.ServiceMap[didexchange.DIDExchange] = didexSvc

		request := &didcommwallet.ConnectRequest{
			WalletAuth: vcwallet.WalletAuth{UserID: sampleDIDCommUser, Auth: token},
			Invitation: &outofbandClient.Invitation{},
			ConnectOpts: didcommwallet.ConnectOpts{
				MyLabel: "sample-label",
			},
		}

		rq := httptest.NewRequest(http.MethodPost, ConnectPath, getReader(t, request))
		rw := httptest.NewRecorder()

		cmd := New(mockctx, &vcwallet.Config{})
		cmd.Connect(rw, rq)
		require.Equal(t, http.StatusInternalServerError, rw.Code)
		require.Contains(t, rw.Body.String(), sampleCommandError)
	})
}

func TestOperation_ProposePresentation(t *testing.T) {
	const sampleDIDCommUser = "sample-didcomm-user-02"

	mockctx := newMockProvider(t)

	createSampleUserProfile(t, mockctx, &vcwallet.CreateOrUpdateProfileRequest{
		UserID:             sampleDIDCommUser,
		LocalKMSPassphrase: samplePassPhrase,
	})

	token, lock := unlockWallet(t, mockctx, &vcwallet.UnlockWalletRequest{
		UserID:             sampleDIDCommUser,
		LocalKMSPassphrase: samplePassPhrase,
	})

	defer lock()

	const (
		myDID    = "did:mydid:123"
		theirDID = "did:theirdid:123"
	)

	t.Run("wallet propose presentation success", func(t *testing.T) {
		sampleConnID := uuid.New().String()
		oobSvc := &mockoutofband.MockOobService{
			AcceptInvitationHandle: func(*outofbandSvc.Invitation, outofbandSvc.Options) (string, error) {
				return sampleConnID, nil
			},
		}
		mockctx.ServiceMap[outofbandSvc.Name] = oobSvc

		didexSvc := &mockdidexchange.MockDIDExchangeSvc{
			RegisterMsgEventHandle: func(ch chan<- service.StateMsg) error {
				ch <- service.StateMsg{
					Type:       service.PostState,
					StateID:    didexchange.StateIDCompleted,
					Properties: &mockdidexchange.MockEventProperties{ConnID: sampleConnID},
				}

				return nil
			},
		}
		mockctx.ServiceMap[didexchange.DIDExchange] = didexSvc

		thID := uuid.New().String()
		ppSvc := &mockpresentproof.MockPresentProofSvc{
			ActionsFunc: func() ([]presentproofSvc.Action, error) {
				return []presentproofSvc.Action{
					{
						PIID: thID,
						Msg: service.NewDIDCommMsgMap(&presentproofSvc.RequestPresentationV2{
							Comment: "mock msg",
						}),
						MyDID:    myDID,
						TheirDID: theirDID,
					},
				}, nil
			},
			HandleFunc: func(service.DIDCommMsg) (string, error) {
				return thID, nil
			},
		}

		mockctx.ServiceMap[outofbandSvc.Name] = oobSvc
		mockctx.ServiceMap[presentproofSvc.Name] = ppSvc

		store, err := mockctx.StorageProvider().OpenStore(connection.Namespace)
		require.NoError(t, err)

		record := &connection.Record{
			ConnectionID: sampleConnID,
			MyDID:        myDID,
			TheirDID:     theirDID,
		}
		recordBytes, err := json.Marshal(record)
		require.NoError(t, err)
		require.NoError(t, store.Put(fmt.Sprintf("conn_%s", sampleConnID), recordBytes))

		request := &didcommwallet.ProposePresentationRequest{
			WalletAuth: vcwallet.WalletAuth{UserID: sampleDIDCommUser, Auth: token},
			Invitation: &wallet.GenericInvitation{},
		}

		rq := httptest.NewRequest(http.MethodPost, ProposeCredentialPath, getReader(t, request))
		rw := httptest.NewRecorder()

		cmd := New(mockctx, &vcwallet.Config{})
		cmd.ProposePresentation(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)

		var r proposePresentationResponse
		require.NoError(t, json.NewDecoder(rw.Body).Decode(&r.Response))
		require.NotEmpty(t, r)
		require.NotEmpty(t, r.Response)
		require.NotEmpty(t, r.Response.PresentationRequest)
	})

	t.Run("wallet propose presentation failure", func(t *testing.T) {
		oobSvc := &mockoutofband.MockOobService{
			AcceptInvitationHandle: func(*outofbandSvc.Invitation, outofbandSvc.Options) (string, error) {
				return "", fmt.Errorf(sampleCommandError)
			},
		}

		mockctx.ServiceMap[outofbandSvc.Name] = oobSvc

		request := &didcommwallet.ProposePresentationRequest{
			WalletAuth: vcwallet.WalletAuth{UserID: sampleDIDCommUser, Auth: token},
			Invitation: &wallet.GenericInvitation{},
		}

		rq := httptest.NewRequest(http.MethodPost, ProposePresentationPath, getReader(t, request))
		rw := httptest.NewRecorder()

		cmd := New(mockctx, &vcwallet.Config{})
		cmd.ProposePresentation(rw, rq)
		require.Equal(t, http.StatusInternalServerError, rw.Code)
		require.Contains(t, rw.Body.String(), sampleCommandError)
	})
}

func TestOperation_PresentProof(t *testing.T) {
	const sampleDIDCommUser = "sample-didcomm-user-03"

	mockctx := newMockProvider(t)

	createSampleUserProfile(t, mockctx, &vcwallet.CreateOrUpdateProfileRequest{
		UserID:             sampleDIDCommUser,
		LocalKMSPassphrase: samplePassPhrase,
	})

	token, lock := unlockWallet(t, mockctx, &vcwallet.UnlockWalletRequest{
		UserID:             sampleDIDCommUser,
		LocalKMSPassphrase: samplePassPhrase,
	})

	defer lock()

	t.Run("wallet present proof success - wait for done", func(t *testing.T) {
		thID := uuid.New().String()
		mockPresentProofSvc := &mockpresentproof.MockPresentProofSvc{
			RegisterMsgEventHandle: func(ch chan<- service.StateMsg) error {
				ch <- service.StateMsg{
					Type:    service.PostState,
					StateID: presentproofSvc.StateNameDone,
					Properties: &mockdidexchange.MockEventProperties{
						Properties: map[string]interface{}{
							webRedirectStatusKey: model.AckStatusOK,
							webRedirectURLKey:    exampleWebRedirect,
						},
					},
					Msg: &mockMsg{thID: thID},
				}

				return nil
			},
		}
		mockctx.ServiceMap[presentproofSvc.Name] = mockPresentProofSvc

		request := &didcommwallet.PresentProofRequest{
			WalletAuth:   vcwallet.WalletAuth{UserID: sampleDIDCommUser, Auth: token},
			ThreadID:     thID,
			Presentation: json.RawMessage{},
			WaitForDone:  true,
			Timeout:      1 * time.Millisecond,
		}

		rq := httptest.NewRequest(http.MethodPost, PresentProofPath, getReader(t, request))
		rw := httptest.NewRecorder()

		cmd := New(mockctx, &vcwallet.Config{})
		cmd.PresentProof(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)

		var r presentProofResponse
		require.NoError(t, json.NewDecoder(rw.Body).Decode(&r.Response))
		require.NotEmpty(t, r)
		require.NotEmpty(t, r.Response)
		require.Equal(t, model.AckStatusOK, r.Response.Status)
		require.NotEmpty(t, exampleWebRedirect, r.Response.RedirectURL)
	})

	t.Run("wallet present proof success", func(t *testing.T) {
		request := &didcommwallet.PresentProofRequest{
			WalletAuth:   vcwallet.WalletAuth{UserID: sampleDIDCommUser, Auth: token},
			ThreadID:     uuid.New().String(),
			Presentation: json.RawMessage{},
		}

		rq := httptest.NewRequest(http.MethodPost, PresentProofPath, getReader(t, request))
		rw := httptest.NewRecorder()

		cmd := New(mockctx, &vcwallet.Config{})
		cmd.PresentProof(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)
	})

	t.Run("wallet present proof failure", func(t *testing.T) {
		ppSvc := &mockpresentproof.MockPresentProofSvc{
			ActionContinueFunc: func(string, ...presentproofSvc.Opt) error {
				return fmt.Errorf(sampleCommandError)
			},
		}

		mockctx.ServiceMap[presentproofSvc.Name] = ppSvc

		request := &didcommwallet.PresentProofRequest{
			WalletAuth:   vcwallet.WalletAuth{UserID: sampleDIDCommUser, Auth: token},
			ThreadID:     uuid.New().String(),
			Presentation: json.RawMessage{},
		}

		rq := httptest.NewRequest(http.MethodPost, PresentProofPath, getReader(t, request))
		rw := httptest.NewRecorder()

		cmd := New(mockctx, &vcwallet.Config{})
		cmd.PresentProof(rw, rq)
		require.Equal(t, http.StatusInternalServerError, rw.Code)
		require.Contains(t, rw.Body.String(), sampleCommandError)
	})
}

func TestOperation_ProposeCredential(t *testing.T) {
	const (
		sampleDIDCommUser = "sample-didcomm-user02"
		sampleMsgComment  = "sample mock msg"
		myDID             = "did:mydid:123"
		theirDID          = "did:theirdid:123"
	)

	mockctx := newMockProvider(t)

	createSampleUserProfile(t, mockctx, &vcwallet.CreateOrUpdateProfileRequest{
		UserID:             sampleDIDCommUser,
		LocalKMSPassphrase: samplePassPhrase,
	})

	token, lock := unlockWallet(t, mockctx, &vcwallet.UnlockWalletRequest{
		UserID:             sampleDIDCommUser,
		LocalKMSPassphrase: samplePassPhrase,
	})

	defer lock()

	t.Run("wallet propose credential success", func(t *testing.T) {
		sampleConnID := uuid.New().String()
		oobSvc := &mockoutofband.MockOobService{
			AcceptInvitationHandle: func(*outofbandSvc.Invitation, outofbandSvc.Options) (string, error) {
				return sampleConnID, nil
			},
		}
		mockctx.ServiceMap[outofbandSvc.Name] = oobSvc

		didexSvc := &mockdidexchange.MockDIDExchangeSvc{
			RegisterMsgEventHandle: func(ch chan<- service.StateMsg) error {
				ch <- service.StateMsg{
					Type:       service.PostState,
					StateID:    didexchange.StateIDCompleted,
					Properties: &mockdidexchange.MockEventProperties{ConnID: sampleConnID},
				}

				return nil
			},
		}
		mockctx.ServiceMap[didexchange.DIDExchange] = didexSvc

		thID := uuid.New().String()
		icSvc := &mockissuecredential.MockIssueCredentialSvc{
			ActionsFunc: func() ([]issuecredentialsvc.Action, error) {
				return []issuecredentialsvc.Action{
					{
						PIID: thID,
						Msg: service.NewDIDCommMsgMap(&issuecredentialsvc.OfferCredentialV2{
							Comment: sampleMsgComment,
						}),
						MyDID:    myDID,
						TheirDID: theirDID,
					},
				}, nil
			},
			HandleFunc: func(service.DIDCommMsg) (string, error) {
				return thID, nil
			},
		}
		mockctx.ServiceMap[issuecredentialsvc.Name] = icSvc

		store, err := mockctx.StorageProvider().OpenStore(connection.Namespace)
		require.NoError(t, err)

		record := &connection.Record{
			ConnectionID: sampleConnID,
			MyDID:        myDID,
			TheirDID:     theirDID,
		}
		recordBytes, err := json.Marshal(record)
		require.NoError(t, err)
		require.NoError(t, store.Put(fmt.Sprintf("conn_%s", sampleConnID), recordBytes))

		request := &didcommwallet.ProposeCredentialRequest{
			WalletAuth: vcwallet.WalletAuth{UserID: sampleDIDCommUser, Auth: token},
			Invitation: &wallet.GenericInvitation{},
		}

		rq := httptest.NewRequest(http.MethodPost, ProposeCredentialPath, getReader(t, request))
		rw := httptest.NewRecorder()

		cmd := New(mockctx, &vcwallet.Config{})
		cmd.ProposeCredential(rw, rq)
		require.Equal(t, rw.Code, http.StatusOK)

		var r proposeCredentialResponse
		require.NoError(t, json.NewDecoder(rw.Body).Decode(&r.Response))
		require.NotEmpty(t, r)
		require.NotEmpty(t, r.Response)
		require.NotEmpty(t, r.Response.OfferCredential)

		offer := &issuecredentialsvc.OfferCredentialV2{}

		err = r.Response.OfferCredential.Decode(offer)
		require.NoError(t, err)
		require.NotEmpty(t, offer)
		require.Equal(t, sampleMsgComment, offer.Comment)
	})

	t.Run("wallet propose credential failure", func(t *testing.T) {
		oobSvc := &mockoutofband.MockOobService{
			AcceptInvitationHandle: func(*outofbandSvc.Invitation, outofbandSvc.Options) (string, error) {
				return "", fmt.Errorf(sampleCommandError)
			},
		}

		mockctx.ServiceMap[outofbandSvc.Name] = oobSvc

		request := &didcommwallet.ProposeCredentialRequest{
			WalletAuth: vcwallet.WalletAuth{UserID: sampleDIDCommUser, Auth: token},
			Invitation: &wallet.GenericInvitation{},
		}

		rq := httptest.NewRequest(http.MethodPost, ProposeCredentialPath, getReader(t, request))
		rw := httptest.NewRecorder()

		cmd := New(mockctx, &vcwallet.Config{})
		cmd.ProposeCredential(rw, rq)
		require.Equal(t, rw.Code, http.StatusInternalServerError)
		require.Contains(t, rw.Body.String(), sampleCommandError)
	})
}

func TestOperation_RequestCredential(t *testing.T) {
	const (
		sampleDIDCommUser = "sample-didcomm-user03"
	)

	mockctx := newMockProvider(t)

	createSampleUserProfile(t, mockctx, &vcwallet.CreateOrUpdateProfileRequest{
		UserID:             sampleDIDCommUser,
		LocalKMSPassphrase: samplePassPhrase,
	})

	token, lock := unlockWallet(t, mockctx, &vcwallet.UnlockWalletRequest{
		UserID:             sampleDIDCommUser,
		LocalKMSPassphrase: samplePassPhrase,
	})

	defer lock()

	t.Run("wallet request credential success - wait for done", func(t *testing.T) {
		thID := uuid.New().String()

		icSvc := &mockissuecredential.MockIssueCredentialSvc{
			RegisterMsgEventHandle: func(ch chan<- service.StateMsg) error {
				ch <- service.StateMsg{
					Type:    service.PostState,
					StateID: "done",
					Properties: &mockdidexchange.MockEventProperties{
						Properties: map[string]interface{}{
							webRedirectStatusKey: model.AckStatusOK,
							webRedirectURLKey:    exampleWebRedirect,
						},
					},
					Msg: &mockMsg{thID: thID},
				}

				return nil
			},
		}
		mockctx.ServiceMap[issuecredentialsvc.Name] = icSvc

		request := &didcommwallet.RequestCredentialRequest{
			WalletAuth:   vcwallet.WalletAuth{UserID: sampleDIDCommUser, Auth: token},
			ThreadID:     thID,
			Presentation: json.RawMessage{},
			WaitForDone:  true,
			Timeout:      600 * time.Millisecond,
		}

		rq := httptest.NewRequest(http.MethodPost, PresentProofPath, getReader(t, request))
		rw := httptest.NewRecorder()

		cmd := New(mockctx, &vcwallet.Config{})
		cmd.RequestCredential(rw, rq)
		require.Equal(t, http.StatusOK, rw.Code)

		var r requestCredentialResponse
		require.NoError(t, json.NewDecoder(rw.Body).Decode(&r.Response))
		require.NotEmpty(t, r)
		require.NotEmpty(t, r.Response)
		require.Equal(t, model.AckStatusOK, r.Response.Status)
		require.NotEmpty(t, exampleWebRedirect, r.Response.RedirectURL)
	})

	t.Run("wallet request credential success", func(t *testing.T) {
		request := &didcommwallet.RequestCredentialRequest{
			WalletAuth:   vcwallet.WalletAuth{UserID: sampleDIDCommUser, Auth: token},
			ThreadID:     uuid.New().String(),
			Presentation: json.RawMessage{},
		}

		rq := httptest.NewRequest(http.MethodPost, PresentProofPath, getReader(t, request))
		rw := httptest.NewRecorder()

		cmd := New(mockctx, &vcwallet.Config{})
		cmd.RequestCredential(rw, rq)
		require.Equal(t, rw.Code, http.StatusOK)
	})

	t.Run("wallet request credential failure", func(t *testing.T) {
		icSvc := &mockissuecredential.MockIssueCredentialSvc{
			ActionContinueFunc: func(string, ...issuecredentialsvc.Opt) error {
				return fmt.Errorf(sampleCommandError)
			},
		}
		mockctx.ServiceMap[issuecredentialsvc.Name] = icSvc

		request := &didcommwallet.PresentProofRequest{
			WalletAuth:   vcwallet.WalletAuth{UserID: sampleDIDCommUser, Auth: token},
			ThreadID:     uuid.New().String(),
			Presentation: json.RawMessage{},
		}

		rq := httptest.NewRequest(http.MethodPost, PresentProofPath, getReader(t, request))
		rw := httptest.NewRecorder()

		cmd := New(mockctx, &vcwallet.Config{})
		cmd.RequestCredential(rw, rq)
		require.Equal(t, rw.Code, http.StatusInternalServerError)
		require.Contains(t, rw.Body.String(), sampleCommandError)
	})
}

func TestOperation_ResolveCredentialManifest(t *testing.T) {
	const sampleUser1 = "sample-user-rm01"

	mockctx := newMockProvider(t)
	mockctx.VDRegistryValue = getMockDIDKeyVDR()

	createSampleUserProfile(t, mockctx, &vcwallet.CreateOrUpdateProfileRequest{
		UserID:             sampleUser1,
		LocalKMSPassphrase: samplePassPhrase,
	})

	token, lock := unlockWallet(t, mockctx, &vcwallet.UnlockWalletRequest{
		UserID:             sampleUser1,
		LocalKMSPassphrase: samplePassPhrase,
	})

	defer lock()

	t.Run("resolve credential manifest", func(t *testing.T) {
		request := &vcwallet.ResolveCredentialManifestRequest{
			WalletAuth: vcwallet.WalletAuth{UserID: sampleUser1, Auth: token},
			Manifest:   testdata.CredentialManifestMultipleVCs,
			Response:   testdata.CredentialResponseWithMultipleVCs,
		}

		rq := httptest.NewRequest(http.MethodPost, ResolveCredentialManifestPath, getReader(t, request))
		rw := httptest.NewRecorder()

		cmd := New(mockctx, &vcwallet.Config{})
		cmd.ResolveCredentialManifest(rw, rq)
		require.Equal(t, rw.Code, http.StatusOK)

		var r resolveCredentialManifestResponse
		require.NoError(t, json.NewDecoder(rw.Body).Decode(&r.Response))
		require.NotEmpty(t, r)
		require.NotEmpty(t, r.Response)
		require.Len(t, r.Response.Resolved, 2)
	})

	t.Run("resolve credential manifest failure", func(t *testing.T) {
		request := &vcwallet.ResolveCredentialManifestRequest{
			WalletAuth: vcwallet.WalletAuth{UserID: sampleUser1, Auth: token},
			Manifest:   testdata.CredentialManifestMultipleVCs,
			Credential: testdata.SampleUDCVC,
		}

		rq := httptest.NewRequest(http.MethodPost, ResolveCredentialManifestPath, getReader(t, request))
		rw := httptest.NewRecorder()

		cmd := New(mockctx, &vcwallet.Config{})
		cmd.ResolveCredentialManifest(rw, rq)
		require.Equal(t, rw.Code, http.StatusInternalServerError)
		require.Contains(t, rw.Body.String(), "failed to resolve raw credential by descriptor ID")
	})
}

func createSampleUserProfile(t *testing.T, ctx *mockprovider.Provider, request *vcwallet.CreateOrUpdateProfileRequest) {
	cmd := New(ctx, &vcwallet.Config{})
	require.NotNil(t, cmd)

	rq := httptest.NewRequest(http.MethodPost, CreateProfilePath, getReader(t, request))
	rw := httptest.NewRecorder()
	cmd.CreateProfile(rw, rq)
	require.Equal(t, http.StatusOK, rw.Code)
}

func getReader(t *testing.T, v interface{}) io.Reader {
	vcReqBytes, err := json.Marshal(v)
	require.NoError(t, err)

	return bytes.NewBuffer(vcReqBytes)
}

func getUnlockToken(t *testing.T, b *bytes.Buffer) string {
	var response vcwallet.UnlockWalletResponse

	require.NoError(t, json.NewDecoder(b).Decode(&response))

	return response.Token
}

func unlockWallet(t *testing.T, ctx *mockprovider.Provider, request *vcwallet.UnlockWalletRequest) (string, func()) {
	rq := httptest.NewRequest(http.MethodPost, OpenPath, getReader(t, request))
	rw := httptest.NewRecorder()

	cmd := New(ctx, &vcwallet.Config{})
	cmd.Open(rw, rq)

	require.Equal(t, http.StatusOK, rw.Code)

	return getUnlockToken(t, rw.Body), func() {
		rq = httptest.NewRequest(http.MethodPost, ClosePath,
			getReader(t, &vcwallet.LockWalletRequest{UserID: request.UserID}))
		cmd.Close(httptest.NewRecorder(), rq)
	}
}

func addContent(t *testing.T, ctx *mockprovider.Provider, request *vcwallet.AddContentRequest) {
	rq := httptest.NewRequest(http.MethodPost, AddPath, getReader(t, request))
	rw := httptest.NewRecorder()

	cmd := New(ctx, &vcwallet.Config{})
	cmd.Add(rw, rq)
	require.Equal(t, http.StatusOK, rw.Code)
}

func newMockProvider(t *testing.T) *mockprovider.Provider {
	t.Helper()

	loader, err := ldtestutil.DocumentLoader()
	require.NoError(t, err)

	serviceMap := map[string]interface{}{
		presentproofSvc.Name:    &mockpresentproof.MockPresentProofSvc{},
		outofbandSvc.Name:       &mockoutofband.MockOobService{},
		didexchange.DIDExchange: &mockdidexchange.MockDIDExchangeSvc{},
		mediator.Coordination:   &mockmediator.MockMediatorSvc{},
		issuecredentialsvc.Name: &mockissuecredential.MockIssueCredentialSvc{},
		oobv2.Name:              &mockoutofbandv2.MockOobService{},
	}

	return &mockprovider.Provider{
		StorageProviderValue:              mockstorage.NewMockStoreProvider(),
		ProtocolStateStorageProviderValue: mockstorage.NewMockStoreProvider(),
		DocumentLoaderValue:               loader,
		ServiceMap:                        serviceMap,
	}
}

func getMockDIDKeyVDR() *mockvdr.MockVDRegistry {
	return &mockvdr.MockVDRegistry{
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
}

func parseCredential(t *testing.T, b *bytes.Buffer) *verifiable.Credential {
	var response struct {
		Credential json.RawMessage
	}

	require.NoError(t, json.NewDecoder(b).Decode(&response))

	loader, err := ldtestutil.DocumentLoader()
	require.NoError(t, err)

	vc, err := verifiable.ParseCredential(response.Credential, verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(loader))
	require.NoError(t, err)

	return vc
}

func parsePresentation(t *testing.T, b *bytes.Buffer) *verifiable.Presentation {
	var response struct {
		Presentation json.RawMessage
	}

	require.NoError(t, json.NewDecoder(b).Decode(&response))

	loader, err := ldtestutil.DocumentLoader()
	require.NoError(t, err)

	vp, err := verifiable.ParsePresentation(response.Presentation, verifiable.WithPresDisabledProofCheck(),
		verifiable.WithPresJSONLDDocumentLoader(loader))
	require.NoError(t, err)

	return vp
}

// mockMsg containing custom parent thread ID.
type mockMsg struct {
	*service.DIDCommMsgMap
	thID string
}

func (m *mockMsg) ParentThreadID() string {
	return m.thID
}

func (m *mockMsg) ThreadID() (string, error) {
	return m.thID, nil
}
