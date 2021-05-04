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
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/internal/jsonldtest"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

// nolint: lll
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
	sampleUDCVC            = `{
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
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
      "id": "http://example.edu/credentials/1877",
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
	sampleMetadata = `{
        "@context": ["https://w3id.org/wallet/v1"],
        "id": "urn:uuid:2905324a-9524-11ea-bb37-0242ac130002",
        "type": "Metadata",
        "name": "Ropsten Testnet HD Accounts",
        "image": "https://via.placeholder.com/150",
        "description": "My Ethereum TestNet Accounts",
        "tags": ["professional", "organization"],
        "correlation": ["urn:uuid:4058a72a-9523-11ea-bb37-0242ac130002"],
        "hdPath": "m’/44’/60’/0’",
        "target": ["urn:uuid:c410e44a-9525-11ea-bb37-0242ac130002"]
    }`
	sampleBBSVC = `{
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
                "created": "2021-03-29T13:27:36.483097-04:00",
                "proofPurpose": "assertionMethod",
                "proofValue": "rw7FeV6K1wimnYogF9qd-N0zmq5QlaIoszg64HciTca-mK_WU4E1jIusKTT6EnN2GZz04NVPBIw4yhc0kTwIZ07etMvfWUlHt_KMoy2CfTw8FBhrf66q4h7Qcqxh_Kxp6yCHyB4A-MmURlKKb8o-4w",
                "type": "BbsBlsSignature2020",
                "verificationMethod": "did:key:zUC72c7u4BYVmfYinDceXkNAwzPEyuEE23kUmJDjLy8495KH3pjLwFhae1Fww9qxxRdLnS2VNNwni6W3KbYZKsicDtiNNEp76fYWR6HCD8jAz6ihwmLRjcHH6kB294Xfg1SL1qQ#zUC72c7u4BYVmfYinDceXkNAwzPEyuEE23kUmJDjLy8495KH3pjLwFhae1Fww9qxxRdLnS2VNNwni6W3KbYZKsicDtiNNEp76fYWR6HCD8jAz6ihwmLRjcHH6kB294Xfg1SL1qQ"
            },
            "referenceNumber": 83294847,
            "type": ["VerifiableCredential", "UniversityDegreeCredential"]
        }`
	sampleQueryByExample = `{
                        "reason": "Please present your identity document.",
                        "example": {
                            "@context": [
								"https://www.w3.org/2018/credentials/v1",
								"https://www.w3.org/2018/credentials/examples/v1"
                            ],
                            "type": ["UniversityDegreeCredential"],
							"trustedIssuer": [
              					{
                					"issuer": "urn:some:required:issuer"
              					},
								{
                					"required": true,
                					"issuer": "did:example:76e12ec712ebc6f1c221ebfeb1f"
              					}
							],
							"credentialSubject": {
								"id": "did:example:ebfeb1f712ebc6f1c276e12ec21"	
							}
                        }
                	}`
	sampleQueryByFrame = `{
                    "reason": "Please provide your Passport details.",
                    "frame": {
                        "@context": [
                            "https://www.w3.org/2018/credentials/v1",
                            "https://w3id.org/citizenship/v1",
                            "https://w3id.org/security/bbs/v1"
                        ],
                        "type": ["VerifiableCredential", "PermanentResidentCard"],
                        "@explicit": true,
                        "identifier": {},
                        "issuer": {},
                        "issuanceDate": {},
                        "credentialSubject": {
                            "@explicit": true,
                            "name": {},
                            "spouse": {}
                        }
                    },
                    "trustedIssuer": [
                        {
                            "issuer": "did:example:76e12ec712ebc6f1c221ebfeb1f",
                            "required": true
                        }
                    ],
                    "required": true
                }`
)

func TestNew(t *testing.T) {
	t.Run("successfully create new command instance", func(t *testing.T) {
		cmd := New(newMockProvider(t))
		require.NotNil(t, cmd)

		handlers := cmd.GetHandlers()
		require.Equal(t, 9, len(handlers))
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

func TestCommand_OpenAndClose(t *testing.T) {
	const (
		sampleUser1 = "sample-user-01"
		sampleUser2 = "sample-user-02"
		sampleUser3 = "sample-user-03"
	)

	mockctx := newMockProvider(t)

	createSampleUserProfile(t, mockctx, &CreateOrUpdateProfileRequest{
		UserID:             sampleUser1,
		LocalKMSPassphrase: samplePassPhrase,
	})

	createSampleUserProfile(t, mockctx, &CreateOrUpdateProfileRequest{
		UserID:      sampleUser2,
		KeyStoreURL: sampleKeyStoreURL,
	})

	createSampleUserProfile(t, mockctx, &CreateOrUpdateProfileRequest{
		UserID:             sampleUser3,
		LocalKMSPassphrase: samplePassPhrase,
		EDVConfiguration: &EDVConfiguration{
			ServerURL: sampleEDVServerURL,
			VaultID:   sampleEDVVaultID,
		},
	})

	t.Run("successfully unlock & lock wallet (local kms)", func(t *testing.T) {
		cmd := New(mockctx)

		request := &UnlockWalletRquest{
			UserID:             sampleUser1,
			LocalKMSPassphrase: samplePassPhrase,
		}

		// unlock wallet
		var b bytes.Buffer
		cmdErr := cmd.Open(&b, getReader(t, &request))
		require.NoError(t, cmdErr)
		require.NotEmpty(t, getUnlockToken(t, b))
		b.Reset()

		// try again, should get error, wallet already unlocked
		cmdErr = cmd.Open(&b, getReader(t, &request))
		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), wallet.ErrAlreadyUnlocked.Error())
		require.Empty(t, b.Len())
		b.Reset()

		// lock wallet
		cmdErr = cmd.Close(&b, getReader(t, &LockWalletRequest{UserID: sampleUser1}))
		require.NoError(t, cmdErr)
		var lockResponse LockWalletResponse
		require.NoError(t, json.NewDecoder(&b).Decode(&lockResponse))
		require.True(t, lockResponse.Closed)
		b.Reset()

		// lock wallet again
		cmdErr = cmd.Close(&b, getReader(t, &LockWalletRequest{UserID: sampleUser1}))
		require.NoError(t, cmdErr)
		require.NoError(t, json.NewDecoder(&b).Decode(&lockResponse))
		require.False(t, lockResponse.Closed)
		b.Reset()
	})

	t.Run("successfully unlock & lock wallet (remote kms)", func(t *testing.T) {
		cmd := New(mockctx)

		request := &UnlockWalletRquest{
			UserID:     sampleUser2,
			WebKMSAuth: sampleFakeTkn,
		}

		// unlock wallet
		var b bytes.Buffer
		cmdErr := cmd.Open(&b, getReader(t, &request))
		require.NoError(t, cmdErr)
		require.NotEmpty(t, getUnlockToken(t, b))
		b.Reset()

		// try again, should get error, wallet already unlocked
		cmdErr = cmd.Open(&b, getReader(t, &request))
		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), wallet.ErrAlreadyUnlocked.Error())
		require.Empty(t, b.Len())
		b.Reset()

		// lock wallet
		cmdErr = cmd.Close(&b, getReader(t, &LockWalletRequest{UserID: sampleUser2}))
		require.NoError(t, cmdErr)
		var lockResponse LockWalletResponse
		require.NoError(t, json.NewDecoder(&b).Decode(&lockResponse))
		require.True(t, lockResponse.Closed)
		b.Reset()

		// lock wallet again
		cmdErr = cmd.Close(&b, getReader(t, &LockWalletRequest{UserID: sampleUser2}))
		require.NoError(t, cmdErr)
		require.NoError(t, json.NewDecoder(&b).Decode(&lockResponse))
		require.False(t, lockResponse.Closed)
		b.Reset()
	})

	t.Run("successfully unlock & lock wallet (local kms, edv user)", func(t *testing.T) {
		cmd := New(mockctx)

		request := &UnlockWalletRquest{
			UserID:             sampleUser3,
			LocalKMSPassphrase: samplePassPhrase,
			EDVUnlock: &EDVUnlockRequest{
				AuthToken: sampleFakeTkn,
			},
		}

		// unlock wallet
		var b bytes.Buffer
		cmdErr := cmd.Open(&b, getReader(t, &request))
		require.NoError(t, cmdErr)
		require.NotEmpty(t, getUnlockToken(t, b))
		b.Reset()

		// try again, should get error, wallet already unlocked
		cmdErr = cmd.Open(&b, getReader(t, &request))
		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), wallet.ErrAlreadyUnlocked.Error())
		require.Empty(t, b.Len())
		b.Reset()

		// lock wallet
		cmdErr = cmd.Close(&b, getReader(t, &LockWalletRequest{UserID: sampleUser3}))
		require.NoError(t, cmdErr)
		var lockResponse LockWalletResponse
		require.NoError(t, json.NewDecoder(&b).Decode(&lockResponse))
		require.True(t, lockResponse.Closed)
		b.Reset()

		// lock wallet again
		cmdErr = cmd.Close(&b, getReader(t, &LockWalletRequest{UserID: sampleUser3}))
		require.NoError(t, cmdErr)
		require.NoError(t, json.NewDecoder(&b).Decode(&lockResponse))
		require.False(t, lockResponse.Closed)
		b.Reset()
	})

	t.Run("lock & unlock failures", func(t *testing.T) {
		cmd := New(mockctx)

		var b bytes.Buffer

		cmdErr := cmd.Open(&b, getReader(t, &UnlockWalletRquest{}))
		require.Error(t, cmdErr)
		validateError(t, cmdErr, command.ExecuteError, OpenWalletErrorCode, "profile does not exist")
		require.Empty(t, b.Len())
		b.Reset()

		cmdErr = cmd.Open(&b, getReader(t, ""))
		require.Error(t, cmdErr)
		validateError(t, cmdErr, command.ValidationError, InvalidRequestErrorCode, "cannot unmarshal string into Go")
		require.Empty(t, b.Len())
		b.Reset()

		cmdErr = cmd.Close(&b, getReader(t, &UnlockWalletRquest{}))
		require.Error(t, cmdErr)
		validateError(t, cmdErr, command.ExecuteError, CloseWalletErrorCode, "profile does not exist")
		require.Empty(t, b.Len())
		b.Reset()

		cmdErr = cmd.Close(&b, getReader(t, ""))
		require.Error(t, cmdErr)
		validateError(t, cmdErr, command.ValidationError, InvalidRequestErrorCode, "cannot unmarshal string into Go")
		require.Empty(t, b.Len())
		b.Reset()
	})
}

func TestCommand_AddRemoveGetGetAll(t *testing.T) {
	const (
		sampleUser1 = "sample-user-01"
		sampleUser2 = "sample-user-02"
		sampleUser3 = "sample-user-03"
	)

	mockctx := newMockProvider(t)

	createSampleUserProfile(t, mockctx, &CreateOrUpdateProfileRequest{
		UserID:             sampleUser1,
		LocalKMSPassphrase: samplePassPhrase,
	})

	token1, lock1 := unlockWallet(t, mockctx, &UnlockWalletRquest{
		UserID:             sampleUser1,
		LocalKMSPassphrase: samplePassPhrase,
	})

	defer lock1()

	createSampleUserProfile(t, mockctx, &CreateOrUpdateProfileRequest{
		UserID:      sampleUser2,
		KeyStoreURL: sampleKeyStoreURL,
	})

	token2, lock2 := unlockWallet(t, mockctx, &UnlockWalletRquest{
		UserID:     sampleUser2,
		WebKMSAuth: sampleFakeTkn,
	})

	defer lock2()

	t.Run("add a credential to wallet", func(t *testing.T) {
		cmd := New(mockctx)

		var b bytes.Buffer

		cmdErr := cmd.Add(&b, getReader(t, &AddContentRequest{
			UserID:      sampleUser1,
			Content:     []byte(sampleUDCVC),
			ContentType: "credential",
			WalletAuth:  WalletAuth{Auth: token1},
		}))
		require.NoError(t, cmdErr)
	})

	t.Run("add a metadata to wallet", func(t *testing.T) {
		cmd := New(mockctx)

		var b bytes.Buffer

		cmdErr := cmd.Add(&b, getReader(t, &AddContentRequest{
			UserID:      sampleUser1,
			Content:     []byte(sampleMetadata),
			ContentType: "metadata",
			WalletAuth:  WalletAuth{Auth: token1},
		}))
		require.NoError(t, cmdErr)
	})

	t.Run("get a credential from wallet", func(t *testing.T) {
		cmd := New(mockctx)

		var b bytes.Buffer

		cmdErr := cmd.Get(&b, getReader(t, &GetContentRequest{
			UserID:      sampleUser1,
			ContentID:   "http://example.edu/credentials/1877",
			ContentType: "credential",
			WalletAuth:  WalletAuth{Auth: token1},
		}))
		require.NoError(t, cmdErr)

		var response GetContentResponse
		require.NoError(t, json.NewDecoder(&b).Decode(&response))
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.Content)
	})

	t.Run("get all credentials from wallet", func(t *testing.T) {
		cmd := New(mockctx)

		// save multiple credentials, one already saved
		const count = 6
		for i := 1; i < count; i++ {
			var b bytes.Buffer
			cmdErr := cmd.Add(&b, getReader(t, &AddContentRequest{
				UserID: sampleUser1,
				Content: []byte(strings.ReplaceAll(sampleUDCVC, `"http://example.edu/credentials/1877"`,
					fmt.Sprintf(`"http://example.edu/credentials/1872%d"`, i))),
				ContentType: "credential",
				WalletAuth:  WalletAuth{Auth: token1},
			}))
			require.NoError(t, cmdErr)

			b.Reset()
		}

		var b bytes.Buffer

		cmdErr := cmd.GetAll(&b, getReader(t, &GetAllContentRequest{
			UserID:      sampleUser1,
			ContentType: "credential",
			WalletAuth:  WalletAuth{Auth: token1},
		}))
		require.NoError(t, cmdErr)

		var response GetAllContentResponse
		require.NoError(t, json.NewDecoder(&b).Decode(&response))
		require.NotEmpty(t, response)
		require.Len(t, response.Contents, count)
	})

	t.Run("remove a credential from wallet", func(t *testing.T) {
		cmd := New(mockctx)

		var b bytes.Buffer

		cmdErr := cmd.Remove(&b, getReader(t, &RemoveContentRequest{
			UserID:      sampleUser1,
			ContentID:   "http://example.edu/credentials/1877",
			ContentType: "credential",
			WalletAuth:  WalletAuth{Auth: token1},
		}))
		require.NoError(t, cmdErr)
	})

	t.Run("get a credential from different wallet", func(t *testing.T) {
		cmd := New(mockctx)

		var b bytes.Buffer

		cmdErr := cmd.Get(&b, getReader(t, &GetContentRequest{
			UserID:      sampleUser2,
			ContentID:   "http://example.edu/credentials/1877",
			ContentType: "credential",
			WalletAuth:  WalletAuth{Auth: token2},
		}))
		validateError(t, cmdErr, command.ExecuteError, GetFromWalletErrorCode, "data not found")
	})

	t.Run("try content operations from invalid auth", func(t *testing.T) {
		cmd := New(mockctx)

		var b bytes.Buffer

		const expectedErr = "invalid auth token"

		cmdErr := cmd.Add(&b, getReader(t, &AddContentRequest{
			UserID:      sampleUser1,
			Content:     []byte(sampleUDCVC),
			ContentType: "credential",
			WalletAuth:  WalletAuth{Auth: sampleFakeTkn},
		}))
		validateError(t, cmdErr, command.ExecuteError, AddToWalletErrorCode, expectedErr)
		b.Reset()

		cmdErr = cmd.Get(&b, getReader(t, &GetContentRequest{
			UserID:      sampleUser1,
			ContentID:   "http://example.edu/credentials/1877",
			ContentType: "credential",
			WalletAuth:  WalletAuth{Auth: sampleFakeTkn},
		}))
		validateError(t, cmdErr, command.ExecuteError, GetFromWalletErrorCode, expectedErr)

		cmdErr = cmd.GetAll(&b, getReader(t, &GetAllContentRequest{
			UserID:      sampleUser1,
			ContentType: "credential",
			WalletAuth:  WalletAuth{Auth: sampleFakeTkn},
		}))
		validateError(t, cmdErr, command.ExecuteError, GetAllFromWalletErrorCode, expectedErr)

		cmdErr = cmd.Remove(&b, getReader(t, &RemoveContentRequest{
			UserID:      sampleUser1,
			ContentID:   "http://example.edu/credentials/1877",
			ContentType: "credential",
			WalletAuth:  WalletAuth{Auth: sampleFakeTkn},
		}))
		validateError(t, cmdErr, command.ExecuteError, RemoveFromWalletErrorCode, expectedErr)
	})

	t.Run("try content operations from invalid content type", func(t *testing.T) {
		cmd := New(mockctx)

		var b bytes.Buffer

		cmdErr := cmd.Add(&b, getReader(t, &AddContentRequest{
			UserID:      sampleUser1,
			Content:     []byte(sampleUDCVC),
			ContentType: "mango",
			WalletAuth:  WalletAuth{Auth: token1},
		}))
		validateError(t, cmdErr, command.ExecuteError, AddToWalletErrorCode, "invalid content type")
		b.Reset()

		cmdErr = cmd.Get(&b, getReader(t, &GetContentRequest{
			UserID:      sampleUser1,
			ContentID:   "http://example.edu/credentials/1877",
			ContentType: "pineapple",
			WalletAuth:  WalletAuth{Auth: token1},
		}))
		validateError(t, cmdErr, command.ExecuteError, GetFromWalletErrorCode, "data not found")

		cmdErr = cmd.GetAll(&b, getReader(t, &GetAllContentRequest{
			UserID:      sampleUser1,
			ContentType: "orange",
			WalletAuth:  WalletAuth{Auth: token1},
		}))
		require.NoError(t, cmdErr)

		var response GetAllContentResponse
		require.NoError(t, json.NewDecoder(&b).Decode(&response))
		require.Empty(t, response.Contents)
		b.Reset()

		cmdErr = cmd.Remove(&b, getReader(t, &RemoveContentRequest{
			UserID:      sampleUser1,
			ContentID:   "http://example.edu/credentials/1877",
			ContentType: "strawberry",
			WalletAuth:  WalletAuth{Auth: token1},
		}))
		require.NoError(t, cmdErr)
	})

	t.Run("try content operations from invalid profile", func(t *testing.T) {
		cmd := New(mockctx)

		var b bytes.Buffer

		const expectedErr = "profile does not exist"

		cmdErr := cmd.Add(&b, getReader(t, &AddContentRequest{
			UserID:      sampleUser3,
			Content:     []byte(sampleUDCVC),
			ContentType: "credential",
			WalletAuth:  WalletAuth{Auth: sampleFakeTkn},
		}))
		validateError(t, cmdErr, command.ExecuteError, AddToWalletErrorCode, expectedErr)
		b.Reset()

		cmdErr = cmd.Get(&b, getReader(t, &GetContentRequest{
			UserID:      sampleUser3,
			ContentID:   "http://example.edu/credentials/1877",
			ContentType: "credential",
			WalletAuth:  WalletAuth{Auth: sampleFakeTkn},
		}))
		validateError(t, cmdErr, command.ExecuteError, GetFromWalletErrorCode, expectedErr)

		cmdErr = cmd.GetAll(&b, getReader(t, &GetAllContentRequest{
			UserID:      sampleUser3,
			ContentType: "credential",
			WalletAuth:  WalletAuth{Auth: sampleFakeTkn},
		}))
		validateError(t, cmdErr, command.ExecuteError, GetAllFromWalletErrorCode, expectedErr)

		cmdErr = cmd.Remove(&b, getReader(t, &RemoveContentRequest{
			UserID:      sampleUser3,
			ContentID:   "http://example.edu/credentials/1877",
			ContentType: "credential",
			WalletAuth:  WalletAuth{Auth: sampleFakeTkn},
		}))
		validateError(t, cmdErr, command.ExecuteError, RemoveFromWalletErrorCode, expectedErr)
	})

	t.Run("try content operations from invalid request", func(t *testing.T) {
		cmd := New(mockctx)

		var b bytes.Buffer

		const expectedErr = "invalid character"

		cmdErr := cmd.Add(&b, bytes.NewBufferString("invalid request"))
		validateError(t, cmdErr, command.ValidationError, InvalidRequestErrorCode, expectedErr)
		b.Reset()

		cmdErr = cmd.Get(&b, bytes.NewBufferString("invalid request"))
		validateError(t, cmdErr, command.ValidationError, InvalidRequestErrorCode, expectedErr)

		cmdErr = cmd.GetAll(&b, bytes.NewBufferString("invalid request"))
		validateError(t, cmdErr, command.ValidationError, InvalidRequestErrorCode, expectedErr)

		cmdErr = cmd.Remove(&b, bytes.NewBufferString("invalid request"))
		validateError(t, cmdErr, command.ValidationError, InvalidRequestErrorCode, expectedErr)
	})
}

func TestCommand_Query(t *testing.T) {
	const sampleUser1 = "sample-user-01"

	mockctx := newMockProvider(t)
	mockctx.VDRegistryValue = getMockDIDKeyVDR()

	createSampleUserProfile(t, mockctx, &CreateOrUpdateProfileRequest{
		UserID:             sampleUser1,
		LocalKMSPassphrase: samplePassPhrase,
	})

	token, lock := unlockWallet(t, mockctx, &UnlockWalletRquest{
		UserID:             sampleUser1,
		LocalKMSPassphrase: samplePassPhrase,
	})

	defer lock()

	addContent(t, mockctx, &AddContentRequest{
		UserID:      sampleUser1,
		Content:     []byte(sampleUDCVC),
		ContentType: "credential",
		WalletAuth:  WalletAuth{Auth: token},
	})

	addContent(t, mockctx, &AddContentRequest{
		UserID:      sampleUser1,
		Content:     []byte(sampleBBSVC),
		ContentType: "credential",
		WalletAuth:  WalletAuth{Auth: token},
	})

	t.Run("successfully query credentials", func(t *testing.T) {
		cmd := New(mockctx)

		var b bytes.Buffer

		cmdErr := cmd.Query(&b, getReader(t, &ContentQueryRequest{
			UserID: sampleUser1,
			Query: []*wallet.QueryParams{
				{
					Type:  "QueryByExample",
					Query: []json.RawMessage{[]byte(sampleQueryByExample)},
				},
				{
					Type:  "QueryByFrame",
					Query: []json.RawMessage{[]byte(sampleQueryByFrame)},
				},
			},
			WalletAuth: WalletAuth{Auth: token},
		}))
		require.NoError(t, cmdErr)

		var response map[string]interface{}
		require.NoError(t, json.NewDecoder(&b).Decode(&response))
		require.NotEmpty(t, response)
		require.NotEmpty(t, response["results"])
	})

	t.Run("query credentials with invalid auth", func(t *testing.T) {
		cmd := New(mockctx)

		var b bytes.Buffer

		cmdErr := cmd.Query(&b, getReader(t, &ContentQueryRequest{
			UserID: sampleUser1,
			Query: []*wallet.QueryParams{
				{
					Type:  "QueryByFrame",
					Query: []json.RawMessage{[]byte(sampleQueryByFrame)},
				},
			},
			WalletAuth: WalletAuth{Auth: sampleFakeTkn},
		}))
		validateError(t, cmdErr, command.ExecuteError, QueryWalletErrorCode, "invalid auth token")
	})

	t.Run("query credentials with invalid wallet profile", func(t *testing.T) {
		cmd := New(mockctx)

		var b bytes.Buffer

		cmdErr := cmd.Query(&b, getReader(t, &ContentQueryRequest{
			UserID: sampleUserID,
			Query: []*wallet.QueryParams{
				{
					Type:  "QueryByFrame",
					Query: []json.RawMessage{[]byte(sampleQueryByFrame)},
				},
			},
			WalletAuth: WalletAuth{Auth: sampleFakeTkn},
		}))
		validateError(t, cmdErr, command.ExecuteError, QueryWalletErrorCode, "profile does not exist")
	})

	t.Run("query credentials with invalid query type", func(t *testing.T) {
		cmd := New(mockctx)

		var b bytes.Buffer

		cmdErr := cmd.Query(&b, getReader(t, &ContentQueryRequest{
			UserID: sampleUser1,
			Query: []*wallet.QueryParams{
				{
					Type:  "QueryByOrange",
					Query: []json.RawMessage{[]byte(sampleQueryByFrame)},
				},
			},
			WalletAuth: WalletAuth{Auth: token},
		}))
		validateError(t, cmdErr, command.ExecuteError, QueryWalletErrorCode, "unsupported query type")
	})

	t.Run("query credentials with invalid request", func(t *testing.T) {
		cmd := New(mockctx)

		var b bytes.Buffer

		cmdErr := cmd.Query(&b, bytes.NewBufferString("--"))
		validateError(t, cmdErr, command.ValidationError, InvalidRequestErrorCode, "invalid character")
	})
}

func createSampleUserProfile(t *testing.T, ctx *mockprovider.Provider, request *CreateOrUpdateProfileRequest) {
	cmd := New(ctx)
	require.NotNil(t, cmd)

	var l bytes.Buffer
	cmdErr := cmd.CreateProfile(&l, getReader(t, request))
	require.NoError(t, cmdErr)
}

func getReader(t *testing.T, v interface{}) io.Reader {
	vcReqBytes, err := json.Marshal(v)
	require.NoError(t, err)

	return bytes.NewBuffer(vcReqBytes)
}

func getUnlockToken(t *testing.T, b bytes.Buffer) string {
	var response UnlockWalletResponse

	require.NoError(t, json.NewDecoder(&b).Decode(&response))

	return response.Token
}

func unlockWallet(t *testing.T, ctx *mockprovider.Provider, request *UnlockWalletRquest) (string, func()) {
	cmd := New(ctx)

	var b bytes.Buffer

	cmdErr := cmd.Open(&b, getReader(t, &request))
	require.NoError(t, cmdErr)

	return getUnlockToken(t, b), func() {
		cmdErr = cmd.Close(&b, getReader(t, &LockWalletRequest{UserID: request.UserID}))
		if cmdErr != nil {
			t.Log(t, cmdErr)
		}
	}
}

func addContent(t *testing.T, ctx *mockprovider.Provider, request *AddContentRequest) {
	cmd := New(ctx)

	var b bytes.Buffer
	defer b.Reset()

	cmdErr := cmd.Add(&b, getReader(t, &request))
	require.NoError(t, cmdErr)
}

func validateError(t *testing.T, err command.Error,
	expectedType command.Type, expectedCode command.Code, contains string) {
	require.Error(t, err)
	require.Equal(t, err.Type(), expectedType)
	require.Equal(t, err.Code(), expectedCode)

	if contains != "" {
		require.Contains(t, err.Error(), contains)
	}
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
