/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/storage/edv"
	"github.com/hyperledger/aries-framework-go/internal/testdata"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/internal/ldtestutil"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	sampleContenttErr  = "sample content err"
	sampleContentValid = `{
  			"@context": ["https://w3id.org/wallet/v1"],
  		  	"id": "did:example:123456789abcdefghi",
    		"type": "Person",
    		"name": "John Smith",
    		"image": "https://via.placeholder.com/150",
    		"description" : "Professional software developer for Acme Corp.",
    		"tags": ["professional", "person"],
    		"correlation": ["4058a72a-9523-11ea-bb37-0242ac130002"]
  		}`
	sampleContentNoID = `{
  			"@context": ["https://w3id.org/wallet/v1"],
    		"type": "Person",
    		"name": "John Smith",
    		"image": "https://via.placeholder.com/150",
    		"description" : "Professional software developer for Acme Corp.",
    		"tags": ["professional", "person"],
    		"correlation": ["4058a72a-9523-11ea-bb37-0242ac130002"]
  		}`
	sampleContentInvalid = `{
  			"@context": ["https://w3id.org/wallet/v1"],
    		"type": "Person",
    		"name": "John Smith",
    		"image": "https://via.placeholder.com/150",
    		"description" : "Professional software developer for Acme Corp.",
    		"tags": ["professional", "person"],
    		"correlation": ["4058a72a-9523-11ea-bb37-0242ac130002"]
  		}`
	didResolutionResult = `{
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
                "@context": [
                    "https://www.w3.org/ns/did/v1",
                    {
                        "@base": "did:key:z6Mks8mvCnVx4HQcoq7ZwvpTbMnoRGudHSiEpXhMf6VW8XMg"
                    }
                ],
                "id": "did:key:z6Mks8mvCnVx4HQcoq7ZwvpTbMnoRGudHSiEpXhMf6VW8XMg",
                "verificationMethod": [
                    {
                        "id": "#z6Mks8mvCnVx4HQcoq7ZwvpTbMnoRGudHSiEpXhMf6VW8XMg",
                        "type": "JsonWebKey2020",
                        "controller": "did:key:z6Mks8mvCnVx4HQcoq7ZwvpTbMnoRGudHSiEpXhMf6VW8XMg",
                        "publicKeyJwk": {
                            "crv": "Ed25519",
                            "x": "vGur-MEOrN6GDLf4TBGHDYAERxkmWOjTbztvG3xP0I8",
                            "kty": "OKP"
                        }
                    },
                    {
                        "id": "#z6LScrLMVd9jvbphPeQkGffSeB99EWSYqAnMg8rGiHCgz5ha",
                        "type": "JsonWebKey2020",
                        "controller": "did:key:z6Mks8mvCnVx4HQcoq7ZwvpTbMnoRGudHSiEpXhMf6VW8XMg",
                        "publicKeyJwk": {
                            "kty": "OKP",
                            "crv": "X25519",
                            "x": "EXXinkMxdA4zGmwpOOpbCXt6Ts6CwyXyEKI3jfHkS3k"
                        }
                    }
                ],
                "authentication": [
                    "#z6Mks8mvCnVx4HQcoq7ZwvpTbMnoRGudHSiEpXhMf6VW8XMg"
                ],
                "assertionMethod": [
                    "#z6Mks8mvCnVx4HQcoq7ZwvpTbMnoRGudHSiEpXhMf6VW8XMg"
                ],
                "capabilityInvocation": [
                    "#z6Mks8mvCnVx4HQcoq7ZwvpTbMnoRGudHSiEpXhMf6VW8XMg"
                ],
                "capabilityDelegation": [
                    "#z6Mks8mvCnVx4HQcoq7ZwvpTbMnoRGudHSiEpXhMf6VW8XMg"
                ],
                "keyAgreement": [
                    "#z6LScrLMVd9jvbphPeQkGffSeB99EWSYqAnMg8rGiHCgz5ha"
                ]
            },
            "didDocumentMetadata": {
                "content-type": "application/did+json"
            },
            "didResolutionMetadata": {}
        }`
	sampleKeyContentBase58Valid = `{
  			"@context": ["https://w3id.org/wallet/v1"],
  		  	"id": "did:example:123456789abcdefghi#key-1",  		  	
			"type": "Ed25519VerificationKey2018",
			"privateKeyBase58":"zJRjGFZydU5DBdS2p5qbiUzDFAxbXTkjiDuGPksMBbY5TNyEsGfK4a4WGKjBCh1zeNryeuKtPotp8W1ESnwP71y"
  		}`
	sampleKeyContentBase58WithInvalidField = `{
  			"@context": ["https://w3id.org/wallet/v1"],
  		  	"id": "did:example:123456789abcdefghi#key-1",
			"controller": "did:example:123456789abcdefghi",
			"type": "Ed25519VerificationKey2018",
			"privateKeyBase58":"zJRjGFZydU5DBdS2p5qbiUzDFAxbXTkjiDuGPksMBbY5TNyEsGfK4a4WGKjBCh1zeNryeuKtPotp8W1ESnwP71y"
  		}`
	sampleKeyContentJwkValid = `{
  			"@context": ["https://w3id.org/wallet/v1"],
  		  	"id": "did:example:123456789abcdefghi#z6MkiEh8RQL83nkPo8ehDeX7",  		  	
			"type": "Ed25519VerificationKey2018",
			"privateKeyJwk": {
				"kty": "OKP",
				"d":"Dq5t2WS3OMzcpkh8AyVxJs5r9v4L39ocIz9CpUOqM40",
				"crv": "Ed25519",
				"x": "ODaPFurJgFcoVCUYEmgOJpWOtPlOYbHSugasscKWqDM",
				"kid":"z6MkiEh8RQL83nkPo8ehDeX7"
			}
  		}`
	sampleJWTCredContentValid = "eyJhbGciOiJFZERTQSIsImtpZCI6IiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1Nzc5MDY2MDQsImlhdCI6M" +
		"TI2MjM3MzgwNCwiaXNzIjoiZGlkOmV4YW1wbGU6NzZlMTJlYzcxMmViYzZmMWMyMjFlYmZlYjFmIiwianRpIjoiaHR0cDovL2V4YW1wbGU" +
		"uZWR1L2NyZWRlbnRpYWxzLzE4NzIiLCJuYmYiOjEyNjIzNzM4MDQsInN1YiI6ImRpZDpleGFtcGxlOmViZmViMWY3MTJlYmM2ZjFjMjc2Z" +
		"TEyZWMyMSIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly93d3c" +
		"udzMub3JnLzIwMTgvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjEiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiZGVncmVlIjp7InR5cGUiOiJCY" +
		"WNoZWxvckRlZ3JlZSIsInVuaXZlcnNpdHkiOiJNSVQifSwiaWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjE" +
		"iLCJuYW1lIjoiSmF5ZGVuIERvZSIsInNwb3VzZSI6ImRpZDpleGFtcGxlOmMyNzZlMTJlYzIxZWJmZWIxZjcxMmViYzZmMSJ9LCJpc3N1Z" +
		"XIiOnsibmFtZSI6IkV4YW1wbGUgVW5pdmVyc2l0eSJ9LCJyZWZlcmVuY2VOdW1iZXIiOjguMzI5NDg0N2UrMDcsInR5cGUiOlsiVmVyaWZ" +
		"pYWJsZUNyZWRlbnRpYWwiLCJVbml2ZXJzaXR5RGVncmVlQ3JlZGVudGlhbCJdfX0.a5yKMPmDnEXvM-fG3BaOqfdkqdvU4s2rzeZuOzLmk" +
		"TH1y9sJT-mgTe7map5E9x7abrNVpyYbaH7JaAb9Yhr1DQ"
)

func TestContentTypes(t *testing.T) {
	t.Run("test content types", func(t *testing.T) {
		tests := []struct {
			name     string
			inputs   []string
			expected []ContentType
			fail     bool
		}{
			{
				name:     "validation success",
				inputs:   []string{"collection", "credential", "didResolutionResponse", "metadata", "connection", "key"},
				expected: []ContentType{Collection, Credential, DIDResolutionResponse, Metadata, Connection, Key},
			},
			{
				name:   "validation error",
				inputs: []string{"collECtion", "CRED", "VC", "DID", ""},
				fail:   true,
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.name, func(t *testing.T) {
				for i, input := range tc.inputs {
					ct := ContentType(input)

					if tc.fail {
						require.Error(t, ct.IsValid())
						return
					}

					require.NoError(t, ct.IsValid())
					require.Equal(t, tc.expected[i], ct)
					require.Equal(t, ct.Name(), input)
				}
			})
		}
	})
}

func TestContentStores(t *testing.T) {
	keyMgr := &mockkms.KeyManager{}

	token, e := sessionManager().createSession(uuid.New().String(), keyMgr, 5*time.Second)
	require.NoError(t, e)

	t.Run("create new content store - success", func(t *testing.T) {
		sp := getMockStorageProvider()

		// create new store
		contentStore := newContentStore(sp, createTestDocumentLoader(t), &profile{ID: uuid.New().String()})
		require.NotEmpty(t, contentStore)
		require.Empty(t, sp.config.TagNames)

		// open store
		require.NoError(t, contentStore.Open(keyMgr, &unlockOpts{}))
		require.EqualValues(t, sp.config.TagNames,
			[]string{"collection", "credential", "connection", "didResolutionResponse", "connection", "key"})

		// close store
		require.True(t, contentStore.Close())
		store, err := contentStore.open(token)
		require.Empty(t, store)
		require.True(t, errors.Is(err, ErrWalletLocked))
	})

	t.Run("create new content store for EDV profile - success", func(t *testing.T) {
		sp := getMockStorageProvider()

		masterLock, err := getDefaultSecretLock(samplePassPhrase)
		require.NoError(t, err)

		masterLockCipherText, err := createMasterLock(masterLock)
		require.NoError(t, err)
		require.NotEmpty(t, masterLockCipherText)

		profileInfo := &profile{
			ID:               uuid.New().String(),
			User:             uuid.New().String(),
			MasterLockCipher: masterLockCipherText,
			EDVConf: &edvConf{
				ServerURL: sampleEDVServerURL,
				VaultID:   sampleEDVVaultID,
			},
		}

		kmsStore, err := kms.NewAriesProviderWrapper(sp)
		require.NoError(t, err)

		kmgr, err := keyManager().createKeyManager(profileInfo, kmsStore, &unlockOpts{passphrase: samplePassPhrase})
		require.NotEmpty(t, kmgr)
		require.NoError(t, err)

		tkn, err := sessionManager().createSession(profileInfo.User, kmgr, 500*time.Millisecond)

		require.NoError(t, err)
		require.NotEmpty(t, kmgr)

		err = profileInfo.setupEDVEncryptionKey(kmgr)
		require.NoError(t, err)

		err = profileInfo.setupEDVMacKey(kmgr)
		require.NoError(t, err)

		// create new store
		contentStore := newContentStore(sp, createTestDocumentLoader(t), profileInfo)
		require.NotEmpty(t, contentStore)
		require.Empty(t, sp.config.TagNames)

		// open store
		require.NoError(t, contentStore.Open(kmgr, &unlockOpts{
			edvOpts: []edv.RESTProviderOption{
				edv.WithFullDocumentsReturnedFromQueries(),
				edv.WithBatchEndpointExtension(),
			},
		}))

		// close store
		require.True(t, contentStore.Close())
		store, err := contentStore.open(tkn)
		require.Empty(t, store)
		require.True(t, errors.Is(err, ErrWalletLocked))
	})

	t.Run("open store - failure", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore := newContentStore(sp, createTestDocumentLoader(t), &profile{ID: uuid.New().String()})

		// open store error
		sp.ErrOpenStoreHandle = errors.New(sampleContenttErr)
		err := contentStore.Open(keyMgr, &unlockOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleContenttErr)
		require.Contains(t, err.Error(), "failed to open store")

		// set store config error
		sp.ErrOpenStoreHandle = nil
		sp.failure = errors.New(sampleContenttErr)
		err = contentStore.Open(keyMgr, &unlockOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleContenttErr)
		require.Contains(t, err.Error(), "failed to set store config")

		sp.ErrOpenStoreHandle = nil
		sp.failure = nil
		sp.Store.ErrClose = errors.New(sampleContenttErr)
		contentStore = newContentStore(sp, createTestDocumentLoader(t), &profile{ID: uuid.New().String()})
		require.NoError(t, contentStore.Open(keyMgr, &unlockOpts{}))

		require.True(t, contentStore.Close())
	})

	t.Run("save to store - success", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore := newContentStore(sp, createTestDocumentLoader(t), &profile{ID: uuid.New().String()})
		require.NotEmpty(t, contentStore)

		require.NoError(t, contentStore.Open(keyMgr, &unlockOpts{}))

		err := contentStore.Save(token, Collection, []byte(sampleContentValid))
		require.NoError(t, err)

		// store is open but invalid auth token
		err = contentStore.Save(sampleFakeTkn, Collection, []byte(sampleContentValid))
		require.True(t, errors.Is(err, ErrInvalidAuthToken))

		err = contentStore.Save(sampleFakeTkn,
			Credential, testdata.SampleUDCVC, AddByCollection("test"))
		require.True(t, errors.Is(err, ErrInvalidAuthToken))
	})

	t.Run("save content to store without ID - success", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore := newContentStore(sp, createTestDocumentLoader(t), &profile{ID: uuid.New().String()})
		require.NotEmpty(t, contentStore)

		require.NoError(t, contentStore.Open(keyMgr, &unlockOpts{}))

		err := contentStore.Save(token, Collection, []byte(sampleContentNoID))
		require.NoError(t, err)
	})

	t.Run("save to doc resolution to store - success", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore := newContentStore(sp, createTestDocumentLoader(t), &profile{ID: uuid.New().String()})
		require.NotEmpty(t, contentStore)

		require.NoError(t, contentStore.Open(keyMgr, &unlockOpts{}))

		err := contentStore.Save(token, DIDResolutionResponse, []byte(didResolutionResult))
		require.NoError(t, err)

		// get by DID ID
		response, err := contentStore.Get(token,
			"did:key:z6Mks8mvCnVx4HQcoq7ZwvpTbMnoRGudHSiEpXhMf6VW8XMg", DIDResolutionResponse)
		require.NoError(t, err)
		require.NotEmpty(t, response)
		require.Equal(t, string(response), didResolutionResult)

		// store is open but invalid auth token
		response, err = contentStore.Get(sampleFakeTkn,
			"did:key:z6Mks8mvCnVx4HQcoq7ZwvpTbMnoRGudHSiEpXhMf6VW8XMg", DIDResolutionResponse)
		require.True(t, errors.Is(err, ErrInvalidAuthToken))
		require.Empty(t, response)
	})

	t.Run("save JWTVC to store - success", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore := newContentStore(sp, createTestDocumentLoader(t), &profile{ID: uuid.New().String()})
		require.NotEmpty(t, contentStore)

		require.NoError(t, contentStore.Open(keyMgr, &unlockOpts{}))

		err := contentStore.Save(token, Credential, []byte(sampleJWTCredContentValid))
		require.NoError(t, err)
	})

	t.Run("save key to store - success", func(t *testing.T) {
		sp := getMockStorageProvider()
		sampleUser := uuid.New().String()

		contentStore := newContentStore(sp, createTestDocumentLoader(t), &profile{ID: sampleUser})
		require.NotEmpty(t, contentStore)

		// wallet locked
		err := contentStore.Save(sampleFakeTkn, Key, []byte(sampleKeyContentBase58Valid))
		require.True(t, errors.Is(err, ErrWalletLocked))

		err = contentStore.Save(sampleFakeTkn, Key, []byte(sampleKeyContentJwkValid))
		require.True(t, errors.Is(err, ErrWalletLocked))

		// unlock keymanager
		masterLock, err := getDefaultSecretLock(samplePassPhrase)
		require.NoError(t, err)

		masterLockCipherText, err := createMasterLock(masterLock)
		require.NoError(t, err)
		require.NotEmpty(t, masterLockCipherText)

		profileInfo := &profile{
			User:             sampleUser,
			MasterLockCipher: masterLockCipherText,
		}

		kmsStore, err := kms.NewAriesProviderWrapper(mockstorage.NewMockStoreProvider())
		require.NoError(t, err)

		kmgr, err := keyManager().createKeyManager(profileInfo, kmsStore,
			&unlockOpts{passphrase: samplePassPhrase})
		require.NotEmpty(t, kmgr)
		require.NoError(t, err)

		tkn, err := sessionManager().createSession(profileInfo.User, kmgr, 500*time.Millisecond)

		require.NoError(t, err)
		require.NotEmpty(t, tkn)

		// import base58 private key
		err = contentStore.Save(tkn, Key, []byte(sampleKeyContentBase58Valid), ValidateContent())
		require.NoError(t, err)

		// import jwk private key
		err = contentStore.Save(tkn, Key, []byte(sampleKeyContentJwkValid), ValidateContent())
		require.NoError(t, err)

		// import using invalid auth token
		err = contentStore.Save(tkn+"invalid", Key, []byte(sampleKeyContentBase58Valid))
		require.True(t, errors.Is(err, ErrWalletLocked))
	})

	t.Run("save key to store - invalid jsonld", func(t *testing.T) {
		sp := getMockStorageProvider()
		sampleUser := uuid.New().String()

		contentStore := newContentStore(sp, createTestDocumentLoader(t), &profile{ID: sampleUser})
		require.NotEmpty(t, contentStore)

		// unlock keymanager
		masterLock, err := getDefaultSecretLock(samplePassPhrase)
		require.NoError(t, err)

		masterLockCipherText, err := createMasterLock(masterLock)
		require.NoError(t, err)
		require.NotEmpty(t, masterLockCipherText)

		profileInfo := &profile{
			User:             sampleUser,
			MasterLockCipher: masterLockCipherText,
		}

		kmsStore, err := kms.NewAriesProviderWrapper(mockstorage.NewMockStoreProvider())
		require.NoError(t, err)

		kmgr, err := keyManager().createKeyManager(profileInfo, kmsStore,
			&unlockOpts{passphrase: samplePassPhrase})
		require.NotEmpty(t, kmgr)
		require.NoError(t, err)

		tkn, err := sessionManager().createSession(profileInfo.User, kmgr, 500*time.Millisecond)

		require.NoError(t, err)
		require.NotEmpty(t, tkn)

		// import base58 private key
		err = contentStore.Save(tkn, Key, []byte(sampleKeyContentBase58WithInvalidField), ValidateContent())
		require.Contains(t, err.Error(), "JSON-LD doc has different structure after compaction")
	})

	t.Run("save JWTVC to store - failures", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore := newContentStore(sp, createTestDocumentLoader(t), &profile{ID: uuid.New().String()})
		require.NotEmpty(t, contentStore)

		require.NoError(t, contentStore.Open(keyMgr, &unlockOpts{}))

		// assumes bad data is not JWT, fails to parse as JSON
		err := contentStore.Save(token, Credential, []byte("f"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to read content to be saved")

		// fail to decode payload that isn't base64
		err = contentStore.Save(token, Credential, []byte("!!!!.!!!!.!!!!"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "decode base64 JWT data")

		// YWJjZGVm is abcdef in base64, so this isn't valid JSON
		err = contentStore.Save(token, Credential, []byte("YWJjZGVm.YWJjZGVm.YWJjZGVm"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to unmarshal JWT data")

		// e30 is {} in base64, so jwt is empty
		err = contentStore.Save(token, Credential, []byte("e30.e30.signature"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "JWT data has no ID")
	})

	t.Run("save key to store - failure", func(t *testing.T) {
		sp := getMockStorageProvider()
		sampleUser := uuid.New().String()

		contentStore := newContentStore(sp, createTestDocumentLoader(t), &profile{ID: sampleUser})
		require.NotEmpty(t, contentStore)

		// wallet locked
		err := contentStore.Save(token, Key, []byte(""))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to read key contents")
	})

	t.Run("save to doc resolution to store - failure", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore := newContentStore(sp, createTestDocumentLoader(t), &profile{ID: uuid.New().String()})
		require.NotEmpty(t, contentStore)

		err := contentStore.Save(token, DIDResolutionResponse, []byte(sampleContentInvalid))
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid DID resolution response model")
	})

	t.Run("save to store - failures", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore := newContentStore(sp, createTestDocumentLoader(t), &profile{ID: uuid.New().String()})
		require.NotEmpty(t, contentStore)

		// invalid content type
		err := contentStore.Save(token, ContentType("invalid"), []byte(sampleContentValid))
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid content type 'invalid'")

		// invalid content
		err = contentStore.Save(token, Credential, []byte("--"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to read content to be saved")

		// store errors
		sp.Store.ErrPut = errors.New(sampleContenttErr)

		contentStore = newContentStore(sp, createTestDocumentLoader(t), &profile{ID: uuid.New().String()})
		require.NotEmpty(t, contentStore)

		// wallet locked
		err = contentStore.Save(token, Credential, []byte(sampleContentValid))
		require.True(t, errors.Is(err, ErrWalletLocked))

		require.NoError(t, contentStore.Open(keyMgr, &unlockOpts{}))

		err = contentStore.Save(token, Credential, []byte(sampleContentValid))
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleContenttErr)

		sp.Store.ErrGet = errors.New(sampleContenttErr)
		err = contentStore.Save(token, Credential, []byte(sampleContentValid))
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleContenttErr)
	})

	t.Run("save to invalid content type - validation", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore := newContentStore(sp, createTestDocumentLoader(t), &profile{ID: uuid.New().String()})
		require.NotEmpty(t, contentStore)

		err := contentStore.Save(token, "Test", []byte("{}"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid content type")
	})

	t.Run("save duplicate items - validation", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore := newContentStore(sp, createTestDocumentLoader(t), &profile{ID: uuid.New().String()})
		require.NotEmpty(t, contentStore)

		require.NoError(t, contentStore.Open(keyMgr, &unlockOpts{}))

		err := contentStore.Save(token, Collection, []byte(sampleContentValid))
		require.NoError(t, err)

		// save again
		err = contentStore.Save(token, Collection, []byte(sampleContentValid))
		require.Error(t, err)
		require.Contains(t, err.Error(), "content with same type and id already exists in this wallet")
	})

	t.Run("get from store - success", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore := newContentStore(sp, createTestDocumentLoader(t), &profile{ID: uuid.New().String()})
		require.NotEmpty(t, contentStore)

		require.NoError(t, contentStore.Open(keyMgr, &unlockOpts{}))

		// save
		err := contentStore.Save(token, Collection, []byte(sampleContentValid))
		require.NoError(t, err)

		// get
		content, err := contentStore.Get(token, "did:example:123456789abcdefghi", Collection)
		require.NoError(t, err)
		require.Equal(t, sampleContentValid, string(content))
	})

	t.Run("get from store - failure", func(t *testing.T) {
		sp := getMockStorageProvider()
		sp.Store.ErrGet = errors.New(sampleContenttErr)

		contentStore := newContentStore(sp, createTestDocumentLoader(t), &profile{ID: uuid.New().String()})
		require.NotEmpty(t, contentStore)

		content, err := contentStore.Get(token, "did:example:123456789abcdefghi", Collection)
		require.Empty(t, content)
		require.True(t, errors.Is(err, ErrWalletLocked))

		require.NoError(t, contentStore.Open(keyMgr, &unlockOpts{}))

		// get
		content, err = contentStore.Get(token, "did:example:123456789abcdefghi", Collection)
		require.Empty(t, content)
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleContenttErr)
	})

	t.Run("remove from store - success", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore := newContentStore(sp, createTestDocumentLoader(t), &profile{ID: uuid.New().String()})
		require.NotEmpty(t, contentStore)

		require.NoError(t, contentStore.Open(keyMgr, &unlockOpts{}))

		// save
		err := contentStore.Save(token, Collection, []byte(sampleContentValid))
		require.NoError(t, err)

		// get
		content, err := contentStore.Get(token, "did:example:123456789abcdefghi", Collection)
		require.NoError(t, err)
		require.Equal(t, sampleContentValid, string(content))

		// remove
		err = contentStore.Remove(token, "did:example:123456789abcdefghi", Collection)
		require.NoError(t, err)

		// get
		content, err = contentStore.Get(token, "did:example:123456789abcdefghi", Collection)
		require.Empty(t, content)
		require.Error(t, err)
		require.True(t, errors.Is(err, storage.ErrDataNotFound))
	})

	t.Run("remove from store - failure", func(t *testing.T) {
		sp := getMockStorageProvider()
		sp.Store.ErrDelete = errors.New(sampleContenttErr)

		contentStore := newContentStore(sp, createTestDocumentLoader(t), &profile{ID: uuid.New().String()})
		require.NotEmpty(t, contentStore)

		require.NoError(t, contentStore.Open(keyMgr, &unlockOpts{}))

		// save
		err := contentStore.Save(token, Collection, []byte(sampleContentValid))
		require.NoError(t, err)

		// remove
		err = contentStore.Remove(token, "did:example:123456789abcdefghi", Collection)
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleContenttErr)

		require.True(t, contentStore.Close())
		err = contentStore.Remove(token, "did:example:123456789abcdefghi", Collection)
		require.True(t, errors.Is(err, ErrWalletLocked))
	})
}

func TestContentStore_GetAll(t *testing.T) {
	const vcContent = `{
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "credentialSchema": [],
      "credentialSubject": {
        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "name": "Jayden Doe"
      },
      "id": "%s",
      "issuanceDate": "2010-01-01T19:23:24Z",
      "issuer": {
        "id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
        "name": "Example University"
      },
      "type": [
        "VerifiableCredential",
        "UniversityDegreeCredential"
      ]
    }`

	const testMetadata = `{
  			"@context": ["https://w3id.org/wallet/v1"],
  		  	"id": "%s",
    		"type": "Person",
    		"name": "John Smith",
    		"image": "https://via.placeholder.com/150",
    		"description" : "Professional software developer for Acme Corp."
  		}`

	keyMgr := &mockkms.KeyManager{}

	token, err := sessionManager().createSession(uuid.New().String(), keyMgr, 500*time.Millisecond)
	require.NoError(t, err)

	t.Run("get all content from store for credential type - success", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore := newContentStore(sp, createTestDocumentLoader(t), &profile{ID: uuid.New().String()})
		require.NotEmpty(t, contentStore)

		require.NoError(t, contentStore.Open(keyMgr, &unlockOpts{}))

		// save test data
		const count = 5

		for i := 0; i < count; i++ {
			require.NoError(t, contentStore.Save(token,
				Credential, []byte(fmt.Sprintf(vcContent, uuid.New().String()))))
			require.NoError(t, contentStore.Save(token,
				Metadata, []byte(fmt.Sprintf(testMetadata, uuid.New().String()))))
		}

		allVcs, err := contentStore.GetAll(token, Credential)
		require.NoError(t, err)
		require.Len(t, allVcs, count)

		allMetadata, err := contentStore.GetAll(token, Metadata)
		require.NoError(t, err)
		require.Len(t, allMetadata, count)

		allDIDs, err := contentStore.GetAll(token, DIDResolutionResponse)
		require.NoError(t, err)
		require.Empty(t, allDIDs)

		// store is open but invalid auth token
		allMetadata, err = contentStore.GetAll(sampleFakeTkn, DIDResolutionResponse)
		require.True(t, errors.Is(err, ErrInvalidAuthToken))
		require.Empty(t, allMetadata)
	})

	t.Run("get all content from store for credential type - errors", func(t *testing.T) {
		sp := getMockStorageProvider()

		// wallet locked
		contentStore := newContentStore(sp, createTestDocumentLoader(t), &profile{ID: uuid.New().String()})

		allVcs, err := contentStore.GetAll(token, Credential)
		require.True(t, errors.Is(err, ErrWalletLocked))
		require.Empty(t, allVcs)

		require.NoError(t, contentStore.Open(keyMgr, &unlockOpts{}))
		require.NoError(t, contentStore.Save(token, Credential, []byte(fmt.Sprintf(vcContent, uuid.New().String()))))

		// iterator value error
		sp.MockStoreProvider.Store.ErrValue = errors.New(sampleContenttErr + uuid.New().String())

		allVcs, err = contentStore.GetAll(token, Credential)
		require.True(t, errors.Is(err, sp.MockStoreProvider.Store.ErrValue))
		require.Empty(t, allVcs)

		// iterator value error
		sp.MockStoreProvider.Store.ErrKey = errors.New(sampleContenttErr + uuid.New().String())

		contentStore = newContentStore(sp, createTestDocumentLoader(t), &profile{ID: uuid.New().String()})
		require.NotEmpty(t, contentStore)
		require.NoError(t, contentStore.Open(keyMgr, &unlockOpts{}))

		allVcs, err = contentStore.GetAll(token, Credential)
		require.True(t, errors.Is(err, sp.MockStoreProvider.Store.ErrKey))
		require.Empty(t, allVcs)

		// iterator next error
		sp.MockStoreProvider.Store.ErrNext = errors.New(sampleContenttErr + uuid.New().String())

		contentStore = newContentStore(sp, createTestDocumentLoader(t), &profile{ID: uuid.New().String()})
		require.NotEmpty(t, contentStore)
		require.NoError(t, contentStore.Open(keyMgr, &unlockOpts{}))

		require.NoError(t, contentStore.Save(token, Credential, []byte(fmt.Sprintf(vcContent, uuid.New().String()))))

		allVcs, err = contentStore.GetAll(token, Credential)
		require.True(t, errors.Is(err, sp.MockStoreProvider.Store.ErrNext))
		require.Empty(t, allVcs)

		// iterator next error
		sp.MockStoreProvider.Store.ErrQuery = errors.New(sampleContenttErr + uuid.New().String())

		contentStore = newContentStore(sp, createTestDocumentLoader(t), &profile{ID: uuid.New().String()})
		require.NotEmpty(t, contentStore)
		require.NoError(t, contentStore.Open(keyMgr, &unlockOpts{}))

		allVcs, err = contentStore.GetAll(token, Credential)
		require.True(t, errors.Is(err, sp.MockStoreProvider.Store.ErrQuery))
		require.Empty(t, allVcs)
	})
}

func TestContentDIDResolver(t *testing.T) {
	keyMgr := &mockkms.KeyManager{}

	token, err := sessionManager().createSession(uuid.New().String(), keyMgr, 500*time.Millisecond)
	require.NoError(t, err)

	t.Run("create new content store - success", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore := newContentStore(sp, createTestDocumentLoader(t), &profile{ID: uuid.New().String()})
		require.NotEmpty(t, contentStore)
		require.NoError(t, contentStore.Open(keyMgr, &unlockOpts{}))

		// save custom DID
		err := contentStore.Save(token, DIDResolutionResponse, testdata.SampleDocResolutionResponse)
		require.NoError(t, err)

		contentVDR := newContentBasedVDR(token, &vdr.MockVDRegistry{}, contentStore)
		require.NotEmpty(t, contentVDR)

		didDoc, err := contentVDR.Resolve("did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5")
		require.NoError(t, err)
		require.NotEmpty(t, didDoc)
		require.Equal(t, "did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5", didDoc.DIDDocument.ID)
		require.NotEmpty(t, didDoc.DIDDocument.Authentication)

		didDoc, err = contentVDR.Resolve("did:key:invalid")
		require.Error(t, err)
		require.Equal(t, vdrapi.ErrNotFound, err)
		require.Empty(t, didDoc)
	})

	t.Run("create new content store - errors", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore := newContentStore(sp, createTestDocumentLoader(t), &profile{ID: uuid.New().String()})
		require.NotEmpty(t, contentStore)

		contentVDR := newContentBasedVDR(token, &vdr.MockVDRegistry{}, contentStore)
		require.NotEmpty(t, contentVDR)

		// wallet locked
		didDoc, err := contentVDR.Resolve("did:key:invalid")
		require.True(t, errors.Is(err, ErrWalletLocked))
		require.Empty(t, didDoc)

		// open store
		require.NoError(t, contentStore.Open(keyMgr, &unlockOpts{}))

		// DID not found
		didDoc, err = contentVDR.Resolve("did:key:invalid")
		require.Error(t, err)
		require.Equal(t, vdrapi.ErrNotFound, err)
		require.Empty(t, didDoc)

		// parse error
		st, err := contentStore.open(token)
		require.NoError(t, err)
		err = st.Put(getContentKeyPrefix(DIDResolutionResponse,
			"did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5"), []byte(sampleInvalidDIDContent))
		require.NoError(t, err)

		didDoc, err = contentVDR.Resolve("did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse stored DID")
		require.Empty(t, didDoc)
	})
}

func TestContentStore_Collections(t *testing.T) {
	const vcContent = `{
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "credentialSchema": [],
      "credentialSubject": {
        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "name": "Jayden Doe"
      },
      "id": "%s",
      "issuanceDate": "2010-01-01T19:23:24Z",
      "issuer": {
        "id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
        "name": "Example University"
      },
      "type": [
        "VerifiableCredential",
        "UniversityDegreeCredential"
      ]
    }`

	const testMetadata = `{
  			"@context": ["https://w3id.org/wallet/v1"],
  		  	"id": "%s",
    		"type": "Person",
    		"name": "John Smith",
    		"image": "https://via.placeholder.com/150",
    		"description" : "Professional software developer for Acme Corp."
  		}`

	const connection = `{
                    "@context": ["https://w3id.org/wallet/v1"],
                    "id": "%s",
                    "name": "My Health Record Certifier",
                    "image": "https://via.placeholder.com/150",
                    "description" : "The identifier that issues health record credentials.",
                    "tags": ["professional"],
                    "correlation": ["4058a72a-9523-11ea-bb37-0242ac130002"],
                    "type": "Connection"
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

	keyMgr := &mockkms.KeyManager{}

	token, err := sessionManager().createSession(uuid.New().String(), keyMgr, 500*time.Millisecond)
	require.NoError(t, err)

	t.Run("contents by collection - success", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore := newContentStore(sp, createTestDocumentLoader(t), &profile{ID: uuid.New().String()})
		require.NotEmpty(t, contentStore)
		require.NoError(t, contentStore.Open(keyMgr, &unlockOpts{}))

		// save a collection
		require.NoError(t, contentStore.Save(token, Collection, []byte(orgCollection)))

		const addedWithoutCollection = 4
		const addedToCollection = 3

		// save test data
		for i := 0; i < addedToCollection; i++ {
			require.NoError(t, contentStore.Save(token,
				Credential, []byte(fmt.Sprintf(vcContent, uuid.New().String())), AddByCollection(collectionID)))
			require.NoError(t, contentStore.Save(token,
				Metadata, []byte(fmt.Sprintf(testMetadata, uuid.New().String())), AddByCollection(collectionID)))
		}

		require.NoError(t, contentStore.Save(token,
			DIDResolutionResponse, []byte(didResolutionResult), AddByCollection(collectionID)))

		for i := 0; i < addedWithoutCollection; i++ {
			require.NoError(t, contentStore.Save(token,
				Credential, []byte(fmt.Sprintf(vcContent, uuid.New().String()))))
			require.NoError(t, contentStore.Save(token,
				Metadata, []byte(fmt.Sprintf(testMetadata, uuid.New().String()))))
			require.NoError(t, contentStore.Save(token,
				Connection, []byte(fmt.Sprintf(connection, uuid.New().String()))))
		}

		allVcs, err := contentStore.GetAll(token, Credential)
		require.NoError(t, err)
		require.Len(t, allVcs, addedWithoutCollection+addedToCollection)

		allVcs, err = contentStore.GetAllByCollection(token, collectionID, Credential)
		require.NoError(t, err)
		require.Len(t, allVcs, addedToCollection)

		allMetadata, err := contentStore.GetAll(token, Metadata)
		require.NoError(t, err)
		require.Len(t, allMetadata, addedWithoutCollection+addedToCollection)

		allMetadata, err = contentStore.GetAllByCollection(token, collectionID, Metadata)
		require.NoError(t, err)
		require.Len(t, allMetadata, addedToCollection)

		allDIDs, err := contentStore.GetAll(token, DIDResolutionResponse)
		require.NoError(t, err)
		require.Len(t, allDIDs, 1)

		allDIDs, err = contentStore.GetAllByCollection(token, collectionID, DIDResolutionResponse)
		require.NoError(t, err)
		require.Len(t, allDIDs, 1)

		allConns, err := contentStore.GetAll(token, Connection)
		require.NoError(t, err)
		require.Len(t, allConns, addedWithoutCollection)

		allConns, err = contentStore.GetAllByCollection(token, collectionID, Connection)
		require.NoError(t, err)
		require.Empty(t, allConns)
	})

	t.Run("contents by collection - failure", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore := newContentStore(sp, createTestDocumentLoader(t), &profile{ID: uuid.New().String()})
		require.NotEmpty(t, contentStore)
		require.NoError(t, contentStore.Open(keyMgr, &unlockOpts{}))

		err := contentStore.Save(token,
			DIDResolutionResponse, []byte(didResolutionResult), AddByCollection(collectionID+"invalid"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to find existing collection")

		err = contentStore.Save(token,
			Credential, []byte(fmt.Sprintf(vcContent, uuid.New().String())), AddByCollection(collectionID+"invalid"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to find existing collection")

		// save a collection
		require.NoError(t, contentStore.Save(token, Collection, []byte(orgCollection)))
		require.NoError(t, contentStore.Save(token, Credential, []byte(fmt.Sprintf(vcContent, uuid.New().String())),
			AddByCollection(collectionID)))

		// get content error
		sp.MockStoreProvider.Store.ErrGet = errors.New(sampleContenttErr + uuid.New().String())

		contentStore = newContentStore(sp, createTestDocumentLoader(t), &profile{ID: uuid.New().String()})
		require.NotEmpty(t, contentStore)
		require.NoError(t, contentStore.Open(keyMgr, &unlockOpts{}))

		allVcs, err := contentStore.GetAllByCollection(token, collectionID, Credential)
		require.True(t, errors.Is(err, sp.MockStoreProvider.Store.ErrGet))
		require.Empty(t, allVcs)

		// iterator value error
		sp.MockStoreProvider.Store.ErrValue = errors.New(sampleContenttErr + uuid.New().String())

		contentStore = newContentStore(sp, createTestDocumentLoader(t), &profile{ID: uuid.New().String()})
		require.NotEmpty(t, contentStore)
		require.NoError(t, contentStore.Open(keyMgr, &unlockOpts{}))

		allVcs, err = contentStore.GetAllByCollection(token, collectionID, Credential)
		require.True(t, errors.Is(err, sp.MockStoreProvider.Store.ErrValue))
		require.Empty(t, allVcs)

		// iterator value error
		sp.MockStoreProvider.Store.ErrKey = errors.New(sampleContenttErr + uuid.New().String())

		contentStore = newContentStore(sp, createTestDocumentLoader(t), &profile{ID: uuid.New().String()})
		require.NotEmpty(t, contentStore)
		require.NoError(t, contentStore.Open(keyMgr, &unlockOpts{}))

		allVcs, err = contentStore.GetAllByCollection(token, collectionID, Credential)
		require.True(t, errors.Is(err, sp.MockStoreProvider.Store.ErrKey))
		require.Empty(t, allVcs)

		// iterator next error
		sp.MockStoreProvider.Store.ErrNext = errors.New(sampleContenttErr + uuid.New().String())

		contentStore = newContentStore(sp, createTestDocumentLoader(t), &profile{ID: uuid.New().String()})
		require.NotEmpty(t, contentStore)
		require.NoError(t, contentStore.Open(keyMgr, &unlockOpts{}))

		allVcs, err = contentStore.GetAllByCollection(token, collectionID, Credential)
		require.True(t, errors.Is(err, sp.MockStoreProvider.Store.ErrNext))
		require.Empty(t, allVcs)

		// iterator next error
		sp.MockStoreProvider.Store.ErrQuery = errors.New(sampleContenttErr + uuid.New().String())

		contentStore = newContentStore(sp, createTestDocumentLoader(t), &profile{ID: uuid.New().String()})
		require.NotEmpty(t, contentStore)
		require.NoError(t, contentStore.Open(keyMgr, &unlockOpts{}))

		allVcs, err = contentStore.GetAllByCollection(token, collectionID, Credential)
		require.True(t, errors.Is(err, sp.MockStoreProvider.Store.ErrQuery))
		require.Empty(t, allVcs)

		// wallet locked error
		require.True(t, contentStore.Close())
		allVcs, err = contentStore.GetAllByCollection(token, collectionID, Credential)
		require.True(t, errors.Is(err, ErrWalletLocked))
		require.Empty(t, allVcs)
	})
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

func getMockStorageProvider() *mockStorageProvider {
	return &mockStorageProvider{MockStoreProvider: mockstorage.NewMockStoreProvider()}
}

func createTestDocumentLoader(t *testing.T) *ld.DocumentLoader {
	t.Helper()

	loader, err := ldtestutil.DocumentLoader()
	require.NoError(t, err)

	return loader
}
