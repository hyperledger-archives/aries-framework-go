/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

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
  		  	"controller": "did:example:123456789abcdefghi",
			"type": "Ed25519VerificationKey2018",
			"privateKeyBase58":"zJRjGFZydU5DBdS2p5qbiUzDFAxbXTkjiDuGPksMBbY5TNyEsGfK4a4WGKjBCh1zeNryeuKtPotp8W1ESnwP71y"
  		}`
	sampleKeyContentJwkValid = `{
  			"@context": ["https://w3id.org/wallet/v1"],
  		  	"id": "did:example:123456789abcdefghi#z6MkiEh8RQL83nkPo8ehDeX7",
  		  	"controller": "did:example:123456789abcdefghi",
			"type": "Ed25519VerificationKey2018",
			"privateKeyJwk": {
				"kty": "OKP",
				"d":"Dq5t2WS3OMzcpkh8AyVxJs5r9v4L39ocIz9CpUOqM40",
				"crv": "Ed25519",
				"x": "ODaPFurJgFcoVCUYEmgOJpWOtPlOYbHSugasscKWqDM",
				"kid":"z6MkiEh8RQL83nkPo8ehDeX7"
			}
  		}`
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
	t.Run("create new content store - success", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore, err := newContentStore(sp, &profile{ID: uuid.New().String()})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)
		require.EqualValues(t, sp.config.TagNames,
			[]string{"collection", "credential", "connection", "didResolutionResponse", "connection", "key"})
	})

	t.Run("create new content store - failure", func(t *testing.T) {
		sp := getMockStorageProvider()
		sp.failure = errors.New(sampleContenttErr)

		// set store config error
		contentStore, err := newContentStore(sp, &profile{ID: uuid.New().String()})
		require.Empty(t, contentStore)
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleContenttErr)
		require.Contains(t, err.Error(), "failed to set store config for user")

		// open store error
		sp.failure = nil
		sp.ErrOpenStoreHandle = errors.New(sampleContenttErr)

		contentStore, err = newContentStore(sp, &profile{ID: uuid.New().String()})
		require.Empty(t, contentStore)
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleContenttErr)
		require.Contains(t, err.Error(), "failed to create store for user")
	})

	t.Run("save to store - success", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore, err := newContentStore(sp, &profile{ID: uuid.New().String()})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)

		err = contentStore.Save(sampleFakeTkn, Collection, []byte(sampleContentValid))
		require.NoError(t, err)
	})

	t.Run("save content to store without ID - success", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore, err := newContentStore(sp, &profile{ID: uuid.New().String()})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)

		err = contentStore.Save(sampleFakeTkn, Collection, []byte(sampleContentNoID))
		require.NoError(t, err)
	})

	t.Run("save to doc resolution to store - success", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore, err := newContentStore(sp, &profile{ID: uuid.New().String()})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)

		err = contentStore.Save(sampleFakeTkn, DIDResolutionResponse, []byte(didResolutionResult))
		require.NoError(t, err)

		// get by DID ID
		response, err := contentStore.Get(DIDResolutionResponse,
			"did:key:z6Mks8mvCnVx4HQcoq7ZwvpTbMnoRGudHSiEpXhMf6VW8XMg")
		require.NoError(t, err)
		require.NotEmpty(t, response)
		require.Equal(t, string(response), didResolutionResult)
	})

	t.Run("save key to store - success", func(t *testing.T) {
		sp := getMockStorageProvider()
		sampleUser := uuid.New().String()

		contentStore, err := newContentStore(sp, &profile{ID: sampleUser})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)

		// wallet locked
		err = contentStore.Save(sampleFakeTkn, Key, []byte(sampleKeyContentBase58Valid))
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

		tkn, err := keyManager().createKeyManager(profileInfo, mockstorage.NewMockStoreProvider(),
			&unlockOpts{passphrase: samplePassPhrase})
		require.NoError(t, err)
		require.NotEmpty(t, tkn)

		// import base58 private key
		err = contentStore.Save(tkn, Key, []byte(sampleKeyContentBase58Valid))
		require.NoError(t, err)

		// import jwk private key
		err = contentStore.Save(tkn, Key, []byte(sampleKeyContentJwkValid))
		require.NoError(t, err)
	})

	t.Run("save key to store - failure", func(t *testing.T) {
		sp := getMockStorageProvider()
		sampleUser := uuid.New().String()

		contentStore, err := newContentStore(sp, &profile{ID: sampleUser})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)

		// wallet locked
		err = contentStore.Save(sampleFakeTkn, Key, []byte(""))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to read key contents")
	})

	t.Run("save to doc resolution to store - failure", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore, err := newContentStore(sp, &profile{ID: uuid.New().String()})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)

		err = contentStore.Save(sampleFakeTkn, DIDResolutionResponse, []byte(sampleContentInvalid))
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid DID resolution response model")
	})

	t.Run("save to store - failures", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore, err := newContentStore(sp, &profile{ID: uuid.New().String()})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)

		// invalid content type
		err = contentStore.Save(sampleFakeTkn, ContentType("invalid"), []byte(sampleContentValid))
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid content type 'invalid'")

		// invalid content
		err = contentStore.Save(sampleFakeTkn, Credential, []byte("--"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to read content to be saved")

		// store errors
		sp.Store.ErrPut = errors.New(sampleContenttErr)

		contentStore, err = newContentStore(sp, &profile{ID: uuid.New().String()})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)

		err = contentStore.Save(sampleFakeTkn, Credential, []byte(sampleContentValid))
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleContenttErr)

		sp.Store.ErrGet = errors.New(sampleContenttErr)
		err = contentStore.Save(sampleFakeTkn, Credential, []byte(sampleContentValid))
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleContenttErr)
	})

	t.Run("save to invalid content type - validation", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore, err := newContentStore(sp, &profile{ID: uuid.New().String()})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)

		err = contentStore.Save(sampleFakeTkn, "Test", []byte("{}"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid content type")
	})

	t.Run("save duplicate items - validation", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore, err := newContentStore(sp, &profile{ID: uuid.New().String()})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)

		err = contentStore.Save(sampleFakeTkn, Collection, []byte(sampleContentValid))
		require.NoError(t, err)

		// save again
		err = contentStore.Save(sampleFakeTkn, Collection, []byte(sampleContentValid))
		require.Error(t, err)
		require.Contains(t, err.Error(), "content with same type and id already exists in this wallet")
	})

	t.Run("get from store - success", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore, err := newContentStore(sp, &profile{ID: uuid.New().String()})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)

		// save
		err = contentStore.Save(sampleFakeTkn, Collection, []byte(sampleContentValid))
		require.NoError(t, err)

		// get
		content, err := contentStore.Get(Collection, "did:example:123456789abcdefghi")
		require.NoError(t, err)
		require.Equal(t, sampleContentValid, string(content))
	})

	t.Run("get from store - failure", func(t *testing.T) {
		sp := getMockStorageProvider()
		sp.Store.ErrGet = errors.New(sampleContenttErr)

		contentStore, err := newContentStore(sp, &profile{ID: uuid.New().String()})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)

		// remove
		content, err := contentStore.Get(Collection, "did:example:123456789abcdefghi")
		require.Empty(t, content)
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleContenttErr)
	})

	t.Run("remove from store - success", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore, err := newContentStore(sp, &profile{ID: uuid.New().String()})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)

		// save
		err = contentStore.Save(sampleFakeTkn, Collection, []byte(sampleContentValid))
		require.NoError(t, err)

		// get
		content, err := contentStore.Get(Collection, "did:example:123456789abcdefghi")
		require.NoError(t, err)
		require.Equal(t, sampleContentValid, string(content))

		// remove
		err = contentStore.Remove(Collection, "did:example:123456789abcdefghi")
		require.NoError(t, err)

		// get
		content, err = contentStore.Get(Collection, "did:example:123456789abcdefghi")
		require.Empty(t, content)
		require.Error(t, err)
		require.True(t, errors.Is(err, storage.ErrDataNotFound))
	})

	t.Run("remove from store - failure", func(t *testing.T) {
		sp := getMockStorageProvider()
		sp.Store.ErrDelete = errors.New(sampleContenttErr)

		contentStore, err := newContentStore(sp, &profile{ID: uuid.New().String()})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)

		// save
		err = contentStore.Save(sampleFakeTkn, Collection, []byte(sampleContentValid))
		require.NoError(t, err)

		// remove
		err = contentStore.Remove(Collection, "did:example:123456789abcdefghi")
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleContenttErr)
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

	t.Run("get all content from store for credential type - success", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore, err := newContentStore(sp, &profile{ID: uuid.New().String()})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)

		// save test data
		const count = 5

		for i := 0; i < count; i++ {
			require.NoError(t, contentStore.Save(sampleFakeTkn,
				Credential, []byte(fmt.Sprintf(vcContent, uuid.New().String()))))
			require.NoError(t, contentStore.Save(sampleFakeTkn,
				Metadata, []byte(fmt.Sprintf(testMetadata, uuid.New().String()))))
		}

		allVcs, err := contentStore.GetAll(Credential)
		require.NoError(t, err)
		require.Len(t, allVcs, count)

		allMetadata, err := contentStore.GetAll(Metadata)
		require.NoError(t, err)
		require.Len(t, allMetadata, count)

		allDIDs, err := contentStore.GetAll(DIDResolutionResponse)
		require.NoError(t, err)
		require.Empty(t, allDIDs)
	})

	t.Run("get all content from store for credential type - errors", func(t *testing.T) {
		sp := getMockStorageProvider()

		// iterator value error
		sp.MockStoreProvider.Store.ErrValue = errors.New(sampleContenttErr + uuid.New().String())

		contentStore, err := newContentStore(sp, &profile{ID: uuid.New().String()})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)

		require.NoError(t, contentStore.Save(sampleFakeTkn, Credential, []byte(fmt.Sprintf(vcContent, uuid.New().String()))))

		allVcs, err := contentStore.GetAll(Credential)
		require.True(t, errors.Is(err, sp.MockStoreProvider.Store.ErrValue))
		require.Empty(t, allVcs)

		// iterator value error
		sp.MockStoreProvider.Store.ErrKey = errors.New(sampleContenttErr + uuid.New().String())

		contentStore, err = newContentStore(sp, &profile{ID: uuid.New().String()})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)

		allVcs, err = contentStore.GetAll(Credential)
		require.True(t, errors.Is(err, sp.MockStoreProvider.Store.ErrKey))
		require.Empty(t, allVcs)

		// iterator next error
		sp.MockStoreProvider.Store.ErrNext = errors.New(sampleContenttErr + uuid.New().String())

		contentStore, err = newContentStore(sp, &profile{ID: uuid.New().String()})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)

		require.NoError(t, contentStore.Save(sampleFakeTkn, Credential, []byte(fmt.Sprintf(vcContent, uuid.New().String()))))

		allVcs, err = contentStore.GetAll(Credential)
		require.True(t, errors.Is(err, sp.MockStoreProvider.Store.ErrNext))
		require.Empty(t, allVcs)

		// iterator next error
		sp.MockStoreProvider.Store.ErrQuery = errors.New(sampleContenttErr + uuid.New().String())

		contentStore, err = newContentStore(sp, &profile{ID: uuid.New().String()})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)

		allVcs, err = contentStore.GetAll(Credential)
		require.True(t, errors.Is(err, sp.MockStoreProvider.Store.ErrQuery))
		require.Empty(t, allVcs)
	})
}

func TestContentDIDResolver(t *testing.T) {
	t.Run("create new content store - success", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore, err := newContentStore(sp, &profile{ID: uuid.New().String()})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)

		// save custom DID
		err = contentStore.Save(sampleFakeTkn, DIDResolutionResponse, []byte(sampleDocResolutionResponse))
		require.NoError(t, err)

		contentVDR := newContentBasedVDR(&vdr.MockVDRegistry{}, contentStore)
		require.NotEmpty(t, contentVDR)

		didDoc, err := contentVDR.Resolve("did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5")
		require.NoError(t, err)
		require.NotEmpty(t, didDoc)
		require.Equal(t, "did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5", didDoc.DIDDocument.ID)
		require.NotEmpty(t, didDoc.DIDDocument.Authentication)

		didDoc, err = contentVDR.Resolve("did:key:invalid")
		require.Error(t, err)
		require.Contains(t, err.Error(), "DID not found")
		require.Empty(t, didDoc)
	})

	t.Run("create new content store - errors", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore, err := newContentStore(sp, &profile{ID: uuid.New().String()})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)

		contentVDR := newContentBasedVDR(&vdr.MockVDRegistry{}, contentStore)
		require.NotEmpty(t, contentVDR)

		// DID not found
		didDoc, err := contentVDR.Resolve("did:key:invalid")
		require.Error(t, err)
		require.Contains(t, err.Error(), "DID not found")
		require.Empty(t, didDoc)

		// parse error
		err = contentStore.store.Put(getContentKeyPrefix(DIDResolutionResponse,
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

	t.Run("contents by collection - success", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore, err := newContentStore(sp, &profile{ID: uuid.New().String()})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)

		// save a collection
		require.NoError(t, contentStore.Save(sampleFakeTkn, Collection, []byte(orgCollection)))

		const addedWithoutCollection = 4
		const addedToCollection = 3

		// save test data
		for i := 0; i < addedToCollection; i++ {
			require.NoError(t, contentStore.Save(sampleFakeTkn,
				Credential, []byte(fmt.Sprintf(vcContent, uuid.New().String())), AddByCollection(collectionID)))
			require.NoError(t, contentStore.Save(sampleFakeTkn,
				Metadata, []byte(fmt.Sprintf(testMetadata, uuid.New().String())), AddByCollection(collectionID)))
		}

		require.NoError(t, contentStore.Save(sampleFakeTkn,
			DIDResolutionResponse, []byte(didResolutionResult), AddByCollection(collectionID)))

		for i := 0; i < addedWithoutCollection; i++ {
			require.NoError(t, contentStore.Save(sampleFakeTkn,
				Credential, []byte(fmt.Sprintf(vcContent, uuid.New().String()))))
			require.NoError(t, contentStore.Save(sampleFakeTkn,
				Metadata, []byte(fmt.Sprintf(testMetadata, uuid.New().String()))))
			require.NoError(t, contentStore.Save(sampleFakeTkn,
				Connection, []byte(fmt.Sprintf(connection, uuid.New().String()))))
		}

		allVcs, err := contentStore.GetAll(Credential)
		require.NoError(t, err)
		require.Len(t, allVcs, addedWithoutCollection+addedToCollection)

		allVcs, err = contentStore.GetAllByCollection(Credential, collectionID)
		require.NoError(t, err)
		require.Len(t, allVcs, addedToCollection)

		allMetadata, err := contentStore.GetAll(Metadata)
		require.NoError(t, err)
		require.Len(t, allMetadata, addedWithoutCollection+addedToCollection)

		allMetadata, err = contentStore.GetAllByCollection(Metadata, collectionID)
		require.NoError(t, err)
		require.Len(t, allMetadata, addedToCollection)

		allDIDs, err := contentStore.GetAll(DIDResolutionResponse)
		require.NoError(t, err)
		require.Len(t, allDIDs, 1)

		allDIDs, err = contentStore.GetAllByCollection(DIDResolutionResponse, collectionID)
		require.NoError(t, err)
		require.Len(t, allDIDs, 1)

		allConns, err := contentStore.GetAll(Connection)
		require.NoError(t, err)
		require.Len(t, allConns, addedWithoutCollection)

		allConns, err = contentStore.GetAllByCollection(Connection, collectionID)
		require.NoError(t, err)
		require.Empty(t, allConns)
	})

	t.Run("contents by collection - failure", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore, err := newContentStore(sp, &profile{ID: uuid.New().String()})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)

		err = contentStore.Save(sampleFakeTkn,
			DIDResolutionResponse, []byte(didResolutionResult), AddByCollection(collectionID+"invalid"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to find existing collection")

		err = contentStore.Save(sampleFakeTkn,
			Credential, []byte(fmt.Sprintf(vcContent, uuid.New().String())), AddByCollection(collectionID+"invalid"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to find existing collection")

		// save a collection
		require.NoError(t, contentStore.Save(sampleFakeTkn, Collection, []byte(orgCollection)))
		require.NoError(t, contentStore.Save(sampleFakeTkn, Credential, []byte(fmt.Sprintf(vcContent, uuid.New().String())),
			AddByCollection(collectionID)))

		// get content error
		sp.MockStoreProvider.Store.ErrGet = errors.New(sampleContenttErr + uuid.New().String())

		contentStore, err = newContentStore(sp, &profile{ID: uuid.New().String()})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)

		allVcs, err := contentStore.GetAllByCollection(Credential, collectionID)
		require.True(t, errors.Is(err, sp.MockStoreProvider.Store.ErrGet))
		require.Empty(t, allVcs)

		// iterator value error
		sp.MockStoreProvider.Store.ErrValue = errors.New(sampleContenttErr + uuid.New().String())

		contentStore, err = newContentStore(sp, &profile{ID: uuid.New().String()})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)

		allVcs, err = contentStore.GetAllByCollection(Credential, collectionID)
		require.True(t, errors.Is(err, sp.MockStoreProvider.Store.ErrValue))
		require.Empty(t, allVcs)

		// iterator value error
		sp.MockStoreProvider.Store.ErrKey = errors.New(sampleContenttErr + uuid.New().String())

		contentStore, err = newContentStore(sp, &profile{ID: uuid.New().String()})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)

		allVcs, err = contentStore.GetAllByCollection(Credential, collectionID)
		require.True(t, errors.Is(err, sp.MockStoreProvider.Store.ErrKey))
		require.Empty(t, allVcs)

		// iterator next error
		sp.MockStoreProvider.Store.ErrNext = errors.New(sampleContenttErr + uuid.New().String())

		contentStore, err = newContentStore(sp, &profile{ID: uuid.New().String()})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)

		allVcs, err = contentStore.GetAllByCollection(Credential, collectionID)
		require.True(t, errors.Is(err, sp.MockStoreProvider.Store.ErrNext))
		require.Empty(t, allVcs)

		// iterator next error
		sp.MockStoreProvider.Store.ErrQuery = errors.New(sampleContenttErr + uuid.New().String())

		contentStore, err = newContentStore(sp, &profile{ID: uuid.New().String()})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)

		allVcs, err = contentStore.GetAllByCollection(Credential, collectionID)
		require.True(t, errors.Is(err, sp.MockStoreProvider.Store.ErrQuery))
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
