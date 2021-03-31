/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcwallet

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
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
	sampleDIDKey2       = "did:key:z6MkwFKUCsf8wvn6eSSu1WFAKatN1yexiDM7bf7pZLSFjdz6"
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
	sampleVP = `{
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "holder": "did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5",
    "proof": {
        "created": "2021-03-26T14:08:21.15597-04:00",
        "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..GUbI3psCXXhCjDJ2yBTwteuKSUHJuEK840yJzxWuPPxYyAuza1uwK1v75Az2jO63ILHEsLmxwcEhBlKcTw7ODA",
        "proofPurpose": "authentication",
        "type": "Ed25519Signature2018",
        "verificationMethod": "did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5#z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5"
    },
    "type": "VerifiablePresentation",
    "verifiableCredential": [{
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
            "created": "2021-03-26T14:08:20.898673-04:00",
            "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..PeIllfXnUh7zD4mH24NCnfFFeKf0Fys8XWt8nVE2Z-fgSvE6-3Rbc-LgSIpyKPF20CtFzEdownwOiMavy2_tAQ",
            "proofPurpose": "assertionMethod",
            "type": "Ed25519Signature2018",
            "verificationMethod": "did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5#z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5"
        },
        "referenceNumber": 83294847,
        "type": ["VerifiableCredential", "UniversityDegreeCredential"]
    }]
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
	sampleInvalidDIDContent = `{
    	"@context": ["https://w3id.org/did/v1"],
    	"id": "did:example:sampleInvalidDIDContent"
		}`

	sampleKeyContentBase58 = `{
  			"@context": ["https://w3id.org/wallet/v1"],
  		  	"id": "did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5#z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5",
  		  	"controller": "did:example:123456789abcdefghi",
			"type": "Ed25519VerificationKey2018",
			"privateKeyBase58":"2MP5gWCnf67jvW3E4Lz8PpVrDWAXMYY1sDxjnkEnKhkkbKD7yP2mkVeyVpu5nAtr3TeDgMNjBPirk2XcQacs3dvZ"
  		}`

	sampleDIDResolutionResponse = `{
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
        "@context": [
            "https://w3id.org/did/v0.11"
        ],
        "id": "did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5",
        "publicKey": [
            {
                "id": "did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5#z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5",
                "type": "Ed25519VerificationKey2018",
                "controller": "did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5",
                "publicKeyBase58": "8jkuMBqmu1TRA6is7TT5tKBksTZamrLhaXrg9NAczqeh"
            }
        ],
        "authentication": [
            "did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5#z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5"
        ],
        "assertionMethod": [
            "did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5#z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5"
        ],
        "capabilityDelegation": [
            "did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5#z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5"
        ],
        "capabilityInvocation": [
            "did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5#z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5"
        ],
        "keyAgreement": [
            {
                "id": "did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5#z6LSmjNfS5FC9W59JtPZq7fHgrjThxsidjEhZeMxCarbR998",
                "type": "X25519KeyAgreementKey2019",
                "controller": "did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5",
                "publicKeyBase58": "B4CVumSL43MQDW1oJU9LNGWyrpLbw84YgfeGi8D4hmNN"
            }
        ]
    }
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

	vcWalletClient, err := New(sampleUserID, mockctx, wallet.WithUnlockByPassphrase(samplePassPhrase))
	require.NotEmpty(t, vcWalletClient)
	require.NoError(t, err)

	err = vcWalletClient.Add(wallet.Metadata, []byte(sampleContentValid))
	require.NoError(t, err)
}

func TestClient_Get(t *testing.T) {
	mockctx := newMockProvider()
	err := CreateProfile(sampleUserID, mockctx, wallet.WithKeyServerURL(sampleKeyServerURL))
	require.NoError(t, err)

	vcWalletClient, err := New(sampleUserID, mockctx, wallet.WithUnlockByPassphrase(samplePassPhrase))
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

	vcWalletClient, err := New(sampleUserID, mockctx, wallet.WithUnlockByPassphrase(samplePassPhrase))
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

	t.Run("Test VC wallet client issue using controller - success", func(t *testing.T) {
		vcWalletClient, err := New(sampleUserID, mockctx, wallet.WithUnlockByPassphrase(samplePassPhrase))
		require.NotEmpty(t, vcWalletClient)
		require.NoError(t, err)

		defer vcWalletClient.Close()

		// save a DID & corresponding key
		require.NoError(t, vcWalletClient.Add(wallet.Key, []byte(sampleKeyContentBase58)))
		require.NoError(t, vcWalletClient.Add(wallet.DIDResolutionResponse, []byte(sampleDIDResolutionResponse)))

		result, err := vcWalletClient.Issue([]byte(sampleUDCVC), &wallet.ProofOptions{
			Controller: sampleDIDKey,
		})

		require.NoError(t, err)
		require.NotEmpty(t, result)
		require.NotEmpty(t, result.Proofs)
	})

	t.Run("Test VC wallet client issue using controller - failure", func(t *testing.T) {
		vcWalletClient, err := New(sampleUserID, mockctx, wallet.WithUnlockByPassphrase(samplePassPhrase))
		require.NotEmpty(t, vcWalletClient)
		require.NoError(t, err)

		defer vcWalletClient.Close()

		// sign with just controller
		result, err := vcWalletClient.Issue([]byte(sampleUDCVC), &wallet.ProofOptions{
			Controller: sampleDIDKey2,
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

	t.Run("Test VC wallet client prove using controller - success", func(t *testing.T) {
		vcWalletClient, err := New(sampleUserID, mockctx, wallet.WithUnlockByPassphrase(samplePassPhrase))
		require.NotEmpty(t, vcWalletClient)
		require.NoError(t, err)

		defer vcWalletClient.Close()

		// save a credential, DID & key
		require.NoError(t, vcWalletClient.Add(wallet.Credential, []byte(sampleUDCVC)))
		require.NoError(t, vcWalletClient.Add(wallet.Key, []byte(sampleKeyContentBase58)))
		require.NoError(t, vcWalletClient.Add(wallet.DIDResolutionResponse, []byte(sampleDIDResolutionResponse)))

		result, err := vcWalletClient.Prove(&wallet.ProofOptions{Controller: sampleDIDKey},
			wallet.WithStoredCredentialsToPresent("http://example.edu/credentials/1872"),
			wallet.WithRawCredentialsToPresent([]byte(sampleUDCVC)),
		)
		require.NoError(t, err)
		require.NotEmpty(t, result)
		require.NotEmpty(t, result.Proofs)
	})

	t.Run("Test VC wallet client prove using controller - failure", func(t *testing.T) {
		vcWalletClient, err := New(sampleUserID, mockctx, wallet.WithUnlockByPassphrase(samplePassPhrase))
		require.NotEmpty(t, vcWalletClient)
		require.NoError(t, err)

		defer vcWalletClient.Close()

		require.NoError(t, vcWalletClient.Remove(wallet.Credential, "http://example.edu/credentials/1872"))
		require.NoError(t, vcWalletClient.Add(wallet.Credential, []byte(sampleUDCVC)))

		result, err := vcWalletClient.Prove(&wallet.ProofOptions{Controller: sampleDIDKey2},
			wallet.WithStoredCredentialsToPresent("http://example.edu/credentials/1872"),
			wallet.WithRawCredentialsToPresent([]byte(sampleUDCVC)),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to read json keyset from reader")
		require.Empty(t, result)
	})

	t.Run("Test VC wallet client prove using controller - wallet locked", func(t *testing.T) {
		vcWalletClient, err := New(sampleUserID, mockctx, wallet.WithUnlockByPassphrase(samplePassPhrase))
		require.NotEmpty(t, vcWalletClient)
		require.NoError(t, err)

		defer vcWalletClient.Close()

		require.NoError(t, vcWalletClient.Remove(wallet.Credential, "http://example.edu/credentials/1872"))
		require.NoError(t, vcWalletClient.Add(wallet.Credential, []byte(sampleUDCVC)))

		vcWalletClient.Close()

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

		// verify stored VC
		ok, err := vcWalletClient.Verify(wallet.WithStoredCredentialToVerify("http://example.edu/credentials/1872"))
		require.NoError(t, err)
		require.True(t, ok)

		// verify raw VC
		ok, err = vcWalletClient.Verify(wallet.WithRawCredentialToVerify([]byte(sampleUDCVCWithProof)))
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
		require.NoError(t, vcWalletClient.Remove(wallet.Credential, "http://example.edu/credentials/1872"))
		require.NoError(t, vcWalletClient.Add(wallet.Credential, []byte(tamperedVC)))

		ok, err := vcWalletClient.Verify(wallet.WithStoredCredentialToVerify("http://example.edu/credentials/1872"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid signature")
		require.False(t, ok)

		ok, err = vcWalletClient.Verify(wallet.WithRawCredentialToVerify([]byte(tamperedVC)))
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid signature")
		require.False(t, ok)
	})

	t.Run("Test VC wallet verify presentation - success", func(t *testing.T) {
		vcWalletClient, err := New(sampleUserID, mockctx, wallet.WithUnlockByPassphrase(samplePassPhrase))
		require.NotEmpty(t, vcWalletClient)
		require.NoError(t, err)

		defer vcWalletClient.Close()

		// verify raw VC
		ok, err := vcWalletClient.Verify(wallet.WithRawPresentationToVerify([]byte(sampleVP)))
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("Test VC wallet verify presentation - invalid signature", func(t *testing.T) {
		vcWalletClient, err := New(sampleUserID, mockctx, wallet.WithUnlockByPassphrase(samplePassPhrase))
		require.NotEmpty(t, vcWalletClient)
		require.NoError(t, err)

		defer vcWalletClient.Close()

		tamperedVP := strings.ReplaceAll(sampleVP, `"holder": "did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5"`,
			`"holder": "did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv464"`)

		ok, err := vcWalletClient.Verify(wallet.WithRawPresentationToVerify([]byte(tamperedVP)))
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid signature")
		require.False(t, ok)
	})
}

func TestWallet_Derive(t *testing.T) {
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

	customCrypto, err := tinkcrypto.New()
	require.NoError(t, err)

	mockctx.CryptoValue = customCrypto

	// create profile
	err = CreateProfile(sampleUserID, mockctx, wallet.WithPassphrase(samplePassPhrase))
	require.NoError(t, err)

	// prepare frame
	var frameDoc map[string]interface{}

	require.NoError(t, json.Unmarshal([]byte(sampleFrame), &frameDoc))

	t.Run("Test derive a credential from wallet - success", func(t *testing.T) {
		walletInstance, err := New(sampleUserID, mockctx, wallet.WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, walletInstance)

		// save BBS VC in store
		require.NoError(t, walletInstance.Add(wallet.Credential, []byte(sampleBBSVC)))

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
		vc, err := walletInstance.Derive(wallet.FromStoredCredential("http://example.edu/credentials/1872"),
			&wallet.DeriveOptions{
				Nonce: sampleNonce,
				Frame: frameDoc,
			})
		require.NoError(t, err)
		require.NotEmpty(t, vc)
		verifyBBSProof(vc.Proofs)

		// derive raw credential
		vc, err = walletInstance.Derive(wallet.FromRawCredential([]byte(sampleBBSVC)), &wallet.DeriveOptions{
			Nonce: sampleNonce,
			Frame: frameDoc,
		})
		require.NoError(t, err)
		require.NotEmpty(t, vc)
		verifyBBSProof(vc.Proofs)

		// derive from credential instance
		pkFetcher := verifiable.WithPublicKeyFetcher(
			verifiable.NewVDRKeyResolver(customVDR).PublicKeyFetcher(),
		)
		credential, err := verifiable.ParseCredential([]byte(sampleBBSVC), pkFetcher)
		require.NoError(t, err)
		vc, err = walletInstance.Derive(wallet.FromCredential(credential), &wallet.DeriveOptions{
			Nonce: sampleNonce,
			Frame: frameDoc,
		})
		require.NoError(t, err)
		require.NotEmpty(t, vc)
		verifyBBSProof(vc.Proofs)
	})

	t.Run("Test derive credential failures", func(t *testing.T) {
		walletInstance, err := New(sampleUserID, mockctx, wallet.WithUnlockByPassphrase(samplePassPhrase))
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		// invalid request
		vc, err := walletInstance.Derive(wallet.FromStoredCredential(""), &wallet.DeriveOptions{})
		require.Empty(t, vc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid request to derive credential")

		// credential not found in store
		vc, err = walletInstance.Derive(wallet.FromStoredCredential("invalid-id"), &wallet.DeriveOptions{})
		require.Empty(t, vc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "data not found")

		// invalid credential in store
		require.NoError(t, walletInstance.Add(wallet.Credential, []byte(sampleInvalidDIDContent)))

		vc, err = walletInstance.Derive(wallet.FromStoredCredential("did:example:sampleInvalidDIDContent"),
			&wallet.DeriveOptions{})
		require.Empty(t, vc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "credential type of unknown structure")

		// invalid raw credential
		vc, err = walletInstance.Derive(wallet.FromRawCredential([]byte(sampleInvalidDIDContent)), &wallet.DeriveOptions{})
		require.Empty(t, vc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "credential type of unknown structure")

		// try deriving wrong proof type - no BbsBlsSignature2020 proof present
		vc, err = walletInstance.Derive(wallet.FromRawCredential([]byte(sampleUDCVCWithProof)), &wallet.DeriveOptions{
			Frame: frameDoc,
		})
		require.Empty(t, vc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no BbsBlsSignature2020 proof present")
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
