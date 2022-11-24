/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	kmsapi "github.com/hyperledger/aries-framework-go/pkg/kms"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local/masterlock/pbkdf2"
)

const (
	samplePassPhrase    = "fakepassphrase"
	sampleRemoteKMSAuth = "sample-auth-token"
	sampleKeyMgrErr     = "sample-keymgr-err"
)

func TestKeyManagerStore(t *testing.T) {
	t.Run("test key manager instance", func(t *testing.T) {
		require.NotEmpty(t, keyManager())
		require.Equal(t, keyManager(), keyManager())
	})
}

func TestKeyManager(t *testing.T) {
	t.Run("create key manager for localkms - with passphrase", func(t *testing.T) {
		sampleUser := uuid.New().String()
		masterLock, err := getDefaultSecretLock(samplePassPhrase)
		require.NoError(t, err)

		masterLockCipherText, err := createMasterLock(masterLock)
		require.NoError(t, err)
		require.NotEmpty(t, masterLockCipherText)

		profileInfo := &profile{
			User:             sampleUser,
			MasterLockCipher: masterLockCipherText,
		}

		kmsStore, err := kmsapi.NewAriesProviderWrapper(mockstorage.NewMockStoreProvider())
		require.NoError(t, err)

		kmgr, err := keyManager().createKeyManager(profileInfo, kmsStore,
			&unlockOpts{passphrase: samplePassPhrase})
		require.NoError(t, err)
		require.NotEmpty(t, kmgr)
	})

	t.Run("create key manager for localkms - with secret lock service", func(t *testing.T) {
		sampleUser := uuid.New().String()
		masterLock, err := pbkdf2.NewMasterLock(samplePassPhrase, sha256.New, 0, nil)
		require.NoError(t, err)

		masterLockCipherText, err := createMasterLock(masterLock)
		require.NoError(t, err)
		require.NotEmpty(t, masterLockCipherText)

		profileInfo := &profile{
			User:             sampleUser,
			MasterLockCipher: masterLockCipherText,
		}

		kmsStore, err := kmsapi.NewAriesProviderWrapper(mockstorage.NewMockStoreProvider())
		require.NoError(t, err)

		kmgr, err := keyManager().createKeyManager(profileInfo, kmsStore,
			&unlockOpts{secretLockSvc: masterLock})
		require.NoError(t, err)
		require.NotEmpty(t, kmgr)
	})

	t.Run("create key manager for localkms - passphrase missmatch", func(t *testing.T) {
		sampleUser := uuid.New().String()
		masterLock, err := getDefaultSecretLock(samplePassPhrase)
		require.NoError(t, err)

		masterLockCipherText, err := createMasterLock(masterLock)
		require.NoError(t, err)
		require.NotEmpty(t, masterLockCipherText)

		profileInfo := &profile{
			User:             sampleUser,
			MasterLockCipher: masterLockCipherText,
		}

		kmsStore, err := kmsapi.NewAriesProviderWrapper(mockstorage.NewMockStoreProvider())
		require.NoError(t, err)

		// use wrong passphrase
		kmgr, err := keyManager().createKeyManager(profileInfo, kmsStore,
			&unlockOpts{passphrase: samplePassPhrase + "wrong"})
		require.Empty(t, kmgr)
		require.Error(t, err)
		require.Contains(t, err.Error(), "message authentication failed")
	})

	t.Run("create key manager for localkms - secret lock service missmatch", func(t *testing.T) {
		sampleUser := uuid.New().String()
		masterLock, err := pbkdf2.NewMasterLock(samplePassPhrase, sha256.New, 0, nil)
		require.NoError(t, err)

		masterLockCipherText, err := createMasterLock(masterLock)
		require.NoError(t, err)
		require.NotEmpty(t, masterLockCipherText)

		profileInfo := &profile{
			User:             sampleUser,
			MasterLockCipher: masterLockCipherText,
		}

		// use wrong secret lock service
		masterLockBad, err := pbkdf2.NewMasterLock(samplePassPhrase+"wrong", sha256.New, 0, nil)
		require.NoError(t, err)

		kmsStore, err := kmsapi.NewAriesProviderWrapper(mockstorage.NewMockStoreProvider())
		require.NoError(t, err)

		kmgr, err := keyManager().createKeyManager(profileInfo, kmsStore,
			&unlockOpts{secretLockSvc: masterLockBad})
		require.Empty(t, kmgr)
		require.Error(t, err)
		require.Contains(t, err.Error(), "message authentication failed")
	})

	t.Run("create key manager for remotekms", func(t *testing.T) {
		sampleUser := uuid.New().String()
		profileInfo := &profile{
			User:         sampleUser,
			KeyServerURL: sampleKeyServerURL,
		}

		kmsStore, err := kmsapi.NewAriesProviderWrapper(mockstorage.NewMockStoreProvider())
		require.NoError(t, err)

		kmgr, err := keyManager().createKeyManager(profileInfo, kmsStore,
			&unlockOpts{authToken: sampleRemoteKMSAuth})
		require.NoError(t, err)
		require.NotEmpty(t, kmgr)

		_, _, err = kmgr.Create(kmsapi.ED25519Type)
		require.Error(t, err)
	})

	t.Run("create key manager for failure - invalid profile", func(t *testing.T) {
		profileInfo := &profile{
			User: uuid.New().String(),
		}

		kmsStore, err := kmsapi.NewAriesProviderWrapper(mockstorage.NewMockStoreProvider())
		require.NoError(t, err)

		kmgr, err := keyManager().createKeyManager(profileInfo, kmsStore,
			&unlockOpts{authToken: sampleRemoteKMSAuth})
		require.Empty(t, kmgr)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid wallet profile")
	})
}

func TestImportKeyJWK(t *testing.T) {
	sampleUser := uuid.New().String()
	masterLock, err := getDefaultSecretLock(samplePassPhrase)
	require.NoError(t, err)

	masterLockCipherText, err := createMasterLock(masterLock)
	require.NoError(t, err)
	require.NotEmpty(t, masterLockCipherText)

	profileInfo := &profile{
		User:             sampleUser,
		MasterLockCipher: masterLockCipherText,
	}

	kmsStore, err := kmsapi.NewAriesProviderWrapper(mockstorage.NewMockStoreProvider())
	require.NoError(t, err)

	kmgr, err := keyManager().createKeyManager(profileInfo, kmsStore,
		&unlockOpts{passphrase: samplePassPhrase})
	require.NoError(t, err)
	require.NotEmpty(t, kmgr)

	tkn, err := sessionManager().createSession(uuid.New().String(), kmgr, 0)
	require.NoError(t, err)

	t.Run("test successful jwk key imports", func(t *testing.T) {
		tests := []struct {
			name      string
			sampleJWK []byte
			ID        string
			error     string
		}{
			{
				name: "import Ed25519",
				sampleJWK: []byte(`{
							"kty": "OKP",
							"d":"Dq5t2WS3OMzcpkh8AyVxJs5r9v4L39ocIz9CpUOqM40",
							"crv": "Ed25519",
							"x": "ODaPFurJgFcoVCUYEmgOJpWOtPlOYbHSugasscKWqDM",
							"kid":"z6MkiEh8RQL83nkPo8ehDeE7"
				}`),
				ID: "did:example:123#z6MkiEh8RQL83nkPo8ehDeE7",
			},
			{
				name: "import Ed25519, use document id for missing kid",
				sampleJWK: []byte(`{
							"kty": "OKP",
							"d":"Dq5t2WS3OMzcpkh8AyVxJs5r9v4L39ocIz9CpUOqM40",
							"crv": "Ed25519",
							"x": "ODaPFurJgFcoVCUYEmgOJpWOtPlOYbHSugasscKWqDM"
				}`),
				ID: "did:example:123#z6MkiEh8RQL83nkPo8ehDeE8",
			},
			{
				name: "import P-256",
				sampleJWK: []byte(`{
                        	"kty": "EC",
                        	"kid": "z6MkiEh8RQL83nkPo8ehDeE9",
                        	"crv": "P-256",
                        	"alg": "EdDSA",
                        	"x": "POTofegIPtEJ4ctuYJ9qY1GZepxAqEcx-RjoYJghW5U",
                        	"y": "C0STSwXZ-krV5CYdqU4yKh7NiKKjwmAkIMXfeyo3Irw",
                        	"d": "GeJ0tppbkfJl8Jci00L3WBIopiE6p6cnkPdT_l9xKmk"
                    }`),
				ID: "did:example:123#z6MkiEh8RQL83nkPo8ehDeE9",
			},
			{
				name: "import P-384",
				sampleJWK: []byte(`{
      					"kty": "EC",
      					"crv": "P-384",
      					"x": "eQbMauiHc9HuiqXT894gW5XTCrOpeY8cjLXAckfRtdVBLzVHKaiXAAxBFeVrSB75",
      					"y": "YOjxhMkdH9QnNmGCGuGXJrjAtk8CQ1kTmEEi9cg2R9ge-zh8SFT1Xu6awoUjK5Bv",
      					"d": "dXghMAzYZmv46SNRuxmfDIuAlv7XIhvlkPzW3vXsopB1ihWp47tx0hqjZmYO6fJa"
    				}`),
				ID: "did:example:123#z6MkiEh8RQL83nkPo8ehDeE10",
			},
			{
				name: "import Ed25519 failure - invalid jwk",
				sampleJWK: []byte(`{
							"invalid":"test"
				}`),
				ID:    "did:example:123#z6MkiEh8RQL83nkPo8ehDeE7",
				error: " unknown json web key type",
			},
			{
				name: "import secp256k1 failure - unsupported curve",
				sampleJWK: []byte(`{
					"kty": "EC",
      				"crv": "secp256k1",
      				"x": "GBMxavme-AfIVDKqI6WBJ4V5wZItsxJ9muhxPByllHQ",
      				"y": "SChlfVBhTXG_sRGc9ZdFeCYzI3Kbph3ivE12OFVk4jo",
      				"d": "m5N7gTItgWz6udWjuqzJsqX-vksUnxJrNjD5OilScBc"
    				}`),
				ID:    "did:example:123#z6MkiEh8RQL83nkPo8ehDeE7",
				error: "unsupported Key type secp256k1",
			},
			{
				name: "import Ed25519 failure - incorrect key type",
				sampleJWK: []byte(`{
				    "kty": "OKP",
        			"crv": "Ed25519",
					"x": "VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ"
      				}`),
				ID:    "did:example:123#z6MkiEh8RQL83nkPo8ehDeE7",
				error: "mport private key does not support this key type or key is public",
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.name, func(t *testing.T) {
				if tc.error != "" {
					err := importKeyJWK(tkn, &keyContent{PrivateKeyJwk: tc.sampleJWK, ID: tc.ID})
					require.Error(t, err)
					require.Contains(t, err.Error(), tc.error)

					return
				}

				err := importKeyJWK(tkn, &keyContent{PrivateKeyJwk: tc.sampleJWK, ID: tc.ID})
				require.NoError(t, err)

				handle, err := kmgr.Get(getKID(tc.ID))
				require.NoError(t, err)
				require.NotEmpty(t, handle)
			})
		}
	})

	t.Run("test key ID already exists", func(t *testing.T) {
		err := importKeyJWK(tkn, &keyContent{PrivateKeyJwk: []byte(`{
							"kty": "OKP",
							"d":"Dq5t2WS3OMzcpkh8AyVxJs5r9v4L39ocIz9CpUOqM40",
							"crv": "Ed25519",
							"x": "ODaPFurJgFcoVCUYEmgOJpWOtPlOYbHSugasscKWqDM",
							"kid":"z6MkiEh8RQL83nkPo8ehDeX7"
				}`), ID: "did:example:123#z6MkiEh8RQL83nkPo8ehDeX7"})
		require.NoError(t, err)

		// import different key with same key ID
		err = importKeyJWK(tkn, &keyContent{PrivateKeyJwk: []byte(`{
      						"kty": "EC",
      						"crv": "P-384",
      						"x": "eQbMauiHc9HuiqXT894gW5XTCrOpeY8cjLXAckfRtdVBLzVHKaiXAAxBFeVrSB75",
      						"y": "YOjxhMkdH9QnNmGCGuGXJrjAtk8CQ1kTmEEi9cg2R9ge-zh8SFT1Xu6awoUjK5Bv",
      						"d": "dXghMAzYZmv46SNRuxmfDIuAlv7XIhvlkPzW3vXsopB1ihWp47tx0hqjZmYO6fJa",
							"kid": "z6MkiEh8RQL83nkPo8ehDeX7"
    					}`), ID: "did:example:123#z6MkiEh8RQL83nkPo8ehDeX8"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "requested ID 'z6MkiEh8RQL83nkPo8ehDeX7' already exists")

		// import different key with same content ID (missing kid)
		err = importKeyJWK(tkn, &keyContent{PrivateKeyJwk: []byte(`{
      						"kty": "EC",
      						"crv": "P-384",
      						"x": "eQbMauiHc9HuiqXT894gW5XTCrOpeY8cjLXAckfRtdVBLzVHKaiXAAxBFeVrSB75",
      						"y": "YOjxhMkdH9QnNmGCGuGXJrjAtk8CQ1kTmEEi9cg2R9ge-zh8SFT1Xu6awoUjK5Bv",
      						"d": "dXghMAzYZmv46SNRuxmfDIuAlv7XIhvlkPzW3vXsopB1ihWp47tx0hqjZmYO6fJa"
    					}`), ID: "did:example:123#z6MkiEh8RQL83nkPo8ehDeX7"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "requested ID 'z6MkiEh8RQL83nkPo8ehDeX7' already exists")

		// no KID
		err = importKeyJWK(tkn, &keyContent{PrivateKeyJwk: []byte(`{
							"kty": "OKP",
							"d":"Dq5t2WS3OMzcpkh8AyVxJs5r9v4L39ocIz9CpUOqM40",
							"crv": "Ed25519",
							"x": "ODaPFurJgFcoVCUYEmgOJpWOtPlOYbHSugasscKWqDM"
				}`)})
		require.NoError(t, err)
	})

	t.Run("test key manager errors", func(t *testing.T) {
		err := importKeyJWK(tkn+"invalid", &keyContent{PrivateKeyJwk: []byte(`{
							"kty": "OKP",
							"d":"Dq5t2WS3OMzcpkh8AyVxJs5r9v4L39ocIz9CpUOqM40",
							"crv": "Ed25519",
							"x": "ODaPFurJgFcoVCUYEmgOJpWOtPlOYbHSugasscKWqDM",
							"kid":"z6MkiEh8RQL83nkPo8ehDeX7"
				}`), ID: "did:example:123#z6MkiEh8RQL83nkPo8ehDeX7"})
		require.True(t, errors.Is(err, ErrWalletLocked))
	})
}

func TestImportKeyBase58(t *testing.T) {
	sampleUser := uuid.New().String()
	masterLock, e := getDefaultSecretLock(samplePassPhrase)
	require.NoError(t, e)

	masterLockCipherText, e := createMasterLock(masterLock)
	require.NoError(t, e)
	require.NotEmpty(t, masterLockCipherText)

	profileInfo := &profile{
		User:             sampleUser,
		MasterLockCipher: masterLockCipherText,
	}

	kmsStore, err := kmsapi.NewAriesProviderWrapper(mockstorage.NewMockStoreProvider())
	require.NoError(t, err)

	kmgr, e := keyManager().createKeyManager(profileInfo, kmsStore,
		&unlockOpts{passphrase: samplePassPhrase})
	require.NoError(t, e)
	require.NotEmpty(t, kmgr)

	tkn, e := sessionManager().createSession(uuid.New().String(), kmgr, 0)
	require.NoError(t, e)
	require.NotEmpty(t, tkn)

	t.Run("test successful base58 key imports", func(t *testing.T) {
		tests := []struct {
			name      string
			keyBase58 string
			keyType   string
			ID        string
			error     string
		}{
			{
				name:      "import Ed25519VerificationKey2018",
				keyBase58: "zJRjGFZydU5DBdS2p5qbiUzDFAxbXTkjiDuGPksMBbY5TNyEsGfK4a4WGKjBCh1zeNryeuKtPotp8W1ESnwP71y",
				keyType:   "Ed25519VerificationKey2018",
				ID:        "did:example:123#z6MkiEh8RQL83nkPo8ehDeE1",
			},
			{
				name:      "import Bls12381G1Key2020",
				keyBase58: "6gsgGpdx7p1nYoKJ4b5fKt1xEomWdnemg9nJFX6mqNCh",
				keyType:   "Bls12381G1Key2020",
				ID:        "did:example:123#z6MkiEh8RQL83nkPo8ehDeE2",
			},
			{
				name:      "import Ed25519VerificationKey2018 failure",
				keyBase58: "6gsgGpdx7p1nYoKJ4b5fKt1xEomWdnemg9nJFX6mqNCh",
				keyType:   "GpgVerificationKey2020",
				ID:        "did:example:123#z6MkiEh8RQL83nkPo8ehDeE3",
				error:     "only Ed25519VerificationKey2018 &  Bls12381G1Key2020 are supported in base58 format",
			},
			{
				name:      "import Bls12381G1Key2020",
				keyBase58: "6gsgGpdx7p1nYossKJ4b5fKt1xEomWdnemg9nJFX6mqNCh",
				keyType:   "Bls12381G1Key2020",
				ID:        "did:example:123#z6MkiEh8RQL83nkPo8ehDeE2",
				error:     "invalid size of private key",
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.name, func(t *testing.T) {
				if tc.error != "" {
					err := importKeyBase58(tkn, &keyContent{
						ID:               tc.ID,
						PrivateKeyBase58: tc.keyBase58,
						KeyType:          tc.keyType,
					})
					require.Error(t, err)
					require.Contains(t, err.Error(), tc.error)

					return
				}

				err := importKeyBase58(tkn, &keyContent{
					ID:               tc.ID,
					PrivateKeyBase58: tc.keyBase58,
					KeyType:          tc.keyType,
				})
				require.NoError(t, err)

				handle, err := kmgr.Get(getKID(tc.ID))
				require.NoError(t, err)
				require.NotEmpty(t, handle)
			})
		}
	})

	t.Run("test key ID already exists", func(t *testing.T) {
		err := importKeyBase58(tkn, &keyContent{
			ID:               "did:example:123#z6MkiEh8RQL83nkPo8ehDeE4",
			PrivateKeyBase58: "zJRjGFZydU5DBdS2p5qbiUzDFAxbXTkjiDuGPksMBbY5TNyEsGfK4a4WGKjBCh1zeNryeuKtPotp8W1ESnwP71y",
			KeyType:          "Ed25519VerificationKey2018",
		})
		require.NoError(t, err)

		err = importKeyBase58(tkn, &keyContent{
			ID:               "did:example:123#z6MkiEh8RQL83nkPo8ehDeE4",
			PrivateKeyBase58: "zJRjGFZydU5DBdS2p5qbiUzDFAxbXTkjiDuGPksMBbY5TNyEsGfK4a4WGKjBCh1zeNryeuKtPotp8W1ESnwP71y",
			KeyType:          "Ed25519VerificationKey2018",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "requested ID 'z6MkiEh8RQL83nkPo8ehDeE4' already exists")
	})

	t.Run("test key manager errors", func(t *testing.T) {
		err := importKeyBase58(tkn+"invalid", &keyContent{
			ID:               "did:example:123#z6MkiEh8RQL83nkPo8ehDeE5",
			PrivateKeyBase58: "zJRjGFZydU5DBdS2p5qbiUzDFAxbXTkjiDuGPksMBbY5TNyEsGfK4a4WGKjBCh1zeNryeuKtPotp8W1ESnwP71y",
			KeyType:          "Ed25519VerificationKey2018",
		})
		require.True(t, errors.Is(err, ErrWalletLocked))
	})

	t.Run("test import errors", func(t *testing.T) {
		sampleErr := errors.New(sampleKeyMgrErr)

		tkn, err := sessionManager().createSession(uuid.New().String(),
			&mockkms.KeyManager{ImportPrivateKeyErr: sampleErr}, 0)
		require.NoError(t, err)
		require.NotEmpty(t, tkn)

		require.NoError(t, err)

		err = importKeyBase58(tkn, &keyContent{
			ID:               "did:example:123#z6MkiEh8RQL83nkPo8ehDeE5",
			PrivateKeyBase58: "zJRjGFZydU5DBdS2p5qbiUzDFAxbXTkjiDuGPksMBbY5TNyEsGfK4a4WGKjBCh1zeNryeuKtPotp8W1ESnwP71y",
			KeyType:          "Ed25519VerificationKey2018",
		})
		require.Error(t, err)
		require.True(t, errors.Is(err, sampleErr))

		err = importKeyBase58(tkn, &keyContent{
			ID:               "did:example:123#z6MkiEh8RQL83nkPo8ehDeE5",
			PrivateKeyBase58: "6gsgGpdx7p1nYoKJ4b5fKt1xEomWdnemg9nJFX6mqNCh",
			KeyType:          "Bls12381G1Key2020",
		})
		require.Error(t, err)
		require.True(t, errors.Is(err, sampleErr))
	})
}

func TestKMSSigner(t *testing.T) {
	token, err := sessionManager().createSession(uuid.New().String(),
		&mockkms.KeyManager{}, 500*time.Millisecond)
	require.NoError(t, err)

	t.Run("kms signer initialization success", func(t *testing.T) {
		signer, err := newKMSSigner(token, &mockcrypto.Crypto{SignErr: errors.New(sampleKeyMgrErr)}, &ProofOptions{
			VerificationMethod: "did:example#123",
		})
		require.NoError(t, err)
		require.NotNil(t, signer)
	})

	t.Run("kms signer initialization errors", func(t *testing.T) {
		// invalid auth
		signer, err := newKMSSigner("invalid", &mockcrypto.Crypto{}, &ProofOptions{})
		require.True(t, errors.Is(err, ErrWalletLocked))
		require.Empty(t, signer)

		// invalid verification method
		signer, err = newKMSSigner(token, &mockcrypto.Crypto{}, &ProofOptions{
			VerificationMethod: "invalid",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid verification method format")
		require.Empty(t, signer)
	})
}
