/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/subtle/random"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms/internal/keywrapper"
	mocksecretlock "github.com/hyperledger/aries-framework-go/pkg/mock/secretlock"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local/masterlock/hkdf"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/pkg/store/wrapper/prefix"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const testMasterKeyURI = keywrapper.LocalKeyURIPrefix + "test/key/uri"

func TestNewKMS_Failure(t *testing.T) {
	t.Run("test New() fail without masterkeyURI", func(t *testing.T) {
		kmsStorage, err := New("", &mockProvider{
			storage: mockstorage.NewMockStoreProvider(),
			secretLock: &mocksecretlock.MockSecretLock{
				ValEncrypt: "",
				ValDecrypt: "",
			},
		})
		require.Error(t, err)
		require.Empty(t, kmsStorage)
	})

	t.Run("test New() fail due to error opening store", func(t *testing.T) {
		kmsStorage, err := New(testMasterKeyURI, &mockProvider{
			storage: &mockstorage.MockStoreProvider{
				ErrOpenStoreHandle: fmt.Errorf("failed to create store"),
			},
			secretLock: &mocksecretlock.MockSecretLock{
				ValEncrypt: "",
				ValDecrypt: "",
			},
		})
		require.Error(t, err)
		require.Empty(t, kmsStorage)
	})

	t.Run("test New() error creating new KMS client with bad master key prefix", func(t *testing.T) {
		badKeyURI := "://test/key/uri"

		kmsStorage, err := New(badKeyURI, &mockProvider{
			storage: mockstorage.NewMockStoreProvider(),
			secretLock: &mocksecretlock.MockSecretLock{
				ValEncrypt: "",
				ValDecrypt: "",
			},
		})
		require.Error(t, err)
		require.Empty(t, kmsStorage)
	})
}

func TestCreateGetRotateKey_Failure(t *testing.T) {
	t.Run("test failure Create() and Rotate() calls with bad key template string", func(t *testing.T) {
		kmsStorage, err := New(testMasterKeyURI, &mockProvider{
			storage: mockstorage.NewMockStoreProvider(),
			secretLock: &mocksecretlock.MockSecretLock{
				ValEncrypt: "",
				ValDecrypt: "",
			},
		})
		require.NoError(t, err)
		require.NotEmpty(t, kmsStorage)

		id, kh, err := kmsStorage.Create("")
		require.Error(t, err)
		require.Empty(t, kh)
		require.Empty(t, id)

		id, kh, err = kmsStorage.Create("unsupported")
		require.Error(t, err)
		require.Empty(t, kh)
		require.Empty(t, id)

		// create a valid key to test Rotate()
		id, kh, err = kmsStorage.Create(kms.AES128GCMType)
		require.NoError(t, err)
		require.NotEmpty(t, kh)
		require.NotEmpty(t, id)

		newID, kh, err := kmsStorage.Rotate("", id)
		require.Error(t, err)
		require.Empty(t, kh)
		require.Empty(t, newID)

		newID, kh, err = kmsStorage.Rotate("unsupported", id)
		require.Error(t, err)
		require.Empty(t, kh)
		require.Empty(t, newID)
	})

	t.Run("test Create() with failure to store key", func(t *testing.T) {
		putDataErr := fmt.Errorf("failed to put data")
		kmsStorage, err := New(testMasterKeyURI, &mockProvider{
			storage: &mockstorage.MockStoreProvider{
				Store: &mockstorage.MockStore{
					ErrPut: putDataErr,
				},
			},
			secretLock: &mocksecretlock.MockSecretLock{
				ValEncrypt: "",
				ValDecrypt: "",
			},
		})
		require.NoError(t, err)

		id, kh, err := kmsStorage.Create(kms.AES128GCMType)
		require.True(t, errors.Is(err, putDataErr))
		require.Empty(t, kh)
		require.Empty(t, id)
	})

	t.Run("test Create() success to store key but fail to get key from store", func(t *testing.T) {
		storeData := map[string]mockstorage.DBEntry{}
		kmsStorage, err := New(testMasterKeyURI, &mockProvider{
			storage: &mockstorage.MockStoreProvider{
				Store: &mockstorage.MockStore{
					Store: storeData,
				},
			},
			secretLock: &mocksecretlock.MockSecretLock{
				ValEncrypt: "",
				ValDecrypt: "",
			},
		})
		require.NoError(t, err)

		id, kh, err := kmsStorage.Create(kms.AES128GCMType)
		require.NoError(t, err)
		require.NotEmpty(t, kh)
		require.NotEmpty(t, id)

		// new create a new client with a store throwing an error during a Get()
		kmsStorage3, err := New(testMasterKeyURI, &mockProvider{
			storage: &mockstorage.MockStoreProvider{
				Store: &mockstorage.MockStore{
					ErrGet: fmt.Errorf("failed to get data"),
					Store:  storeData,
				},
			},
			secretLock: &mocksecretlock.MockSecretLock{
				ValEncrypt: "",
				ValDecrypt: "",
			},
		})
		require.NoError(t, err)

		kh, err = kmsStorage3.Get(id)
		require.Contains(t, err.Error(), "failed to get data")
		require.Empty(t, kh)

		newID, kh, err := kmsStorage3.Rotate(kms.AES128GCMType, id)
		require.Contains(t, err.Error(), "failed to get data")
		require.Empty(t, kh)
		require.Empty(t, newID)
	})

	t.Run("create valid key but not available for Export", func(t *testing.T) {
		storeData := map[string]mockstorage.DBEntry{}
		kmsStorage, err := New(testMasterKeyURI, &mockProvider{
			storage: &mockstorage.MockStoreProvider{
				Store: &mockstorage.MockStore{
					Store: storeData,
				},
			},
			secretLock: &noop.NoLock{},
		})
		require.NoError(t, err)

		kid, _, err := kmsStorage.Create(kms.AES128GCM)
		require.NoError(t, err)

		_, err = kmsStorage.ExportPubKeyBytes(kid)
		require.EqualError(t, err, "exportPubKeyBytes: failed to export marshalled key: exportPubKeyBytes: "+
			"failed to get public keyset handle: keyset.Handle: keyset.Handle: keyset contains a non-private key")
	})

	t.Run("create And Export invalid key", func(t *testing.T) {
		storeData := map[string]mockstorage.DBEntry{}
		kmsStorage, err := New(testMasterKeyURI, &mockProvider{
			storage: &mockstorage.MockStoreProvider{
				Store: &mockstorage.MockStore{
					Store: storeData,
				},
			},
			secretLock: &noop.NoLock{},
		})
		require.NoError(t, err)

		// try to create and export an unsupported key type.
		_, _, err = kmsStorage.CreateAndExportPubKeyBytes("unsupported")
		require.EqualError(t, err, "createAndExportPubKeyBytes: failed to create new key: create: failed to "+
			"getKeyTemplate: getKeyTemplate: key type 'unsupported' unrecognized")

		// try to create and export a supported key type, but does not support export.
		_, _, err = kmsStorage.CreateAndExportPubKeyBytes(kms.HMACSHA256Tag256)
		require.EqualError(t, err, "createAndExportPubKeyBytes: failed to export new public key bytes: "+
			"exportPubKeyBytes: failed to export marshalled key: exportPubKeyBytes: failed to get public keyset "+
			"handle: keyset.Handle: keyset.Handle: keyset contains a non-private key")
	})
}

func TestEncryptRotateDecrypt_Success(t *testing.T) {
	// create a real (not mocked) master key and secret lock to test the KMS end to end
	sl := createMasterKeyAndSecretLock(t)

	storeDB := make(map[string]mockstorage.DBEntry)
	// test New()
	kmsService, err := New(testMasterKeyURI, &mockProvider{
		storage: mockstorage.NewCustomMockStoreProvider(
			&mockstorage.MockStore{
				Store: storeDB,
			}),
		secretLock: sl,
	})
	require.NoError(t, err)
	require.NotEmpty(t, kmsService)

	keyTemplates := []kms.KeyType{
		kms.AES128GCMType,
		kms.AES256GCMNoPrefixType,
		kms.AES256GCMType,
		kms.ChaCha20Poly1305,
		kms.XChaCha20Poly1305,
	}

	for _, v := range keyTemplates {
		// test Create() a new key
		keyID, keyHandle, e := kmsService.Create(v)
		require.NoError(t, e, "failed on template %v", v)
		require.NotEmpty(t, keyHandle)
		require.NotEmpty(t, keyID)

		c := tinkcrypto.Crypto{}
		msg := []byte("Test Rotation Message")
		aad := []byte("some additional data")

		cipherText, nonce, e := c.Encrypt(msg, aad, keyHandle)
		require.NoError(t, e)

		newKeyID, rotatedKeyHandle, e := kmsService.Rotate(v, keyID)
		require.NoError(t, e)
		require.NotEmpty(t, rotatedKeyHandle)
		require.NotEqual(t, newKeyID, keyID)

		decryptedMsg, e := c.Decrypt(cipherText, aad, nonce, rotatedKeyHandle)
		require.NoError(t, e)
		require.Equal(t, msg, decryptedMsg)
	}
}

func TestLocalKMS_Success(t *testing.T) {
	// create a real (not mocked) master key and secret lock to test the KMS end to end
	sl := createMasterKeyAndSecretLock(t)

	storeDB := make(map[string]mockstorage.DBEntry)
	// test New()
	kmsService, err := New(testMasterKeyURI, &mockProvider{
		storage: mockstorage.NewCustomMockStoreProvider(
			&mockstorage.MockStore{
				Store: storeDB,
			}),
		secretLock: sl,
	})
	require.NoError(t, err)
	require.NotEmpty(t, kmsService)

	keyTemplates := []kms.KeyType{
		kms.AES128GCMType,
		kms.AES256GCMNoPrefixType,
		kms.AES256GCMType,
		kms.ChaCha20Poly1305Type,
		kms.XChaCha20Poly1305Type,
		kms.ECDSAP256TypeDER,
		kms.ECDSAP384TypeDER,
		kms.ECDSAP521TypeDER,
		kms.ECDSAP256TypeIEEEP1363,
		kms.ECDSAP384TypeIEEEP1363,
		kms.ECDSAP521TypeIEEEP1363,
		kms.ED25519Type,
		kms.NISTP256ECDHKWType,
		kms.NISTP384ECDHKWType,
		kms.NISTP521ECDHKWType,
		kms.X25519ECDHKWType,
		kms.BLS12381G2Type,
	}

	for _, v := range keyTemplates {
		// test Create() a new key
		keyID, newKeyHandle, e := kmsService.Create(v)
		require.NoError(t, e, "failed on template %v", v)
		require.NotEmpty(t, newKeyHandle)
		require.NotEmpty(t, keyID)

		ks, ok := storeDB[prefix.StorageKIDPrefix+keyID]
		require.True(t, ok)
		require.NotEmpty(t, ks)

		// get key handle primitives
		newKHPrimitives, e := newKeyHandle.(*keyset.Handle).Primitives()
		require.NoError(t, e)
		require.NotEmpty(t, newKHPrimitives)

		// test Get() an existing keyhandle (it should match newKeyHandle above)
		loadedKeyHandle, e := kmsService.Get(keyID)
		require.NoError(t, e)
		require.NotEmpty(t, loadedKeyHandle)

		readKHPrimitives, e := loadedKeyHandle.(*keyset.Handle).Primitives()
		require.NoError(t, e)
		require.NotEmpty(t, newKHPrimitives)

		require.Equal(t, len(newKHPrimitives.Entries), len(readKHPrimitives.Entries))

		// finally test Rotate()
		// with unsupported key type - should fail
		newKeyID, rotatedKeyHandle, e := kmsService.Rotate("unsupported", keyID)
		require.Error(t, e)
		require.Empty(t, rotatedKeyHandle)
		require.Empty(t, newKeyID)

		// with valid key type - should succeed
		newKeyID, rotatedKeyHandle, e = kmsService.Rotate(v, keyID)
		require.NoError(t, e)
		require.NotEmpty(t, rotatedKeyHandle)
		require.NotEqual(t, newKeyID, keyID)

		rotatedKHPrimitives, e := loadedKeyHandle.(*keyset.Handle).Primitives()
		require.NoError(t, e)
		require.NotEmpty(t, newKHPrimitives)
		require.Equal(t, len(newKHPrimitives.Entries), len(rotatedKHPrimitives.Entries))
		require.Equal(t, len(readKHPrimitives.Entries), len(rotatedKHPrimitives.Entries))

		if strings.Contains(string(v), "ECDSA") || v == kms.ED25519Type || v == kms.BLS12381G2Type {
			pubKeyBytes, e := kmsService.ExportPubKeyBytes(keyID)
			require.Errorf(t, e, "KeyID has been rotated. An error must be returned")
			require.Empty(t, pubKeyBytes)

			pubKeyBytes, e = kmsService.ExportPubKeyBytes(newKeyID)
			require.NoError(t, e)
			require.NotEmpty(t, pubKeyBytes)

			kh, e := kmsService.PubKeyBytesToHandle(pubKeyBytes, v)
			require.NoError(t, e)
			require.NotEmpty(t, kh)

			// test create and export key in one function
			_, _, e = kmsService.CreateAndExportPubKeyBytes(v)
			require.NoError(t, e)
		}
	}
}

func TestLocalKMS_ImportPrivateKey(t *testing.T) {
	// create a real (not mocked) master key and secret lock to test the KMS end to end
	sl := createMasterKeyAndSecretLock(t)

	storeDB := make(map[string]mockstorage.DBEntry)
	// test New()
	kmsService, e := New(testMasterKeyURI, &mockProvider{
		storage: mockstorage.NewCustomMockStoreProvider(
			&mockstorage.MockStore{
				Store: storeDB,
			}),
		secretLock: sl,
	})
	require.NoError(t, e)
	require.NotEmpty(t, kmsService)

	// test import with nil key
	_, _, err := kmsService.ImportPrivateKey(nil, kms.ECDSAP256TypeDER)
	require.EqualError(t, err, "import private key does not support this key type or key is public")

	flagTests := []struct {
		tcName  string
		keyType kms.KeyType
		curve   elliptic.Curve
		setID   bool
		ksID    string
	}{
		{
			tcName:  "import private key using ECDSAP256DER type",
			keyType: kms.ECDSAP256TypeDER,
			curve:   elliptic.P256(),
		},
		{
			tcName:  "import private key using ECDSAP384TypeDER type",
			keyType: kms.ECDSAP384TypeDER,
			curve:   elliptic.P384(),
		},
		{
			tcName:  "import private key using ECDSAP521TypeDER type",
			keyType: kms.ECDSAP521TypeDER,
			curve:   elliptic.P521(),
		},
		{
			tcName:  "import private key using ECDSAP256TypeIEEEP1363 type",
			keyType: kms.ECDSAP256TypeIEEEP1363,
			curve:   elliptic.P256(),
		},
		{
			tcName:  "import private key using ECDSAP384TypeIEEEP1363 type",
			keyType: kms.ECDSAP384TypeIEEEP1363,
			curve:   elliptic.P384(),
		},
		{
			tcName:  "import private key using ECDSAP521TypeIEEEP1363 type",
			keyType: kms.ECDSAP521TypeIEEEP1363,
			curve:   elliptic.P521(),
		},
		{
			tcName:  "import private key using ED25519Type type",
			keyType: kms.ED25519Type,
		},
		{
			tcName:  "import private key using BLS12381G2Type type",
			keyType: kms.BLS12381G2Type,
		},
		{
			tcName:  "import private key using ECDSAP256DER type and a set empty KeyID",
			keyType: kms.ECDSAP256TypeDER,
			curve:   elliptic.P256(),
			setID:   true,
			ksID:    "",
		},
		{
			tcName:  "import private key using ECDSAP256DER type and a set non empty KeyID",
			keyType: kms.ECDSAP256TypeDER,
			curve:   elliptic.P256(),
			setID:   true,
			ksID: base64.RawURLEncoding.EncodeToString(random.GetRandomBytes(
				uint32(base64.RawURLEncoding.DecodedLen(maxKeyIDLen)))),
		},
		{
			tcName:  "import private key using ECDSAP256DER type and a set non KeyID larger than maxKeyIDLen",
			keyType: kms.ECDSAP256TypeDER,
			curve:   elliptic.P256(),
			setID:   true,
			ksID: base64.RawURLEncoding.EncodeToString(random.GetRandomBytes(
				uint32(base64.RawURLEncoding.DecodedLen(30)))),
		},
	}

	for _, tc := range flagTests {
		tt := tc
		t.Run(tt.tcName, func(t *testing.T) {
			if tt.keyType == kms.ED25519Type {
				pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)

				ksID, _, err := kmsService.ImportPrivateKey(privKey, tt.keyType)
				require.NoError(t, err)

				pubKeyBytes, err := kmsService.ExportPubKeyBytes(ksID)
				require.NoError(t, err)
				require.EqualValues(t, pubKey, pubKeyBytes)
				return
			}

			if tt.keyType == kms.BLS12381G2Type {
				seed := make([]byte, 32)

				_, err := rand.Read(seed)
				require.NoError(t, err)

				pubKey, privKey, err := bbs12381g2pub.GenerateKeyPair(sha256.New, seed)
				require.NoError(t, err)

				ksID, _, err := kmsService.ImportPrivateKey(privKey, tt.keyType)
				require.NoError(t, err)

				pubKeyBytes, err := kmsService.ExportPubKeyBytes(ksID)
				require.NoError(t, err)

				expectedPubKeyBytes, err := pubKey.Marshal()
				require.NoError(t, err)
				require.EqualValues(t, expectedPubKeyBytes, pubKeyBytes)
				return
			}

			privKey, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			require.NoError(t, err)

			var ksID string

			// test ImportPrivateKey
			if tt.setID {
				// with set keyset ID
				ksID, _, err = kmsService.ImportPrivateKey(privKey, tt.keyType, kms.WithKeyID(tt.ksID))
				require.NoError(t, err)
				// calling ImportPrivatekeyt and WithKeyID("") will ignore the set KeyID and generate a new one
				if tt.ksID != "" {
					require.Equal(t, tt.ksID, ksID)
				}
			} else {
				// generate a new keyset ID
				ksID, _, err = kmsService.ImportPrivateKey(privKey, tt.keyType)
				require.NoError(t, err)
			}

			// export marshaled public key to verify it against the original public key (marshalled)
			pubKeyBytes, err := kmsService.ExportPubKeyBytes(ksID)
			require.NoError(t, err)

			switch tt.keyType {
			case kms.ECDSAP256TypeDER, kms.ECDSAP384TypeDER, kms.ECDSAP521TypeDER:
				pubKey, err := x509.MarshalPKIXPublicKey(privKey.Public())
				require.NoError(t, err)
				require.EqualValues(t, pubKey, pubKeyBytes)
			case kms.ECDSAP256TypeIEEEP1363, kms.ECDSAP384TypeIEEEP1363, kms.ECDSAP521TypeIEEEP1363:
				pubKey := elliptic.Marshal(tt.curve, privKey.X, privKey.Y)
				require.EqualValues(t, pubKey, pubKeyBytes)
			}
		})
	}
}

func TestLocalKMS_getKeyTemplate(t *testing.T) {
	keyTemplate, err := getKeyTemplate(kms.HMACSHA256Tag256Type)
	require.NoError(t, err)
	require.NotNil(t, keyTemplate)
	require.Equal(t, "type.googleapis.com/google.crypto.tink.HmacKey", keyTemplate.TypeUrl)
}

func createMasterKeyAndSecretLock(t *testing.T) secretlock.Service {
	t.Helper()

	masterKeyFilePath := "masterKey_file.txt"
	tmpfile, err := ioutil.TempFile("", masterKeyFilePath)
	require.NoError(t, err)

	defer func() {
		// close file
		require.NoError(t, tmpfile.Close())
		// clean up file
		require.NoError(t, os.Remove(tmpfile.Name()))
	}()

	masterKeyContent := random.GetRandomBytes(uint32(32))
	require.NotEmpty(t, masterKeyContent)

	// first create a master lock to use in our secret lock and encrypt the master key
	passphrase := "secretPassphrase"
	keySize := sha256.Size
	// salt is optional, it can be nil
	salt := make([]byte, keySize)
	_, err = rand.Read(salt)
	require.NoError(t, err)

	masterLocker, err := hkdf.NewMasterLock(passphrase, sha256.New, salt)
	require.NoError(t, err)
	require.NotEmpty(t, masterLocker)

	// now encrypt masterKeyContent
	masterLockEnc, err := masterLocker.Encrypt("", &secretlock.EncryptRequest{
		Plaintext: string(masterKeyContent),
	})
	require.NoError(t, err)
	require.NotEmpty(t, masterLockEnc)

	// and write it to tmpfile
	n, err := tmpfile.Write([]byte(masterLockEnc.Ciphertext))
	require.NoError(t, err)
	require.Equal(t, len(masterLockEnc.Ciphertext), n)

	// now get a reader from path
	r, err := local.MasterKeyFromPath(tmpfile.Name())
	require.NoError(t, err)
	require.NotEmpty(t, r)

	// finally create lock service with the master lock created above to encrypt decrypt keys using
	// a protected (encrypted) master key
	s, err := local.NewService(r, masterLocker)
	require.NoError(t, err)
	require.NotEmpty(t, s)

	return s
}

// mockProvider mocks a provider for KMS storage.
type mockProvider struct {
	storage    *mockstorage.MockStoreProvider
	secretLock secretlock.Service
}

func (m *mockProvider) StorageProvider() storage.Provider {
	return m.storage
}

func (m *mockProvider) SecretLock() secretlock.Service {
	return m.secretLock
}
