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
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/subtle/random"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/spi/crypto"
	kmsapi "github.com/hyperledger/aries-framework-go/spi/kms"
	"github.com/hyperledger/aries-framework-go/spi/secretlock"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/kms"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/kms/localkms/internal/keywrapper"
	mocksecretlock "github.com/hyperledger/aries-framework-go/component/kmscrypto/mock/secretlock"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/secretlock/local"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/secretlock/local/masterlock/hkdf"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/secretlock/noop"
)

const testMasterKeyURI = keywrapper.LocalKeyURIPrefix + "test/key/uri"

type inMemoryKMSStore struct {
	keys map[string][]byte
}

func newInMemoryKMSStore() *inMemoryKMSStore {
	return &inMemoryKMSStore{keys: make(map[string][]byte)}
}

func (i *inMemoryKMSStore) Put(keysetID string, key []byte) error {
	i.keys[keysetID] = key

	return nil
}

func (i *inMemoryKMSStore) Get(keysetID string) ([]byte, error) {
	key, found := i.keys[keysetID]
	if !found {
		return nil, kms.ErrKeyNotFound
	}

	return key, nil
}

func (i *inMemoryKMSStore) Delete(keysetID string) error {
	delete(i.keys, keysetID)

	return nil
}

type mockStore struct {
	errPut error
	errGet error
}

func (m *mockStore) Put(string, []byte) error {
	return m.errPut
}

func (m *mockStore) Get(string) ([]byte, error) {
	return nil, m.errGet
}

func (m *mockStore) Delete(string) error {
	return nil
}

func TestNewKMS_Failure(t *testing.T) {
	t.Run("test New() fail without masterkeyURI", func(t *testing.T) {
		kmsStorage, err := New("", &mockProvider{
			storage: newInMemoryKMSStore(),
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
			storage: newInMemoryKMSStore(),
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
			storage: newInMemoryKMSStore(),
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
		id, kh, err = kmsStorage.Create(kmsapi.AES128GCMType)
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
		putErr := fmt.Errorf("failed to put data")
		errGet := kms.ErrKeyNotFound
		mockStore := &mockStore{
			errPut: putErr,
			errGet: errGet,
		}

		kmsStorage, err := New(testMasterKeyURI, &mockProvider{
			storage: mockStore,
			secretLock: &mocksecretlock.MockSecretLock{
				ValEncrypt: "",
				ValDecrypt: "",
			},
		})
		require.NoError(t, err)

		id, kh, err := kmsStorage.Create(kmsapi.AES128GCMType)
		require.True(t, errors.Is(err, putErr))
		require.Empty(t, kh)
		require.Empty(t, id)
	})

	t.Run("test Create() success to store key but fail to get key from store", func(t *testing.T) {
		kmsStorage, err := New(testMasterKeyURI, &mockProvider{
			storage: newInMemoryKMSStore(),
			secretLock: &mocksecretlock.MockSecretLock{
				ValEncrypt: "",
				ValDecrypt: "",
			},
		})
		require.NoError(t, err)

		id, kh, err := kmsStorage.Create(kmsapi.AES128GCMType)
		require.NoError(t, err)
		require.NotEmpty(t, kh)
		require.NotEmpty(t, id)

		// new create a new client with a store throwing an error during a Get()
		errGet := errors.New("failed to get data")
		mockStore := &mockStore{
			errGet: errGet,
		}

		kmsStorage3, err := New(testMasterKeyURI, &mockProvider{
			storage: mockStore,
			secretLock: &mocksecretlock.MockSecretLock{
				ValEncrypt: "",
				ValDecrypt: "",
			},
		})
		require.NoError(t, err)

		kh, err = kmsStorage3.Get(id)
		require.Contains(t, err.Error(), "failed to get data")
		require.Empty(t, kh)

		newID, kh, err := kmsStorage3.Rotate(kmsapi.AES128GCMType, id)
		require.Contains(t, err.Error(), "failed to get data")
		require.Empty(t, kh)
		require.Empty(t, newID)
	})

	t.Run("create valid key but not available for Export", func(t *testing.T) {
		kmsStorage, err := New(testMasterKeyURI, &mockProvider{
			storage:    newInMemoryKMSStore(),
			secretLock: &noop.NoLock{},
		})
		require.NoError(t, err)

		kid, _, err := kmsStorage.Create(kmsapi.AES128GCM)
		require.NoError(t, err)

		_, _, err = kmsStorage.ExportPubKeyBytes(kid)
		require.EqualError(t, err, "exportPubKeyBytes: failed to export marshalled key: exportPubKeyBytes: "+
			"failed to get public keyset handle: keyset.Handle: keyset.Handle: keyset contains a non-private key")
	})

	t.Run("create And Export invalid key", func(t *testing.T) {
		kmsStorage, err := New(testMasterKeyURI, &mockProvider{
			storage:    newInMemoryKMSStore(),
			secretLock: &noop.NoLock{},
		})
		require.NoError(t, err)

		// try to create and export an unsupported key type.
		_, _, err = kmsStorage.CreateAndExportPubKeyBytes("unsupported")
		require.EqualError(t, err, "createAndExportPubKeyBytes: failed to create new key: create: failed to "+
			"getKeyTemplate: getKeyTemplate: key type 'unsupported' unrecognized")

		// try to create and export a supported key type, but does not support export.
		_, _, err = kmsStorage.CreateAndExportPubKeyBytes(kmsapi.HMACSHA256Tag256)
		require.EqualError(t, err, "createAndExportPubKeyBytes: failed to export new public key bytes: "+
			"exportPubKeyBytes: failed to export marshalled key: exportPubKeyBytes: failed to get public keyset "+
			"handle: keyset.Handle: keyset.Handle: keyset contains a non-private key")
	})
}

func TestEncryptRotateDecrypt_Success(t *testing.T) {
	// create a real (not mocked) master key and secret lock to test the KMS end to end
	sl := createMasterKeyAndSecretLock(t)

	// test New()
	kmsService, err := New(testMasterKeyURI, &mockProvider{
		storage:    newInMemoryKMSStore(),
		secretLock: sl,
	})
	require.NoError(t, err)
	require.NotEmpty(t, kmsService)

	keyTemplates := []kmsapi.KeyType{
		kmsapi.AES128GCMType,
		kmsapi.AES256GCMNoPrefixType,
		kmsapi.AES256GCMType,
		kmsapi.ChaCha20Poly1305,
		kmsapi.XChaCha20Poly1305,
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

	keys := make(map[string][]byte)

	testStore := newInMemoryKMSStore()

	testStore.keys = keys

	// test New()
	kmsService, err := New(testMasterKeyURI, &mockProvider{
		storage:    testStore,
		secretLock: sl,
	})
	require.NoError(t, err)
	require.NotEmpty(t, kmsService)

	keyTemplates := []kmsapi.KeyType{
		kmsapi.AES128GCMType,
		kmsapi.AES256GCMNoPrefixType,
		kmsapi.AES256GCMType,
		kmsapi.ChaCha20Poly1305Type,
		kmsapi.XChaCha20Poly1305Type,
		kmsapi.ECDSAP256TypeDER,
		kmsapi.ECDSAP384TypeDER,
		kmsapi.ECDSAP521TypeDER,
		kmsapi.ECDSAP256TypeIEEEP1363,
		kmsapi.ECDSAP384TypeIEEEP1363,
		kmsapi.ECDSAP521TypeIEEEP1363,
		kmsapi.ED25519Type,
		kmsapi.NISTP256ECDHKWType,
		kmsapi.NISTP384ECDHKWType,
		kmsapi.NISTP521ECDHKWType,
		kmsapi.X25519ECDHKWType,
		kmsapi.BLS12381G2Type,
		kmsapi.ECDSASecp256k1DER,
		kmsapi.ECDSASecp256k1IEEEP1363,
	}

	for _, v := range keyTemplates {
		if v == kmsapi.ECDSASecp256k1DER {
			t.Logf("testing create for %s", v)
			_, _, e := kmsService.Create(v)
			require.EqualError(t, e, "create: Unable to create kms key: Secp256K1 is not supported by DER format")

			continue
		}

		// test Create() a new key
		keyID, newKeyHandle, e := kmsService.Create(v)
		require.NoError(t, e, "failed on template %v", v)
		require.NotEmpty(t, newKeyHandle)
		require.NotEmpty(t, keyID)

		ks, ok := keys[keyID]
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

		if strings.Contains(string(v), "ECDSA") || v == kmsapi.ED25519Type || v == kmsapi.BLS12381G2Type {
			pubKeyBytes, kt, e := kmsService.ExportPubKeyBytes(keyID)
			require.Errorf(t, e, "KeyID has been rotated. An error must be returned")
			require.Empty(t, pubKeyBytes)
			require.Empty(t, kt)

			pubKeyBytes, kt, e = kmsService.ExportPubKeyBytes(newKeyID)
			require.NoError(t, e)
			require.NotEmpty(t, pubKeyBytes)
			require.Equal(t, v, kt)

			kh, e := kmsService.PubKeyBytesToHandle(pubKeyBytes, v)
			require.NoError(t, e)
			require.NotEmpty(t, kh)

			// test create and export key in one function
			_, _, e = kmsService.CreateAndExportPubKeyBytes(v)
			require.NoError(t, e)
		}
	}
}

func TestLocalKMS_ImportPrivateKey(t *testing.T) { // nolint:gocyclo
	// create a real (not mocked) master key and secret lock to test the KMS end to end
	sl := createMasterKeyAndSecretLock(t)

	// test New()
	kmsService, e := New(testMasterKeyURI, &mockProvider{
		storage:    newInMemoryKMSStore(),
		secretLock: sl,
	})
	require.NoError(t, e)
	require.NotEmpty(t, kmsService)

	// test import with nil key
	_, _, err := kmsService.ImportPrivateKey(nil, kmsapi.ECDSAP256TypeDER)
	require.EqualError(t, err, "import private key does not support this key type or key is public")

	flagTests := []struct {
		tcName  string
		keyType kmsapi.KeyType
		curve   elliptic.Curve
		setID   bool
		ksID    string
	}{
		{
			tcName:  "import private key using ECDSAP256DER type",
			keyType: kmsapi.ECDSAP256TypeDER,
			curve:   elliptic.P256(),
		},
		{
			tcName:  "import private key using ECDSAP384TypeDER type",
			keyType: kmsapi.ECDSAP384TypeDER,
			curve:   elliptic.P384(),
		},
		{
			tcName:  "import private key using ECDSAP521TypeDER type",
			keyType: kmsapi.ECDSAP521TypeDER,
			curve:   elliptic.P521(),
		},
		{
			tcName:  "import private key using NISTP256ECDHKW type",
			keyType: kmsapi.NISTP256ECDHKWType,
			curve:   elliptic.P256(),
		},
		{
			tcName:  "import private key using NISTP384ECDHKW type",
			keyType: kmsapi.NISTP384ECDHKWType,
			curve:   elliptic.P384(),
		},
		{
			tcName:  "import private key using NISTP521ECDHKW type",
			keyType: kmsapi.NISTP521ECDHKWType,
			curve:   elliptic.P521(),
		},
		{
			tcName:  "import private key using ECDSAP256TypeIEEEP1363 type",
			keyType: kmsapi.ECDSAP256TypeIEEEP1363,
			curve:   elliptic.P256(),
		},
		{
			tcName:  "import private key using ECDSAP384TypeIEEEP1363 type",
			keyType: kmsapi.ECDSAP384TypeIEEEP1363,
			curve:   elliptic.P384(),
		},
		{
			tcName:  "import private key using ECDSAP521TypeIEEEP1363 type",
			keyType: kmsapi.ECDSAP521TypeIEEEP1363,
			curve:   elliptic.P521(),
		},
		/*{
			tcName:  "import private key using ECDSAP256DER type",
			keyType: kms.ECDSASecp256k1DER,
			curve:   btcec.S256(),
		},*/
		{
			tcName:  "import private key using ECDSAP256IEEEP1363 type",
			keyType: kmsapi.ECDSASecp256k1IEEEP1363,
			curve:   btcec.S256(),
		},
		{
			tcName:  "import private key using ED25519Type type",
			keyType: kmsapi.ED25519Type,
		},
		{
			tcName:  "import private key using BLS12381G2Type type",
			keyType: kmsapi.BLS12381G2Type,
		},
		{
			tcName:  "import private key using ECDSAP256DER type and a set empty KeyID",
			keyType: kmsapi.ECDSAP256TypeDER,
			curve:   elliptic.P256(),
			setID:   true,
			ksID:    "",
		},
		{
			tcName:  "import private key using ECDSAP256DER type and a set non empty KeyID",
			keyType: kmsapi.ECDSAP256TypeDER,
			curve:   elliptic.P256(),
			setID:   true,
			ksID: base64.RawURLEncoding.EncodeToString(random.GetRandomBytes(
				uint32(base64.RawURLEncoding.DecodedLen(maxKeyIDLen)))),
		},
		{
			tcName:  "import private key using ECDSAP256DER type and a set non KeyID larger than maxKeyIDLen",
			keyType: kmsapi.ECDSAP256TypeDER,
			curve:   elliptic.P256(),
			setID:   true,
			ksID: base64.RawURLEncoding.EncodeToString(random.GetRandomBytes(
				uint32(base64.RawURLEncoding.DecodedLen(30)))),
		},
	}

	for _, tc := range flagTests {
		tt := tc
		t.Run(tt.tcName, func(t *testing.T) {
			if tt.keyType == kmsapi.ED25519Type {
				pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)

				ksID, _, err := kmsService.ImportPrivateKey(privKey, tt.keyType)
				require.NoError(t, err)

				pubKeyBytes, kt, err := kmsService.ExportPubKeyBytes(ksID)
				require.NoError(t, err)
				require.EqualValues(t, pubKey, pubKeyBytes)
				require.Equal(t, tt.keyType, kt)
				return
			}

			if tt.keyType == kmsapi.BLS12381G2Type {
				seed := make([]byte, 32)

				_, err := rand.Read(seed)
				require.NoError(t, err)

				pubKey, privKey, err := bbs12381g2pub.GenerateKeyPair(sha256.New, seed)
				require.NoError(t, err)

				ksID, _, err := kmsService.ImportPrivateKey(privKey, tt.keyType)
				require.NoError(t, err)

				pubKeyBytes, kt, err := kmsService.ExportPubKeyBytes(ksID)
				require.NoError(t, err)
				require.Equal(t, tt.keyType, kt)

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
				ksID, _, err = kmsService.ImportPrivateKey(privKey, tt.keyType, kmsapi.WithKeyID(tt.ksID))
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
			actualPubKey, kt, err := kmsService.ExportPubKeyBytes(ksID)
			require.NoError(t, err)
			require.Equal(t, tt.keyType, kt)

			var expectedPubKey []byte

			switch tt.keyType {
			case kmsapi.ECDSAP256TypeDER, kmsapi.ECDSAP384TypeDER, kmsapi.ECDSAP521TypeDER, kmsapi.ECDSASecp256k1TypeDER:
				expectedPubKey, err = x509.MarshalPKIXPublicKey(privKey.Public())
				require.NoError(t, err)
			case kmsapi.ECDSAP256TypeIEEEP1363, kmsapi.ECDSAP384TypeIEEEP1363, kmsapi.ECDSAP521TypeIEEEP1363,
				kmsapi.ECDSASecp256k1TypeIEEEP1363:
				expectedPubKey = elliptic.Marshal(tt.curve, privKey.X, privKey.Y)
			case kmsapi.NISTP256ECDHKWType, kmsapi.NISTP384ECDHKWType, kmsapi.NISTP521ECDHKWType:
				var curveName string

				switch tt.curve.Params().Name {
				case "P-256":
					curveName = "NIST_P256"
				case "P-384":
					curveName = "NIST_P384"
				case "P-521":
					curveName = "NIST_P521"
				case "secp256k1":
					curveName = "SECP256K1"
				}

				cryptoKey := &crypto.PublicKey{
					KID:   ksID,
					X:     privKey.PublicKey.X.Bytes(),
					Y:     privKey.PublicKey.Y.Bytes(),
					Curve: curveName,
					Type:  "EC",
				}

				expectedPubKey, err = json.Marshal(cryptoKey)
				require.NoError(t, err)
			}

			require.EqualValues(t, expectedPubKey, actualPubKey)
		})
	}
}

func TestLocalKMS_getKeyTemplate(t *testing.T) {
	keyTemplate, err := getKeyTemplate(kmsapi.HMACSHA256Tag256Type)
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
	storage    kmsapi.Store
	secretLock secretlock.Service
}

func (m *mockProvider) StorageProvider() kmsapi.Store {
	return m.storage
}

func (m *mockProvider) SecretLock() secretlock.Service {
	return m.secretLock
}
