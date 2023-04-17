/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package local

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/google/tink/go/subtle/random"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/spi/secretlock"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/secretlock/local/masterlock/hkdf"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/secretlock/local/masterlock/pbkdf2"
)

const (
	testKeyURI = "test://test/key/uri"
	envPrefix  = "TESTLOCAL_"
)

func TestCreateServiceFromPathWithDifferentFileSizes(t *testing.T) {
	tcs := []struct {
		tcName       string
		fileName     string
		masterKeyLen int
		readerError  bool
		serviceError bool
		base64Enc    bool
	}{
		{
			tcName:       "large file",
			fileName:     "masterKey_file_large.txt",
			masterKeyLen: 9999,
			readerError:  false,
			serviceError: true,
		},
		{
			tcName:       "empty file",
			fileName:     "masterKey_file_empty.txt",
			masterKeyLen: 0,
			readerError:  true,
			serviceError: true,
		},
		{
			tcName:       "valid file with raw master key content",
			fileName:     "masterKey_file_valid_raw.txt",
			masterKeyLen: 32,
			readerError:  false,
			serviceError: false,
		},
		{
			tcName:       "valid file with base64 URL Encoded master key",
			fileName:     "masterKey_file_valid_enc.txt",
			masterKeyLen: 32,
			readerError:  false,
			serviceError: false,
			base64Enc:    true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.tcName, func(t *testing.T) {
			masterKeyFilePath := tc.fileName
			tmpfile, err := ioutil.TempFile("", masterKeyFilePath)
			require.NoError(t, err)

			defer func() {
				// close file
				require.NoError(t, tmpfile.Close())
				// clean up file
				require.NoError(t, os.Remove(tmpfile.Name()))
			}()

			masterKeyContent := []byte{}

			if tc.masterKeyLen != 0 {
				masterKeyContent = random.GetRandomBytes(uint32(tc.masterKeyLen))
				require.NotEmpty(t, masterKeyContent)
			}

			if tc.base64Enc {
				keyEncoded := base64.URLEncoding.EncodeToString(masterKeyContent)
				masterKeyContent = []byte(keyEncoded)
			}

			n, err := tmpfile.Write(masterKeyContent)
			require.NoError(t, err)
			require.Equal(t, len(masterKeyContent), n)

			// try to get a reader
			r, err := MasterKeyFromPath(tmpfile.Name())
			if tc.readerError {
				require.Error(t, err)
				require.Empty(t, r)

				// set r to empty reader
				r = bytes.NewReader([]byte{})
			} else {
				require.NoError(t, err)
				require.NotEmpty(t, r)
			}

			// try to create lock service for this above reader with nil master lock (master key not encrypted)
			s, err := NewService(r, nil)
			if tc.serviceError {
				require.Error(t, err)
				require.Empty(t, s)
			} else {
				require.NoError(t, err)
				require.NotEmpty(t, s)
			}
		})
	}
}

func TestCreateServiceFromPathWithoutMasterLock(t *testing.T) {
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

	masterKeyToSave := make([]byte, base64.URLEncoding.EncodedLen(len(masterKeyContent)))
	base64.URLEncoding.Encode(masterKeyToSave, masterKeyContent)

	n, err := tmpfile.Write(masterKeyToSave)
	require.NoError(t, err)
	require.Equal(t, len(masterKeyToSave), n)

	// try invalid path
	r, err := MasterKeyFromPath("bad/mk/test/file/name")
	require.Error(t, err)
	require.Empty(t, r)

	// try real file path
	r, err = MasterKeyFromPath(tmpfile.Name())
	require.NoError(t, err)
	require.NotEmpty(t, r)

	// create lock service with nil master lock (master key not encrypted)
	s, err := NewService(r, nil)
	require.NoError(t, err)
	require.NotEmpty(t, s)

	someKey := random.GetRandomBytes(uint32(32))
	someKeyEnc, err := s.Encrypt("", &secretlock.EncryptRequest{
		Plaintext: string(someKey),
	})
	require.NoError(t, err)
	require.NotEmpty(t, someKeyEnc)

	someKeyDec, err := s.Decrypt("", &secretlock.DecryptRequest{
		Ciphertext: someKeyEnc.Ciphertext,
	})
	require.NoError(t, err)
	require.Equal(t, someKey, []byte(someKeyDec.Plaintext))

	// try decrypting a non valid base64URL string
	someKeyDec, err = s.Decrypt("", &secretlock.DecryptRequest{Ciphertext: "bad{}base64URLstring[]"})
	require.Error(t, err)
	require.Empty(t, someKeyDec)
}

func TestCreateServiceFromPathWithMasterLock(t *testing.T) {
	// first create a master lock to use in our secret lock and encrypt the master key
	passphrase := "secretPassphrase"
	keySize := sha256.New().Size()
	// salt is optional, it can be nil
	salt := make([]byte, keySize)
	_, err := rand.Read(salt)
	require.NoError(t, err)

	masterLockerHKDF, err := hkdf.NewMasterLock(passphrase, sha256.New, salt)
	require.NoError(t, err)
	require.NotEmpty(t, masterLockerHKDF)

	masterLockerPBKDF2, err := pbkdf2.NewMasterLock(passphrase, sha256.New, 8192, salt)
	require.NoError(t, err)
	require.NotEmpty(t, masterLockerPBKDF2)

	tests := []struct {
		name       string
		masterLock secretlock.Service
	}{
		{
			name:       "lock using hkdf as masterlock",
			masterLock: masterLockerHKDF,
		}, {
			name:       "lock using pbkdf2 as masterlock",
			masterLock: masterLockerPBKDF2,
		},
	}

	for _, tt := range tests {
		tc := tt
		t.Run("Test "+tc.name, func(t *testing.T) {
			checkCreateServiceUsingMasterLock(t, tc.masterLock)
		})
	}
}

func checkCreateServiceUsingMasterLock(t *testing.T, masterLocker secretlock.Service) {
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
	r, err := MasterKeyFromPath(tmpfile.Name())
	require.NoError(t, err)
	require.NotEmpty(t, r)

	// try a bad reader
	badReader, err := MasterKeyFromPath("bad/mk/test/file/name")
	require.Error(t, err)
	require.Empty(t, badReader)

	// finally create lock service with the master lock created earlier to encrypt decrypt keys using
	// a protected (encrypted) master key
	s, err := NewService(r, masterLocker)
	require.NoError(t, err)
	require.NotEmpty(t, s)

	// now try to crate a lock service with a bad (nil) reader reference
	badSerivce, err := NewService(badReader, masterLocker)
	require.EqualError(t, err, "masterKeyReader is nil")
	require.Empty(t, badSerivce)

	// or a nil reader as argument
	badSerivce, err = NewService(nil, masterLocker)
	require.Error(t, err)
	require.Empty(t, badSerivce)

	// or a reader containing an invalid master key
	badSerivce, err = NewService(bytes.NewReader([]byte("badMasterKey")), masterLocker)
	require.Error(t, err)
	require.Empty(t, badSerivce)

	someKey := random.GetRandomBytes(uint32(32))
	someKeyEnc, err := s.Encrypt("", &secretlock.EncryptRequest{
		Plaintext: string(someKey),
	})
	require.NoError(t, err)
	require.NotEmpty(t, someKeyEnc)

	someKeyDec, err := s.Decrypt("", &secretlock.DecryptRequest{
		Ciphertext: someKeyEnc.Ciphertext,
	})
	require.NoError(t, err)
	require.Equal(t, someKey, []byte(someKeyDec.Plaintext))

	// finally try to decrypt a bad ciphertext
	badCipher := base64.URLEncoding.EncodeToString([]byte("BadCipherTextInAction"))

	someKeyDec, err = s.Decrypt("", &secretlock.DecryptRequest{Ciphertext: badCipher})
	require.Error(t, err)
	require.Empty(t, someKeyDec)

	// try with a short cipher (shorter than nonce+ciphertext)
	badCipher = base64.URLEncoding.EncodeToString([]byte("short"))

	someKeyDec, err = s.Decrypt("", &secretlock.DecryptRequest{Ciphertext: badCipher})
	require.Error(t, err)
	require.Empty(t, someKeyDec)
}

func TestCreateServiceFromEnvWithoutMasterLock(t *testing.T) {
	masterKeyContent := random.GetRandomBytes(uint32(32))
	require.NotEmpty(t, masterKeyContent)

	envKey := envPrefix + strings.ReplaceAll(testKeyURI, "/", "_")

	// set the master key (unencrypted) in env
	err := os.Setenv(envKey, base64.URLEncoding.EncodeToString(masterKeyContent))
	require.NoError(t, err)

	defer func() {
		// clean up env variable
		require.NoError(t, os.Unsetenv(envKey))
	}()

	r, err := MasterKeyFromEnv(envPrefix, "bad/mk/test/key")
	require.Error(t, err)
	require.Empty(t, r)

	r, err = MasterKeyFromEnv(envPrefix, testKeyURI)
	require.NoError(t, err)
	require.NotEmpty(t, r)

	// create lock service with nil master lock (master key not encrypted)
	s, err := NewService(r, nil)
	require.NoError(t, err)
	require.NotEmpty(t, s)

	someKey := random.GetRandomBytes(uint32(32))
	someKeyEnc, err := s.Encrypt("", &secretlock.EncryptRequest{
		Plaintext: string(someKey),
	})
	require.NoError(t, err)
	require.NotEmpty(t, someKeyEnc)

	someKeyDec, err := s.Decrypt("", &secretlock.DecryptRequest{
		Ciphertext: someKeyEnc.Ciphertext,
	})
	require.NoError(t, err)
	require.Equal(t, someKey, []byte(someKeyDec.Plaintext))
}

func TestCreateServiceFromEnvWithMasterLock(t *testing.T) {
	masterKeyContent := random.GetRandomBytes(uint32(32))
	require.NotEmpty(t, masterKeyContent)

	// first create a master lock to use in our secret lock and encrypt the master key
	passphrase := "secretPassphrase"
	keySize := sha256.New().Size()
	// salt is optional, it can be nil
	salt := make([]byte, keySize)
	_, err := rand.Read(salt)
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

	envKey := envPrefix + strings.ReplaceAll(testKeyURI, "/", "_")

	// now set the encrypted master key in env
	err = os.Setenv(envKey, masterLockEnc.Ciphertext)
	require.NoError(t, err)

	defer func() {
		// clean up env variable
		require.NoError(t, os.Unsetenv(envKey))
	}()

	// get a reader from an invalid env variable
	badReader, err := MasterKeyFromEnv(envPrefix, "bad/mk/test/key")
	require.Error(t, err)
	require.Empty(t, badReader)

	// get a reader from a valid env variable
	r, err := MasterKeyFromEnv(envPrefix, testKeyURI)
	require.NoError(t, err)
	require.NotEmpty(t, r)

	// finally create lock service with the master lock created earlier to encrypt decrypt keys using
	// a protected (encrypted) master key
	s, err := NewService(r, masterLocker)
	require.NoError(t, err)
	require.NotEmpty(t, s)

	// now try to crate a lock service with a bad reader
	badSerivce, err := NewService(badReader, masterLocker)
	require.Error(t, err)
	require.Empty(t, badSerivce)

	// or a nil reader
	badSerivce, err = NewService(nil, masterLocker)
	require.Error(t, err)
	require.Empty(t, badSerivce)

	someKey := random.GetRandomBytes(uint32(32))
	someKeyEnc, err := s.Encrypt("", &secretlock.EncryptRequest{
		Plaintext: string(someKey),
	})
	require.NoError(t, err)
	require.NotEmpty(t, someKeyEnc)

	someKeyDec, err := s.Decrypt("", &secretlock.DecryptRequest{
		Ciphertext: someKeyEnc.Ciphertext,
	})
	require.NoError(t, err)
	require.Equal(t, someKey, []byte(someKeyDec.Plaintext))
}
