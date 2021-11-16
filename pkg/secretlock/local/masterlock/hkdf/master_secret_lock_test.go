/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package hkdf

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"testing"

	"github.com/google/tink/go/subtle/random"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
)

func TestMasterLock(t *testing.T) {
	keySize := sha256.New().Size()
	testKey := random.GetRandomBytes(uint32(keySize))
	goodPassphrase := "somepassphrase"

	salt := make([]byte, keySize)
	_, err := rand.Read(salt)
	require.NoError(t, err)

	mkLock, err := NewMasterLock(goodPassphrase, sha256.New, salt)
	require.NoError(t, err)

	// try to create a bad master key lock (unsupported hash)
	mkLockBad, err := NewMasterLock(goodPassphrase, sha512.New, salt)
	require.Error(t, err)
	require.Empty(t, mkLockBad)

	encryptedMk, err := mkLock.Encrypt("", &secretlock.EncryptRequest{Plaintext: string(testKey)})
	require.NoError(t, err)
	require.NotEmpty(t, encryptedMk)

	decryptedMk, err := mkLock.Decrypt("", &secretlock.DecryptRequest{Ciphertext: encryptedMk.Ciphertext})
	require.NoError(t, err)
	require.Equal(t, testKey, []byte(decryptedMk.Plaintext))

	// try decrypting a non valid base64URL string
	decryptedMk, err = mkLock.Decrypt("", &secretlock.DecryptRequest{Ciphertext: "bad{}base64URLstring[]"})
	require.Error(t, err)
	require.Empty(t, decryptedMk)

	// create a new lock instance with the same passphrase, hash, salt
	mkLock2, err := NewMasterLock(goodPassphrase, sha256.New, salt)
	require.NoError(t, err)

	// ensure Decrypt() is successful and returns the same result as the original lock
	decryptedMk2, err := mkLock2.Decrypt("", &secretlock.DecryptRequest{Ciphertext: encryptedMk.Ciphertext})
	require.NoError(t, err)
	require.Equal(t, testKey, []byte(decryptedMk2.Plaintext))

	// recreate new lock with empty salt
	mkLock2, err = NewMasterLock(goodPassphrase, sha256.New, nil)
	require.NoError(t, err)

	decryptedMk2, err = mkLock2.Decrypt("", &secretlock.DecryptRequest{Ciphertext: encryptedMk.Ciphertext})
	require.Error(t, err)
	require.Empty(t, decryptedMk2)

	// recreate new lock with a different salt
	salt2 := make([]byte, keySize)
	_, err = rand.Read(salt2)
	require.NoError(t, err)

	mkLock2, err = NewMasterLock(goodPassphrase, sha256.New, salt2)
	require.NoError(t, err)

	decryptedMk2, err = mkLock2.Decrypt("", &secretlock.DecryptRequest{Ciphertext: encryptedMk.Ciphertext})
	require.Error(t, err)
	require.Empty(t, decryptedMk2)

	// try with a bad passhrase
	mkLock2, err = NewMasterLock("badPassphrase", sha256.New, salt)
	require.NoError(t, err)

	decryptedMk2, err = mkLock2.Decrypt("", &secretlock.DecryptRequest{Ciphertext: encryptedMk.Ciphertext})
	require.Error(t, err)
	require.Empty(t, decryptedMk2)

	// try creating a lock with a nil hash
	mkLock2, err = NewMasterLock(goodPassphrase, nil, salt)
	require.Error(t, err)
	require.Empty(t, mkLock2)

	// try creating a lock with an empty passphrase
	mkLock2, err = NewMasterLock("", sha256.New, salt)
	require.Error(t, err)
	require.Empty(t, mkLock2)
}
