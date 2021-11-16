/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package pbkdf2

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"testing"

	"github.com/google/tink/go/subtle/random"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
)

func TestMasterLock(t *testing.T) {
	keySize := sha256.New().Size()
	testKey := random.GetRandomBytes(uint32(keySize))
	goodPassphrase := "somepassphrase"
	defIter := 4096

	salt := make([]byte, keySize)
	_, err := rand.Read(salt)
	require.NoError(t, err)

	mkLock, err := NewMasterLock(goodPassphrase, sha256.New, defIter, salt)
	require.NoError(t, err)

	// try to create a bad master key lock (unsupported hash)
	mkLockBad, err := NewMasterLock(goodPassphrase, sha512.New, defIter, salt)
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
	mkLock2, err := NewMasterLock(goodPassphrase, sha256.New, defIter, salt)
	require.NoError(t, err)

	// ensure Decrypt() is successful and returns the same result as the original lock
	decryptedMk2, err := mkLock2.Decrypt("", &secretlock.DecryptRequest{Ciphertext: encryptedMk.Ciphertext})
	require.NoError(t, err)
	require.Equal(t, testKey, []byte(decryptedMk2.Plaintext))

	// recreate new lock with empty salt
	mkLock2, err = NewMasterLock(goodPassphrase, sha256.New, defIter, nil)
	require.NoError(t, err)

	decryptedMk2, err = mkLock2.Decrypt("", &secretlock.DecryptRequest{Ciphertext: encryptedMk.Ciphertext})
	require.Error(t, err)
	require.Empty(t, decryptedMk2)

	// recreate new lock with a different salt
	salt2 := make([]byte, keySize)
	_, err = rand.Read(salt2)
	require.NoError(t, err)

	mkLock2, err = NewMasterLock(goodPassphrase, sha256.New, defIter, salt2)
	require.NoError(t, err)

	decryptedMk2, err = mkLock2.Decrypt("", &secretlock.DecryptRequest{Ciphertext: encryptedMk.Ciphertext})
	require.Error(t, err)
	require.Empty(t, decryptedMk2)

	// try with a bad passhrase
	mkLock2, err = NewMasterLock("badPassphrase", sha256.New, defIter, salt)
	require.NoError(t, err)

	decryptedMk2, err = mkLock2.Decrypt("", &secretlock.DecryptRequest{Ciphertext: encryptedMk.Ciphertext})
	require.Error(t, err)
	require.Empty(t, decryptedMk2)

	// try creating a lock with a nil hash
	mkLock2, err = NewMasterLock(goodPassphrase, nil, defIter, salt)
	require.Error(t, err)
	require.Empty(t, mkLock2)

	// try creating a lock with an empty passphrase
	mkLock2, err = NewMasterLock("", sha256.New, defIter, salt)
	require.Error(t, err)
	require.Empty(t, mkLock2)
}

func benchmark(b *testing.B, h func() hash.Hash, iter int) {
	b.Helper()

	var (
		sink uint8
		lck  secretlock.Service
	)

	password := "somepassphrase"
	salt := make([]byte, h().Size())
	_, err := rand.Read(salt)
	require.NoError(b, err)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		lck, err = NewMasterLock(password, h, iter, salt)
		require.NoError(b, err)

		mlck, ok := lck.(*masterLockPBKDF2)
		require.True(b, ok)

		sink += uint8(mlck.aead.Overhead())
	}

	MajorSink = sink
}

// nolint:gochecknoglobals // needed to avoid Go compiler perf optimizations for benchmarks (avoid optimize loop body).
var MajorSink uint8

func BenchmarkHMACSHA256_4k(b *testing.B) {
	benchmark(b, sha256.New, 4096)
}

func BenchmarkHMACSHA256_8k(b *testing.B) {
	benchmark(b, sha256.New, 8192)
}

func BenchmarkHMACSHA256_64k(b *testing.B) {
	benchmark(b, sha256.New, 65536)
}
