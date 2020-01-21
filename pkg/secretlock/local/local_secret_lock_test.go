/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package local

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/google/tink/go/subtle/random"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
)

func TestSecretLockService(t *testing.T) {
	// verify Lock implements Lock
	var _ secretlock.Service = (*Lock)(nil)

	const testKeyURI = "test://test/key/uri"

	t.Run("error case - create a service with missing masterKey env value", func(t *testing.T) {
		s, err := NewService(testKeyURI)
		require.EqualError(t, err, "masterKey not set")
		require.Empty(t, s)
	})

	t.Run("error case - create a service with master key not base64.URLEncoded", func(t *testing.T) {
		masterKey := random.GetRandomBytes(chacha20poly1305.KeySize)
		envKey := "LOCAL_" + strings.ReplaceAll(testKeyURI, "/", "_")
		masterKeyEnc := base64.URLEncoding.EncodeToString(masterKey)
		err := os.Setenv(envKey, masterKeyEnc+"{}") // setting master key with invalid characters, source of error.
		require.NoError(t, err)

		defer func() {
			e := os.Unsetenv(envKey)
			require.NoError(t, e)
		}()

		// test the creation of a local secret lock service with an invalid master key
		s, err := NewService(testKeyURI)
		require.Error(t, err)
		require.Empty(t, s)
	})

	t.Run("error case - master key length greater than chacha20poly1305.KeySize", func(t *testing.T) {
		masterKey := random.GetRandomBytes(chacha20poly1305.KeySize)
		// source of error - masterKey should not contain more bytes than chacha20poly1305.KeySize
		masterKey = append(masterKey, []byte("additionalKeyContent")...)
		masterKeyEnc := base64.URLEncoding.EncodeToString(masterKey)
		envKey := "LOCAL_" + strings.ReplaceAll(testKeyURI, "/", "_")
		err := os.Setenv(envKey, masterKeyEnc)
		require.NoError(t, err)
		defer func() {
			e := os.Unsetenv(envKey)
			require.NoError(t, e)
		}()

		s, err := NewService(testKeyURI)
		require.Error(t, err)
		require.Empty(t, s)
	})

	t.Run("success case - encrypt and decrypt valid requests", func(t *testing.T) {
		masterKey := random.GetRandomBytes(chacha20poly1305.KeySize)
		masterKeyEnc := base64.URLEncoding.EncodeToString(masterKey)
		envKey := "LOCAL_" + strings.ReplaceAll(testKeyURI, "/", "_")
		err := os.Setenv(envKey, masterKeyEnc)
		require.NoError(t, err)
		defer func() {
			e := os.Unsetenv(envKey)
			require.NoError(t, e)
		}()

		s, err := NewService(testKeyURI)
		require.NoError(t, err)
		require.NotEmpty(t, s)

		enc, err := s.Encrypt(testKeyURI, &secretlock.EncryptRequest{
			Plaintext:                   "loremipsum",
			AdditionalAuthenticatedData: "extra-data",
		})
		require.NoError(t, err)
		require.NotEmpty(t, enc)

		dec, err := s.Decrypt(testKeyURI, &secretlock.DecryptRequest{
			Ciphertext:                  enc.Ciphertext,
			AdditionalAuthenticatedData: "extra-data",
		})
		require.NoError(t, err)
		require.Equal(t, dec.Plaintext, "loremipsum")
	})

	t.Run("error case - decrypt with invalid base64.URLEncoded ciphertext", func(t *testing.T) {
		masterKey := random.GetRandomBytes(chacha20poly1305.KeySize)
		masterKeyEnc := base64.URLEncoding.EncodeToString(masterKey)
		envKey := "LOCAL_" + strings.ReplaceAll(testKeyURI, "/", "_")
		err := os.Setenv(envKey, masterKeyEnc)
		require.NoError(t, err)
		defer func() {
			e := os.Unsetenv(envKey)
			require.NoError(t, e)
		}()

		s, err := NewService(testKeyURI)
		require.NoError(t, err)
		require.NotEmpty(t, s)

		enc, err := s.Encrypt(testKeyURI, &secretlock.EncryptRequest{
			Plaintext:                   "loremipsum",
			AdditionalAuthenticatedData: "extra-data",
		})
		require.NoError(t, err)
		require.NotEmpty(t, enc)

		dec, err := s.Decrypt(testKeyURI, &secretlock.DecryptRequest{
			Ciphertext:                  enc.Ciphertext + "{}", // source of error - ciphertext with invalid characters
			AdditionalAuthenticatedData: "extra-data",
		})
		require.Error(t, err)
		require.Empty(t, dec)
	})

	t.Run("error case - decrypt with corrupt ciphertext prefix", func(t *testing.T) {
		masterKey := random.GetRandomBytes(chacha20poly1305.KeySize)
		masterKeyEnc := base64.URLEncoding.EncodeToString(masterKey)
		envKey := "LOCAL_" + strings.ReplaceAll(testKeyURI, "/", "_")
		err := os.Setenv(envKey, masterKeyEnc)
		require.NoError(t, err)
		defer func() {
			e := os.Unsetenv(envKey)
			require.NoError(t, e)
		}()

		s, err := NewService(testKeyURI)
		require.NoError(t, err)
		require.NotEmpty(t, s)

		enc, err := s.Encrypt(testKeyURI, &secretlock.EncryptRequest{
			Plaintext:                   "loremipsum",
			AdditionalAuthenticatedData: "extra-data",
		})
		require.NoError(t, err)
		require.NotEmpty(t, enc)

		ct := "badPrefix" + enc.Ciphertext[len("badPrefix"):]
		dec, err := s.Decrypt(testKeyURI, &secretlock.DecryptRequest{
			Ciphertext:                  ct, // source of error - using bad prefix to bread decryption
			AdditionalAuthenticatedData: "extra-data",
		})
		require.Error(t, err)
		require.Empty(t, dec)
	})
}
