/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tinkcrypto

import (
	"testing"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/signature"
	aeadsubtle "github.com/google/tink/go/subtle/aead"
	"github.com/stretchr/testify/require"
	chacha "golang.org/x/crypto/chacha20poly1305"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
)

const testMessage = "test message"

// Assert that Crypto implements the Crypto interface.
var _ crypto.Crypto = (*Crypto)(nil)

func TestNew(t *testing.T) {
	_, err := New()
	require.NoError(t, err)
}

func TestCrypto_EncryptDecrypt(t *testing.T) {
	t.Run("test XChacha20Poly1305 encryption", func(t *testing.T) {
		kh, err := keyset.NewHandle(aead.XChaCha20Poly1305KeyTemplate())
		require.NoError(t, err)

		badKH, err := keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate("babdUrl", nil))
		require.NoError(t, err)

		c := Crypto{}
		msg := []byte(testMessage)
		aad := []byte("some additional data")
		cipherText, nonce, err := c.Encrypt(msg, aad, kh)
		require.NoError(t, err)
		require.NotEmpty(t, nonce)
		require.Equal(t, chacha.NonceSizeX, len(nonce))

		// encrypt with bad key handle - should fail
		_, _, err = c.Encrypt(msg, aad, badKH)
		require.Error(t, err)

		plainText, err := c.Decrypt(cipherText, nonce, aad, kh)
		require.NoError(t, err)
		require.Equal(t, msg, plainText)

		// decrypt with bad key handle - should fail
		_, err = c.Decrypt(cipherText, nonce, aad, badKH)
		require.Error(t, err)

		// decrypt with bad nonce - should fail
		plainText, err = c.Decrypt(cipherText, []byte("bad nonce"), aad, kh)
		require.Error(t, err)
		require.Empty(t, plainText)

		// decrypt with bad cipher - should fail
		plainText, err = c.Decrypt([]byte("bad cipher"), nonce, aad, kh)
		require.Error(t, err)
		require.Empty(t, plainText)
	})

	t.Run("test AES256GCM encryption", func(t *testing.T) {
		kh, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
		require.NoError(t, err)

		c := Crypto{}
		msg := []byte(testMessage)
		aad := []byte("some additional data")
		cipherText, nonce, err := c.Encrypt(msg, aad, kh)
		require.NoError(t, err)
		require.NotEmpty(t, nonce)
		require.Equal(t, aeadsubtle.AESGCMIVSize, len(nonce))

		// encrypt with nil key handle - should fail
		_, _, err = c.Encrypt(msg, aad, nil)
		require.Error(t, err)
		require.Equal(t, errBadKeyHandleFormat, err)

		plainText, err := c.Decrypt(cipherText, nonce, aad, kh)
		require.NoError(t, err)
		require.Equal(t, msg, plainText)

		// decrypt with bad nonce - should fail
		plainText, err = c.Decrypt(cipherText, []byte("bad nonce"), aad, kh)
		require.Error(t, err)
		require.Empty(t, plainText)

		// decrypt with bad cipher - should fail
		plainText, err = c.Decrypt([]byte("bad cipher"), nonce, aad, kh)
		require.Error(t, err)
		require.Empty(t, plainText)

		// decrypt with nil key handle - should fail
		_, err = c.Decrypt(cipherText, nonce, aad, nil)
		require.Error(t, err)
		require.Equal(t, errBadKeyHandleFormat, err)
	})
}

func TestCrypto_SignVerify(t *testing.T) {
	t.Run("test with Ed25519 signature", func(t *testing.T) {
		kh, err := keyset.NewHandle(signature.ED25519KeyTemplate())
		require.NoError(t, err)

		badKH, err := keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate("babdUrl", nil))
		require.NoError(t, err)

		c := Crypto{}
		msg := []byte(testMessage)
		s, err := c.Sign(msg, kh)
		require.NoError(t, err)

		// sign with nil key handle - should fail
		_, err = c.Sign(msg, nil)
		require.Error(t, err)
		require.Equal(t, errBadKeyHandleFormat, err)

		// sign with bad key handle - should fail
		_, err = c.Sign(msg, badKH)
		require.Error(t, err)

		// get corresponding public key handle to verify
		pubKH, err := kh.Public()
		require.NoError(t, err)

		err = c.Verify(s, msg, pubKH)
		require.NoError(t, err)
	})

	t.Run("test with P-256 signature", func(t *testing.T) {
		kh, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
		require.NoError(t, err)

		badKH, err := keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate("babdUrl", nil))
		require.NoError(t, err)

		c := Crypto{}
		msg := []byte(testMessage)
		s, err := c.Sign(msg, kh)
		require.NoError(t, err)

		// get corresponding public key handle to verify
		pubKH, err := kh.Public()
		require.NoError(t, err)

		err = c.Verify(s, msg, pubKH)
		require.NoError(t, err)

		// verify with nil key handle - should fail
		err = c.Verify(s, msg, nil)
		require.Error(t, err)
		require.Equal(t, errBadKeyHandleFormat, err)

		// verify with bad key handle - should fail
		err = c.Verify(s, msg, badKH)
		require.Error(t, err)
	})
}

func TestCrypto_ComputeMAC(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		kh, err := keyset.NewHandle(mac.HMACSHA256Tag256KeyTemplate())
		require.NoError(t, err)
		require.NotNil(t, kh)

		c := Crypto{}
		msg := []byte(testMessage)
		macBytes, err := c.ComputeMAC(msg, kh)
		require.NoError(t, err)
		require.NotEmpty(t, macBytes)
	})
	t.Run("fail - message to compute MAC for is empty", func(t *testing.T) {
		kh, err := keyset.NewHandle(mac.HMACSHA256Tag256KeyTemplate())
		require.NoError(t, err)
		require.NotNil(t, kh)

		c := Crypto{}
		macBytes, err := c.ComputeMAC(nil, kh)
		require.EqualError(t, err, "HMAC: invalid input")
		require.Empty(t, macBytes)
	})
	t.Run("invalid key handle", func(t *testing.T) {
		c := Crypto{}
		macBytes, err := c.ComputeMAC(nil, nil)
		require.Equal(t, errBadKeyHandleFormat, err)
		require.Empty(t, macBytes)
	})
	t.Run("fail - wrong key type", func(t *testing.T) {
		kh, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
		require.NoError(t, err)
		require.NotNil(t, kh)

		c := Crypto{}
		msg := []byte(testMessage)
		macBytes, err := c.ComputeMAC(msg, kh)
		require.EqualError(t, err, "mac_factory: not a MAC primitive")
		require.Empty(t, macBytes)
	})
}

func TestCrypto_VerifyMAC(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		kh, err := keyset.NewHandle(mac.HMACSHA256Tag256KeyTemplate())
		require.NoError(t, err)
		require.NotNil(t, kh)

		c := Crypto{}
		msg := []byte(testMessage)
		macBytes, err := c.ComputeMAC(msg, kh)
		require.NoError(t, err)
		require.NotEmpty(t, macBytes)

		err = c.VerifyMAC(macBytes, msg, kh)
		require.NoError(t, err)
	})
	t.Run("bad key handle format", func(t *testing.T) {
		c := Crypto{}
		err := c.VerifyMAC(nil, nil, nil)
		require.Equal(t, errBadKeyHandleFormat, err)
	})
	t.Run("fail - wrong key type", func(t *testing.T) {
		kh, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
		require.NoError(t, err)
		require.NotNil(t, kh)

		c := Crypto{}
		err = c.VerifyMAC(nil, nil, kh)
		require.EqualError(t, err, "mac_factory: not a MAC primitive")
	})
}
