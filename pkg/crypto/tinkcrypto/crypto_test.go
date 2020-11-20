/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tinkcrypto

import (
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/google/tink/go/aead"
	aeadsubtle "github.com/google/tink/go/aead/subtle"
	hybrid "github.com/google/tink/go/hybrid/subtle"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/subtle/random"
	"github.com/stretchr/testify/require"
	chacha "golang.org/x/crypto/chacha20poly1305"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/keyio"
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

		badKH2, err := keyset.NewHandle(ecdh.ECDH256KWAES256GCMKeyTemplate())
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

		// encrypt with another bad key handle - should fail
		_, _, err = c.Encrypt(msg, aad, badKH2)
		require.Error(t, err)

		plainText, err := c.Decrypt(cipherText, aad, nonce, kh)
		require.NoError(t, err)
		require.Equal(t, msg, plainText)

		// decrypt with bad key handle - should fail
		_, err = c.Decrypt(cipherText, aad, nonce, badKH)
		require.Error(t, err)

		// decrypt with another bad key handle - should fail
		_, err = c.Decrypt(cipherText, aad, nonce, badKH2)
		require.Error(t, err)

		// decrypt with bad nonce - should fail
		plainText, err = c.Decrypt(cipherText, aad, []byte("bad nonce"), kh)
		require.Error(t, err)
		require.Empty(t, plainText)

		// decrypt with bad cipher - should fail
		plainText, err = c.Decrypt([]byte("bad cipher"), aad, nonce, kh)
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

		plainText, err := c.Decrypt(cipherText, aad, nonce, kh)
		require.NoError(t, err)
		require.Equal(t, msg, plainText)

		// decrypt with bad nonce - should fail
		plainText, err = c.Decrypt(cipherText, aad, []byte("bad nonce"), kh)
		require.Error(t, err)
		require.Empty(t, plainText)

		// decrypt with bad cipher - should fail
		plainText, err = c.Decrypt([]byte("bad cipher"), aad, nonce, kh)
		require.Error(t, err)
		require.Empty(t, plainText)

		// decrypt with nil key handle - should fail
		_, err = c.Decrypt(cipherText, aad, nonce, nil)
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

func TestCrypto_ECDHES_Wrap_Unwrap_Key(t *testing.T) {
	recipientKeyHandle, err := keyset.NewHandle(ecdh.ECDH256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	c, err := New()
	require.NoError(t, err)

	cek := random.GetRandomBytes(uint32(crypto.DefKeySize))
	apu := random.GetRandomBytes(uint32(10)) // or sender name
	apv := random.GetRandomBytes(uint32(10)) // or recipient name

	// test WrapKey with nil recipientKey
	_, err = c.WrapKey(cek, apu, apv, nil)
	require.EqualError(t, err, "wrapKey: recipient public key is required")

	// now test WrapKey with good key
	recipientKey, err := keyio.ExtractPrimaryPublicKey(recipientKeyHandle)
	require.NoError(t, err)

	wrappedKey, err := c.WrapKey(cek, apu, apv, recipientKey)
	require.NoError(t, err)
	require.NotEmpty(t, wrappedKey.EncryptedCEK)
	require.NotEmpty(t, wrappedKey.EPK)
	require.EqualValues(t, wrappedKey.APU, apu)
	require.EqualValues(t, wrappedKey.APV, apv)
	require.Equal(t, wrappedKey.Alg, ECDHESA256KWAlg)

	// test UnwrapKey with empty recWK and/or kh
	_, err = c.UnwrapKey(nil, nil)
	require.EqualError(t, err, "unwrapKey: RecipientWrappedKey is empty")

	_, err = c.UnwrapKey(nil, recipientKeyHandle)
	require.EqualError(t, err, "unwrapKey: RecipientWrappedKey is empty")

	_, err = c.UnwrapKey(wrappedKey, nil)
	require.EqualError(t, err, "unwrapKey: bad key handle format")

	// test UnwrapKey with ECDHES key but different curve
	ecdh384Key, err := keyset.NewHandle(ecdh.ECDH384KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	_, err = c.UnwrapKey(wrappedKey, ecdh384Key)
	require.EqualError(t, err, "unwrapKey: recipient and epk keys are not on the same curve")

	// test UnwrapKey with wrappedKey using different algorithm
	origAlg := wrappedKey.Alg
	wrappedKey.Alg = "badAlg"
	_, err = c.UnwrapKey(wrappedKey, recipientKeyHandle)
	require.EqualError(t, err, "unwrapKey: unsupported JWE KW Alg 'badAlg'")

	wrappedKey.Alg = origAlg

	// finally test with valid wrappedKey and recipientKey
	uCEK, err := c.UnwrapKey(wrappedKey, recipientKeyHandle) // UnwrapKey will extract private key from recipientKey
	require.NoError(t, err)
	require.EqualValues(t, cek, uCEK)
}

func TestCrypto_ECDH1PU_Wrap_Unwrap_Key(t *testing.T) {
	recipientKeyHandle, err := keyset.NewHandle(ecdh.ECDH256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	recipientKey, err := keyio.ExtractPrimaryPublicKey(recipientKeyHandle)
	require.NoError(t, err)

	senderKH, err := keyset.NewHandle(ecdh.ECDH256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	c, err := New()
	require.NoError(t, err)

	cek := random.GetRandomBytes(uint32(crypto.DefKeySize))
	apu := random.GetRandomBytes(uint32(10)) // or sender name
	apv := random.GetRandomBytes(uint32(10)) // or recipient name

	// test with bad senderKH value
	_, err = c.WrapKey(cek, apu, apv, recipientKey, crypto.WithSender("badKey"))
	require.EqualError(t, err, "wrapKey: failed to retrieve sender key: ksToPrivateECDSAKey: bad key handle format")

	// now test WrapKey with good key
	wrappedKey, err := c.WrapKey(cek, apu, apv, recipientKey, crypto.WithSender(senderKH))
	require.NoError(t, err)
	require.NotEmpty(t, wrappedKey.EncryptedCEK)
	require.NotEmpty(t, wrappedKey.EPK)
	require.EqualValues(t, wrappedKey.APU, apu)
	require.EqualValues(t, wrappedKey.APV, apv)
	require.Equal(t, wrappedKey.Alg, ECDH1PUA256KWAlg)

	// test with valid wrappedKey, senderKH (public key) and recipientKey
	senderPubKH, err := senderKH.Public()
	require.NoError(t, err)

	uCEK, err := c.UnwrapKey(wrappedKey, recipientKeyHandle, crypto.WithSender(senderPubKH))
	require.NoError(t, err)
	require.EqualValues(t, cek, uCEK)

	// extract sender public key and try Unwrap using extracted key
	senderPubKey, err := keyio.ExtractPrimaryPublicKey(senderKH)
	require.NoError(t, err)

	crv, err := hybrid.GetCurve(senderPubKey.Curve)
	require.NoError(t, err)

	senderECPubKey := &ecdsa.PublicKey{
		Curve: crv,
		X:     new(big.Int).SetBytes(senderPubKey.X),
		Y:     new(big.Int).SetBytes(senderPubKey.Y),
	}

	uCEK, err = c.UnwrapKey(wrappedKey, recipientKeyHandle, crypto.WithSender(senderECPubKey))
	require.NoError(t, err)
	require.EqualValues(t, cek, uCEK)
}

func TestCrypto_ECDH1PU_Wrap_Unwrap_Key_Using_CryptoPubKey_as_SenderKey(t *testing.T) {
	recipientKeyHandle, err := keyset.NewHandle(ecdh.ECDH256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	recipientKey, err := keyio.ExtractPrimaryPublicKey(recipientKeyHandle)
	require.NoError(t, err)

	senderKH, err := keyset.NewHandle(ecdh.ECDH256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	c, err := New()
	require.NoError(t, err)

	cek := random.GetRandomBytes(uint32(crypto.DefKeySize))
	apu := random.GetRandomBytes(uint32(10)) // or sender name
	apv := random.GetRandomBytes(uint32(10)) // or recipient name

	// extract sender public key as crypto.Public key to be used in WithSender()
	senderPubKey, err := keyio.ExtractPrimaryPublicKey(senderKH)
	require.NoError(t, err)

	// test WrapKey with extacted crypto.PublicKey above directly
	// WrapKey() only accepts senderKH as keyset.Handle because it will use its private key.
	wrappedKey, err := c.WrapKey(cek, apu, apv, recipientKey, crypto.WithSender(senderKH))
	require.NoError(t, err)
	require.NotEmpty(t, wrappedKey.EncryptedCEK)
	require.NotEmpty(t, wrappedKey.EPK)
	require.EqualValues(t, wrappedKey.APU, apu)
	require.EqualValues(t, wrappedKey.APV, apv)
	require.Equal(t, wrappedKey.Alg, ECDH1PUA256KWAlg)

	// UnwrapKey require sender public key used here or keyset.Handle which was tested in the previous function above
	uCEK, err := c.UnwrapKey(wrappedKey, recipientKeyHandle, crypto.WithSender(senderPubKey))
	require.NoError(t, err)
	require.EqualValues(t, cek, uCEK)

	crv, err := hybrid.GetCurve(senderPubKey.Curve)
	require.NoError(t, err)

	senderECPubKey := &ecdsa.PublicKey{
		Curve: crv,
		X:     new(big.Int).SetBytes(senderPubKey.X),
		Y:     new(big.Int).SetBytes(senderPubKey.Y),
	}

	uCEK, err = c.UnwrapKey(wrappedKey, recipientKeyHandle, crypto.WithSender(senderECPubKey))
	require.NoError(t, err)
	require.EqualValues(t, cek, uCEK)
}
