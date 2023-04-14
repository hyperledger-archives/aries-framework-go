/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tinkcrypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	tinkaead "github.com/google/tink/go/aead"
	tinkaeadsubtle "github.com/google/tink/go/aead/subtle"
	hybrid "github.com/google/tink/go/hybrid/subtle"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/subtle/random"
	"github.com/stretchr/testify/require"
	chacha "golang.org/x/crypto/chacha20poly1305"

	cryptoapi "github.com/hyperledger/aries-framework-go/spi/crypto"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead/subtle"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/bbs"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/ecdh"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/keyio"
	ecdhpb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/secp256k1"
)

const testMessage = "test message"

// Assert that Crypto implements the Crypto interface.
var _ cryptoapi.Crypto = (*Crypto)(nil)

func TestNew(t *testing.T) {
	_, err := New()
	require.NoError(t, err)
}

func TestCrypto_EncryptDecrypt(t *testing.T) {
	tests := []struct {
		name         string
		ivSize       int
		aeadTemplate *tinkpb.KeyTemplate
	}{
		{
			name:         "test XChacha20Poly1305 encryption",
			ivSize:       chacha.NonceSizeX,
			aeadTemplate: tinkaead.XChaCha20Poly1305KeyTemplate(),
		},
		{
			name:         "test AES256GCM encryption",
			ivSize:       tinkaeadsubtle.AESGCMIVSize,
			aeadTemplate: tinkaead.AES256GCMKeyTemplate(),
		},
		{
			name:         "test AES128CBCHMACSHA256 encryption",
			ivSize:       subtle.AESCBCIVSize,
			aeadTemplate: aead.AES128CBCHMACSHA256KeyTemplate(),
		},
		{
			name:         "test AES192CBCHMACSHA384 encryption",
			ivSize:       subtle.AESCBCIVSize,
			aeadTemplate: aead.AES192CBCHMACSHA384KeyTemplate(),
		},
		{
			name:         "test AES256CBCHMACSHA384 encryption",
			ivSize:       subtle.AESCBCIVSize,
			aeadTemplate: aead.AES256CBCHMACSHA384KeyTemplate(),
		},
		{
			name:         "test AES256CBCHMACSHA512 encryption",
			ivSize:       subtle.AESCBCIVSize,
			aeadTemplate: aead.AES256CBCHMACSHA512KeyTemplate(),
		},
	}

	t.Parallel()

	for _, test := range tests {
		tc := test
		t.Run(tc.name, func(t *testing.T) {
			kh, err := keyset.NewHandle(tc.aeadTemplate)
			require.NoError(t, err)

			c := Crypto{}
			msg := []byte(testMessage)
			aad := []byte("some additional data")
			cipherText, nonce, err := c.Encrypt(msg, aad, kh)
			require.NoError(t, err)
			require.NotEmpty(t, nonce)
			require.Equal(t, tc.ivSize, len(nonce))

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
		})
	}

	t.Run("test bad/nil kh encryption", func(t *testing.T) {
		kh, err := keyset.NewHandle(tinkaead.AES256GCMKeyTemplate())
		require.NoError(t, err)

		c := Crypto{}
		msg := []byte(testMessage)
		aad := []byte("some additional data")
		cipherText, nonce, err := c.Encrypt(msg, aad, kh)
		require.NoError(t, err)
		require.NotEmpty(t, nonce)
		require.Equal(t, tinkaeadsubtle.AESGCMIVSize, len(nonce))

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

		badKH, err := keyset.NewHandle(tinkaead.KMSEnvelopeAEADKeyTemplate("babdUrl", nil))
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

		badKH, err := keyset.NewHandle(tinkaead.KMSEnvelopeAEADKeyTemplate("babdUrl", nil))
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

	t.Run("test with P-384 signature", func(t *testing.T) {
		kh, err := keyset.NewHandle(signature.ECDSAP384KeyTemplate())
		require.NoError(t, err)

		badKH, err := keyset.NewHandle(tinkaead.KMSEnvelopeAEADKeyTemplate("babdUrl", nil))
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

	t.Run("test with secp256k1 signature", func(t *testing.T) {
		derTemplate, err := secp256k1.DERKeyTemplate()
		require.NoError(t, err)

		kh, err := keyset.NewHandle(derTemplate)
		require.NoError(t, err)

		badKH, err := keyset.NewHandle(tinkaead.KMSEnvelopeAEADKeyTemplate("babdUrl", nil))
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
	t.Run("success - message to compute MAC with nil data - should be treated as empty data", func(t *testing.T) {
		kh, err := keyset.NewHandle(mac.HMACSHA256Tag256KeyTemplate())
		require.NoError(t, err)
		require.NotNil(t, kh)

		c := Crypto{}
		macBytes, err := c.ComputeMAC(nil, kh)
		require.NoError(t, err)
		require.NotEmpty(t, macBytes)
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
	recipientKeyHandle, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
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
	require.EqualError(t, err, "unwrapKey: deriveKEKAndUnwrap: bad key handle format")

	// test UnwrapKey with ECDHES key but different curve
	ecdh384Key, err := keyset.NewHandle(ecdh.NISTP384ECDHKWKeyTemplate())
	require.NoError(t, err)

	_, err = c.UnwrapKey(wrappedKey, ecdh384Key)
	require.EqualError(t, err, "unwrapKey: deriveKEKAndUnwrap: error ECDH-ES kek derivation: deriveESKEKForUnwrap:"+
		" error: deriveESWithECKeyForUnwrap: recipient and ephemeral keys are not on the same curve")

	// test UnwrapKey with wrappedKey using different algorithm
	origAlg := wrappedKey.Alg
	wrappedKey.Alg = "badAlg"
	_, err = c.UnwrapKey(wrappedKey, recipientKeyHandle)
	require.EqualError(t, err, "unwrapKey: deriveKEKAndUnwrap: unsupported JWE KW Alg 'badAlg'")

	wrappedKey.Alg = origAlg

	// finally test with valid wrappedKey and recipientKey
	uCEK, err := c.UnwrapKey(wrappedKey, recipientKeyHandle) // UnwrapKey will extract private key from recipientKey
	require.NoError(t, err)
	require.EqualValues(t, cek, uCEK)
}

func TestCrypto_ECDHES_Wrap_Unwrap_ForAllKeyTypes(t *testing.T) {
	tests := []struct {
		tcName   string
		keyTempl *tinkpb.KeyTemplate
		kwAlg    string
		keyType  string
		keyCurve string
		useXC20P bool
		senderKT *tinkpb.KeyTemplate
		err      string
	}{
		{
			tcName:   "key wrap using ECDH-ES with NIST P-256 key and A256GCM kw",
			keyTempl: ecdh.NISTP256ECDHKWKeyTemplate(),
			kwAlg:    ECDHESA256KWAlg,
			keyType:  ecdhpb.KeyType_EC.String(),
			keyCurve: elliptic.P256().Params().Name,
		},
		{
			tcName:   "key wrap using ECDH-ES with NIST P-384 key and A256GCM kw",
			keyTempl: ecdh.NISTP384ECDHKWKeyTemplate(),
			kwAlg:    ECDHESA256KWAlg,
			keyType:  ecdhpb.KeyType_EC.String(),
			keyCurve: elliptic.P384().Params().Name,
		},
		{
			tcName:   "key wrap using ECDH-ES with NIST P-521 key and A256GCM kw",
			keyTempl: ecdh.NISTP521ECDHKWKeyTemplate(),
			kwAlg:    ECDHESA256KWAlg,
			keyType:  ecdhpb.KeyType_EC.String(),
			keyCurve: elliptic.P521().Params().Name,
		},
		{
			tcName:   "key wrap using ECDH-ES with X25519 key and A256GCM kw",
			keyTempl: ecdh.X25519ECDHKWKeyTemplate(),
			kwAlg:    ECDHESA256KWAlg,
			keyType:  ecdhpb.KeyType_OKP.String(),
			keyCurve: "X25519",
		},
		{
			tcName:   "key wrap using ECDH-ES with NIST P-256 key and XC20P kw",
			keyTempl: ecdh.NISTP256ECDHKWKeyTemplate(),
			kwAlg:    ECDHESXC20PKWAlg,
			keyType:  ecdhpb.KeyType_EC.String(),
			keyCurve: elliptic.P256().Params().Name,
			useXC20P: true,
		},
		{
			tcName:   "key wrap using ECDH-ES with NIST P-384 key and XC20P kw",
			keyTempl: ecdh.NISTP384ECDHKWKeyTemplate(),
			kwAlg:    ECDHESXC20PKWAlg,
			keyType:  ecdhpb.KeyType_EC.String(),
			keyCurve: elliptic.P384().Params().Name,
			useXC20P: true,
		},
		{
			tcName:   "key wrap using ECDH-ES with NIST P-521 key and XC20P kw",
			keyTempl: ecdh.NISTP521ECDHKWKeyTemplate(),
			kwAlg:    ECDHESXC20PKWAlg,
			keyType:  ecdhpb.KeyType_EC.String(),
			keyCurve: elliptic.P521().Params().Name,
			useXC20P: true,
		},
		{
			tcName:   "key wrap using ECDH-ES with X25519 key and XC20P kw",
			keyTempl: ecdh.X25519ECDHKWKeyTemplate(),
			kwAlg:    ECDHESXC20PKWAlg,
			keyType:  ecdhpb.KeyType_OKP.String(),
			keyCurve: "X25519",
			useXC20P: true,
		},
		{
			tcName:   "key wrap using ECDH-1PU with NIST P-256 key and A128GCM kw",
			keyTempl: ecdh.NISTP256ECDHKWKeyTemplate(),
			kwAlg:    ECDH1PUA128KWAlg,
			keyType:  ecdhpb.KeyType_EC.String(),
			keyCurve: elliptic.P256().Params().Name,
			senderKT: ecdh.NISTP256ECDHKWKeyTemplate(),
		},
		{
			tcName:   "key wrap using ECDH-1PU with NIST P-384 key and A192GCM kw",
			keyTempl: ecdh.NISTP384ECDHKWKeyTemplate(),
			kwAlg:    ECDH1PUA192KWAlg,
			keyType:  ecdhpb.KeyType_EC.String(),
			keyCurve: elliptic.P384().Params().Name,
			senderKT: ecdh.NISTP384ECDHKWKeyTemplate(),
		},
		{
			tcName:   "key wrap using ECDH-1PU with NIST P-521 key and A256GCM kw",
			keyTempl: ecdh.NISTP521ECDHKWKeyTemplate(),
			kwAlg:    ECDH1PUA256KWAlg,
			keyType:  ecdhpb.KeyType_EC.String(),
			keyCurve: elliptic.P521().Params().Name,
			senderKT: ecdh.NISTP521ECDHKWKeyTemplate(),
		},
		{
			tcName:   "key wrap using ECDH-1PU with NIST P-384 key and A256GCM kw",
			keyTempl: ecdh.NISTP384ECDHKWKeyTemplate(),
			kwAlg:    ECDH1PUA256KWAlg,
			keyType:  ecdhpb.KeyType_EC.String(),
			keyCurve: elliptic.P384().Params().Name,
			senderKT: ecdh.NISTP384ECDHKWKeyTemplate(),
		},
		{
			tcName:   "key wrap using ECDH-1PU with NIST P-521 key and A256GCM kw",
			keyTempl: ecdh.NISTP521ECDHKWKeyTemplate(),
			kwAlg:    ECDH1PUA256KWAlg,
			keyType:  ecdhpb.KeyType_EC.String(),
			keyCurve: elliptic.P521().Params().Name,
			senderKT: ecdh.NISTP521ECDHKWKeyTemplate(),
		},
		{
			tcName:   "key wrap using ECDH-1PU with X25519 key and A256GCM kw",
			keyTempl: ecdh.X25519ECDHKWKeyTemplate(),
			kwAlg:    ECDH1PUA256KWAlg,
			keyType:  ecdhpb.KeyType_OKP.String(),
			keyCurve: "X25519",
			senderKT: ecdh.X25519ECDHKWKeyTemplate(),
		},
		{
			tcName:   "key wrap using ECDH-1PU with NIST P-256 key and XC20P kw",
			keyTempl: ecdh.NISTP256ECDHKWKeyTemplate(),
			kwAlg:    ECDH1PUXC20PKWAlg,
			keyType:  ecdhpb.KeyType_EC.String(),
			keyCurve: elliptic.P256().Params().Name,
			senderKT: ecdh.NISTP256ECDHKWKeyTemplate(),
			useXC20P: true,
		},
		{
			tcName:   "key wrap using ECDH-1PU with NIST P-384 key and XC20P kw",
			keyTempl: ecdh.NISTP384ECDHKWKeyTemplate(),
			kwAlg:    ECDH1PUXC20PKWAlg,
			keyType:  ecdhpb.KeyType_EC.String(),
			keyCurve: elliptic.P384().Params().Name,
			senderKT: ecdh.NISTP384ECDHKWKeyTemplate(),
			useXC20P: true,
		},
		{
			tcName:   "key wrap using ECDH-1PU with NIST P-521 key and XC20P kw",
			keyTempl: ecdh.NISTP521ECDHKWKeyTemplate(),
			kwAlg:    ECDH1PUXC20PKWAlg,
			keyType:  ecdhpb.KeyType_EC.String(),
			keyCurve: elliptic.P521().Params().Name,
			senderKT: ecdh.NISTP521ECDHKWKeyTemplate(),
			useXC20P: true,
		},
		{
			tcName:   "key wrap using ECDH-1PU with X25519 key and XC20P kw",
			keyTempl: ecdh.X25519ECDHKWKeyTemplate(),
			kwAlg:    ECDH1PUXC20PKWAlg,
			keyType:  ecdhpb.KeyType_OKP.String(),
			keyCurve: "X25519",
			senderKT: ecdh.X25519ECDHKWKeyTemplate(),
			useXC20P: true,
		},
	}

	c, err := New()
	require.NoError(t, err)

	apu := random.GetRandomBytes(uint32(10)) // or sender name
	apv := random.GetRandomBytes(uint32(10)) // or recipient name

	for _, tt := range tests {
		tc := tt
		t.Run("Test "+tc.tcName, func(t *testing.T) {
			keySize := aesCEKSize1PU(tc.kwAlg)

			cek := random.GetRandomBytes(uint32(keySize))
			recipientKeyHandle, err := keyset.NewHandle(tc.keyTempl)
			require.NoError(t, err)

			recipientKey, err := keyio.ExtractPrimaryPublicKey(recipientKeyHandle)
			require.NoError(t, err)

			var senderKH *keyset.Handle

			var wrapKeyOtps []cryptoapi.WrapKeyOpts
			if tc.useXC20P {
				// WithXC20OKW option used for WrapKey() only. UnwrapKey() does not check this option, it checks kwAlg.
				wrapKeyOtps = append(wrapKeyOtps, cryptoapi.WithXC20PKW())
			}

			if tc.senderKT != nil {
				senderKH, err = keyset.NewHandle(tc.senderKT)
				require.NoError(t, err)

				wrapKeyOtps = append(wrapKeyOtps, cryptoapi.WithSender(senderKH))
			}

			wrappedKey, err := c.WrapKey(cek, apu, apv, recipientKey, wrapKeyOtps...)
			require.NoError(t, err)
			require.NotEmpty(t, wrappedKey.EncryptedCEK)
			require.NotEmpty(t, wrappedKey.EPK)
			require.EqualValues(t, wrappedKey.APU, apu)
			require.EqualValues(t, wrappedKey.APV, apv)
			require.Equal(t, tc.kwAlg, wrappedKey.Alg)
			require.Equal(t, tc.keyCurve, wrappedKey.EPK.Curve)
			require.Equal(t, tc.keyType, wrappedKey.EPK.Type)

			if senderKH != nil {
				var senderPubKey *cryptoapi.PublicKey

				// mimic recipient side (by using sender public key for unwrapping instead of the private key)
				senderPubKey, err = keyio.ExtractPrimaryPublicKey(senderKH)
				require.NoError(t, err)

				// reset wrapKeyOpts because UnwrapKey only uses WithSender() option.
				wrapKeyOtps = []cryptoapi.WrapKeyOpts{cryptoapi.WithSender(senderPubKey)}
			}

			uCEK, err := c.UnwrapKey(wrappedKey, recipientKeyHandle, wrapKeyOtps...)
			require.NoError(t, err)
			require.EqualValues(t, cek, uCEK)
		})
	}
}

func TestCrypto_ECDH1PU_Wrap_Unwrap_Key(t *testing.T) {
	recipientKeyHandle, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
	require.NoError(t, err)

	recipientKey, err := keyio.ExtractPrimaryPublicKey(recipientKeyHandle)
	require.NoError(t, err)

	senderKH, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
	require.NoError(t, err)

	c, err := New()
	require.NoError(t, err)

	cek := random.GetRandomBytes(uint32(crypto.DefKeySize * 2))
	apu := random.GetRandomBytes(uint32(10)) // or sender name
	apv := random.GetRandomBytes(uint32(10)) // or recipient name

	// test with bad senderKH value
	_, err = c.WrapKey(cek, apu, apv, recipientKey, cryptoapi.WithSender("badKey"))
	require.EqualError(t, err, "wrapKey: deriveKEKAndWrap: error ECDH-1PU kek derivation: derive1PUKEK: EC key"+
		" derivation error derive1PUWithECKey: failed to retrieve sender key: ksToPrivateECDSAKey: bad key handle "+
		"format")

	// now test WrapKey with good key
	wrappedKey, err := c.WrapKey(cek, apu, apv, recipientKey, cryptoapi.WithSender(senderKH))
	require.NoError(t, err)
	require.NotEmpty(t, wrappedKey.EncryptedCEK)
	require.NotEmpty(t, wrappedKey.EPK)
	require.EqualValues(t, wrappedKey.APU, apu)
	require.EqualValues(t, wrappedKey.APV, apv)
	require.Equal(t, wrappedKey.Alg, ECDH1PUA256KWAlg)

	// test with valid wrappedKey, senderKH (public key) and recipientKey
	senderPubKH, err := senderKH.Public()
	require.NoError(t, err)

	uCEK, err := c.UnwrapKey(wrappedKey, recipientKeyHandle, cryptoapi.WithSender(senderPubKH))
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

	uCEK, err = c.UnwrapKey(wrappedKey, recipientKeyHandle, cryptoapi.WithSender(senderECPubKey))
	require.NoError(t, err)
	require.EqualValues(t, cek, uCEK)
}

func TestCrypto_ECDH1PU_Wrap_Unwrap_Key_Using_CryptoPubKey_as_SenderKey(t *testing.T) {
	recipientKeyHandle, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
	require.NoError(t, err)

	recipientKey, err := keyio.ExtractPrimaryPublicKey(recipientKeyHandle)
	require.NoError(t, err)

	senderKH, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
	require.NoError(t, err)

	c, err := New()
	require.NoError(t, err)

	cek := random.GetRandomBytes(uint32(crypto.DefKeySize * 2))
	apu := random.GetRandomBytes(uint32(10)) // or sender name
	apv := random.GetRandomBytes(uint32(10)) // or recipient name

	// extract sender public key as crypto.Public key to be used in WithSender()
	senderPubKey, err := keyio.ExtractPrimaryPublicKey(senderKH)
	require.NoError(t, err)

	// test WrapKey with extacted crypto.PublicKey above directly
	// WrapKey() only accepts senderKH as keyset.Handle because it will use its private key.
	wrappedKey, err := c.WrapKey(cek, apu, apv, recipientKey, cryptoapi.WithSender(senderKH))
	require.NoError(t, err)
	require.NotEmpty(t, wrappedKey.EncryptedCEK)
	require.NotEmpty(t, wrappedKey.EPK)
	require.EqualValues(t, wrappedKey.APU, apu)
	require.EqualValues(t, wrappedKey.APV, apv)
	require.Equal(t, wrappedKey.Alg, ECDH1PUA256KWAlg)

	// UnwrapKey require sender public key used here or keyset.Handle which was tested in the previous function above
	uCEK, err := c.UnwrapKey(wrappedKey, recipientKeyHandle, cryptoapi.WithSender(senderPubKey))
	require.NoError(t, err)
	require.EqualValues(t, cek, uCEK)

	crv, err := hybrid.GetCurve(senderPubKey.Curve)
	require.NoError(t, err)

	senderECPubKey := &ecdsa.PublicKey{
		Curve: crv,
		X:     new(big.Int).SetBytes(senderPubKey.X),
		Y:     new(big.Int).SetBytes(senderPubKey.Y),
	}

	uCEK, err = c.UnwrapKey(wrappedKey, recipientKeyHandle, cryptoapi.WithSender(senderECPubKey))
	require.NoError(t, err)
	require.EqualValues(t, cek, uCEK)
}

func TestBBSCrypto_SignVerify_DeriveProofVerifyProof(t *testing.T) {
	c := Crypto{}
	msg := [][]byte{
		[]byte(testMessage + "0"), []byte(testMessage + "1"), []byte(testMessage + "2"),
		[]byte(testMessage + "3"), []byte(testMessage + "4"), []byte(testMessage + "5"),
	}

	var (
		s     []byte
		pubKH *keyset.Handle
		badKH *keyset.Handle
	)

	t.Run("test with BBS+ signature", func(t *testing.T) {
		kh, err := keyset.NewHandle(bbs.BLS12381G2KeyTemplate())
		require.NoError(t, err)

		badKH, err = keyset.NewHandle(tinkaead.KMSEnvelopeAEADKeyTemplate("babdUrl", nil))
		require.NoError(t, err)

		s, err = c.SignMulti(msg, kh)
		require.NoError(t, err)

		// sign with nil key handle - should fail
		_, err = c.SignMulti(msg, nil)
		require.EqualError(t, err, errBadKeyHandleFormat.Error())

		// sign with bad key type - should fail
		_, err = c.SignMulti(msg, "bad key type")
		require.EqualError(t, err, errBadKeyHandleFormat.Error())

		// sign with empty messages - should fail
		_, err = c.SignMulti([][]byte{}, kh)
		require.EqualError(t, err, "BBS+ sign msg: messages are not defined")

		// sign with bad key handle - should fail
		_, err = c.SignMulti(msg, badKH)
		require.Error(t, err)

		// get corresponding public key handle to verify
		pubKH, err = kh.Public()
		require.NoError(t, err)

		err = c.VerifyMulti(msg, s, nil)
		require.EqualError(t, err, errBadKeyHandleFormat.Error())

		err = c.VerifyMulti(msg, s, "bad key type")
		require.EqualError(t, err, errBadKeyHandleFormat.Error())

		err = c.VerifyMulti(msg, s, badKH)
		require.Error(t, err)

		err = c.VerifyMulti([][]byte{}, s, pubKH)
		require.EqualError(t, err, "BBS+ verify msg: bbs_verifier_factory: invalid signature")

		err = c.VerifyMulti(msg, s, pubKH)
		require.NoError(t, err)
	})

	require.NotEmpty(t, s)

	t.Run("test with BBS+ proof", func(t *testing.T) {
		revealedIndexes := []int{0, 2}
		nonce := make([]byte, 32)

		_, err := rand.Read(nonce)
		require.NoError(t, err)

		_, err = c.DeriveProof(msg, s, nonce, revealedIndexes, nil)
		require.EqualError(t, err, errBadKeyHandleFormat.Error())

		_, err = c.DeriveProof(msg, s, nonce, revealedIndexes, "bad key type")
		require.EqualError(t, err, errBadKeyHandleFormat.Error())

		_, err = c.DeriveProof(msg, s, nonce, revealedIndexes, badKH)
		require.Error(t, err)

		_, err = c.DeriveProof([][]byte{}, s, nonce, revealedIndexes, pubKH)
		require.EqualError(t, err, "verify proof msg: bbs_verifier_factory: invalid signature proof")

		proof, err := c.DeriveProof(msg, s, nonce, revealedIndexes, pubKH)
		require.NoError(t, err)

		err = c.VerifyProof([][]byte{msg[0], msg[2]}, proof, nonce, nil)
		require.EqualError(t, err, errBadKeyHandleFormat.Error())

		err = c.VerifyProof([][]byte{msg[0], msg[2]}, proof, nonce, "bad key type")
		require.EqualError(t, err, errBadKeyHandleFormat.Error())

		err = c.VerifyProof([][]byte{msg[0], msg[2]}, proof, nonce, badKH)
		require.Error(t, err)

		err = c.VerifyProof([][]byte{msg[3], msg[4]}, proof, nonce, pubKH)
		require.EqualError(t, err, "verify proof msg: bbs_verifier_factory: invalid signature proof")

		err = c.VerifyProof([][]byte{msg[0], msg[2]}, proof, nonce, pubKH)
		require.NoError(t, err)
	})
}
