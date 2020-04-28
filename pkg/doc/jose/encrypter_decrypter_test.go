/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jose

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/api"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdhes"
	ecdhessubtle "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdhes/subtle"
)

func TestJWEEncryptRoundTrip(t *testing.T) {
	_, err := NewJWEEncrypt("", nil)
	require.EqualError(t, err, "empty recipientsPubKeys list",
		"NewJWEEncrypt should fail with empty recipientPubKeys")

	recECKeys, recKHs := createRecipients(t, 20)

	_, err = NewJWEEncrypt("", recECKeys)
	require.EqualError(t, err, "encryption algorithm '' not supported",
		"NewJWEEncrypt should fail with empty encAlg")

	jweEncrypter, err := NewJWEEncrypt(A256GCM, recECKeys)
	require.NoError(t, err, "NewJWEEncrypt should not fail with non empty recipientPubKeys")

	pt := []byte("some msg")
	jwe, err := jweEncrypter.Encrypt(pt, []byte("aad value"))
	require.NoError(t, err)
	require.Equal(t, len(recECKeys), len(jwe.Recipients))

	serializedJWE, err := jwe.Serialize(json.Marshal)
	require.NoError(t, err)
	require.NotEmpty(t, serializedJWE)

	// try to deserialize with go-jose (can't decrypt in go-jose since private key is protected by Tink)
	joseJWE, err := jose.ParseEncrypted(serializedJWE)
	require.NoError(t, err)
	require.NotEmpty(t, joseJWE)

	// try to deserialize with local package
	localJWE, err := Deserialize(serializedJWE)
	require.NoError(t, err)

	t.Run("Decrypting JWE tests failures", func(t *testing.T) {
		jweDecrypter := NewJWEDecrypt(recKHs[0])

		// decrypt empty JWE
		_, err = jweDecrypter.Decrypt(nil)
		require.EqualError(t, err, "jwedecrypt: jwe is nil")

		var badJWE *JSONWebEncryption

		badJWE, err = Deserialize(serializedJWE)
		require.NoError(t, err)

		ph := badJWE.ProtectedHeaders
		badJWE.ProtectedHeaders = nil

		// decrypt JWE with empty ProtectHeaders
		_, err = jweDecrypter.Decrypt(badJWE)
		require.EqualError(t, err, "jwedecrypt: jwe is missing alg header")

		badJWE.ProtectedHeaders = map[string]interface{}{
			HeaderEncryption: "badEncHeader",
		}

		// decrypt JWE with bad Enc header value
		_, err = jweDecrypter.Decrypt(badJWE)
		require.EqualError(t, err, "jwedecrypt: encryption algorithm 'badEncHeader' not supported")

		badJWE.ProtectedHeaders = ph

		// decrypt JWE with invalid recipient key
		recipients := badJWE.Recipients

		badJWE.Recipients = []*Recipient{
			{
				EncryptedKey: "someKey",
				Header: RecipientHeaders{
					EPK: "somerawbytes",
				},
			},
		}

		_, err = jweDecrypter.Decrypt(badJWE)
		require.EqualError(t, err, "jwedecrypt: failed to build encryptedData for Decrypt(): unable to read "+
			"JWK: invalid character 's' looking for beginning of value")

		// decrypt JWE with unsupported recipient key
		var privKey *rsa.PrivateKey

		privKey, err = rsa.GenerateKey(rand.Reader, 2048)

		unsupportedJWK := JWK{
			JSONWebKey: jose.JSONWebKey{
				Key: &privKey.PublicKey,
			},
		}

		var mk []byte

		mk, err = unsupportedJWK.MarshalJSON()
		require.NoError(t, err)

		badJWE.Recipients = []*Recipient{
			{
				EncryptedKey: "someKey",
				Header: RecipientHeaders{
					EPK: string(mk),
				},
			},
		}

		_, err = jweDecrypter.Decrypt(badJWE)
		require.EqualError(t, err, "jwedecrypt: failed to build encryptedData for Decrypt(): unsupported "+
			"recipient key type")

		badJWE.Recipients = recipients
		// finally create Decrypt with bad keyset.Handle and try to Decrypt with invalid Handle
		aeadKT := aead.AES256GCMKeyTemplate()

		var aeadKH *keyset.Handle

		aeadKH, err = keyset.NewHandle(aeadKT)
		require.NoError(t, err)
		jweDecrypter = NewJWEDecrypt(aeadKH)

		_, err = jweDecrypter.Decrypt(localJWE)
		require.EqualError(t, err, "ecdhes_factory: decryption failed")
	})

	for _, recKH := range recKHs {
		recipientKH := recKH

		t.Run("Decrypting JWE test success ", func(t *testing.T) {
			jweDecrypter := NewJWEDecrypt(recipientKH)

			var msg []byte

			msg, err = jweDecrypter.Decrypt(localJWE)
			require.NoError(t, err)
			require.EqualValues(t, pt, msg)
		})
	}
}

// createRecipients and return their public key and keyset.Handle
func createRecipients(t *testing.T, numberOfRecipients int) ([]ecdhessubtle.ECPublicKey, []*keyset.Handle) {
	t.Helper()

	var (
		r   []ecdhessubtle.ECPublicKey
		rKH []*keyset.Handle
	)

	for i := 0; i < numberOfRecipients; i++ {
		mrKey, kh := createAndMarshalRecipient(t)
		ecPubKey := new(ecdhessubtle.ECPublicKey)
		err := json.Unmarshal(mrKey, ecPubKey)
		require.NoError(t, err)

		r = append(r, *ecPubKey)
		rKH = append(rKH, kh)
	}

	return r, rKH
}

// createAndMarshalRecipient creates a new recipient keyset.Handle, extracts public key, marshals it and returns
// both marshalled public key and original recipient keyset.Handle
func createAndMarshalRecipient(t *testing.T) ([]byte, *keyset.Handle) {
	t.Helper()

	kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	pubKH, err := kh.Public()
	require.NoError(t, err)

	buf := new(bytes.Buffer)
	pubKeyWriter := ecdhes.NewWriter(buf)
	require.NotEmpty(t, pubKeyWriter)

	err = pubKH.WriteWithNoSecrets(pubKeyWriter)
	require.NoError(t, err)

	return buf.Bytes(), kh
}

func TestFailConvertRecKeyToMarshalledJWK(t *testing.T) {
	recKey := &ecdhessubtle.RecipientWrappedKey{
		EPK: ecdhessubtle.ECPublicKey{
			Curve: "badCurveName",
		},
	}

	_, err := convertRecKeyToMarshalledJWK(recKey)
	require.EqualError(t, err, "unsupported curve")
}

func TestEmptyComputeAuthData(t *testing.T) {
	protecteHeaders := new(map[string]interface{})
	aad := []byte("")
	_, err := computeAuthData(*protecteHeaders, aad)
	require.NoError(t, err, "computeAuthData with empty protectedHeaders and empty aad should not fail")
}

func TestBadSenderKH(t *testing.T) {
	// create a keyset.Handle that doesn't
	aeadKT := aead.AES256GCMKeyTemplate()
	aeadKH, err := keyset.NewHandle(aeadKT)
	require.NoError(t, err)

	// create jweEncrypter manually with a bad sender type
	jweEncrypter := JWEEncrypt{
		senderKH:     aeadKH,
		getPrimitive: getEncryptionPrimitive,
	}

	_, err = jweEncrypter.Encrypt([]byte{}, []byte{})
	require.EqualError(t, err, "jweencrypt: failed to get encryption primitive: "+
		"keyset.Handle: keyset.Handle: keyset contains a non-private key")
}

func TestBadCryptoEncrypt(t *testing.T) {
	mockEncrypt := &mockCompositeEncrypt{
		EncryptValue: "",
		EncryptError: fmt.Errorf("encryption failed"),
	}

	// create JWEEncryption with above mockEncrypt
	jweEncrypter := JWEEncrypt{
		getPrimitive: func(senderKH *keyset.Handle) (api.CompositeEncrypt, error) {
			return mockEncrypt, nil
		},
	}

	_, err := jweEncrypter.Encrypt([]byte{}, []byte{})
	require.EqualError(t, err, "jweencrypt: failed to Encrypt: encryption failed")
}

func TestCryptoWithBadCipherTextFormatEncrypt(t *testing.T) {
	mockEncrypt := &mockCompositeEncrypt{
		EncryptValue: "badEncryptContent",
		EncryptError: nil,
	}

	// create JWEEncryption with above mockEncrypt
	jweEncrypter := JWEEncrypt{
		getPrimitive: func(senderKH *keyset.Handle) (api.CompositeEncrypt, error) {
			return mockEncrypt, nil
		},
	}

	_, err := jweEncrypter.Encrypt([]byte{}, []byte{})
	require.EqualError(t, err, "jweencrypt: unmarshal encrypted data failed: invalid character 'b' "+
		"looking for beginning of value")
}

type mockCompositeEncrypt struct {
	EncryptValue string
	EncryptError error
}

// Encrypt mocks Encrypt function
func (e *mockCompositeEncrypt) Encrypt(plainText, aad []byte) ([]byte, error) {
	return []byte(e.EncryptValue), e.EncryptError
}
