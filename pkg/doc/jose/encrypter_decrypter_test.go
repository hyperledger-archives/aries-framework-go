/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jose

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/subtle"
	"github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/api"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh1pu"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdhes"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/keyio"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
)

func TestJWEEncryptRoundTrip(t *testing.T) {
	_, err := NewJWEEncrypt("", "", "", nil, nil)
	require.EqualError(t, err, "empty recipientsPubKeys list",
		"NewJWEEncrypt should fail with empty recipientPubKeys")

	recECKeys, recKHs := createRecipients(t, 20)

	_, err = NewJWEEncrypt("", "", "", nil, recECKeys)
	require.EqualError(t, err, "encryption algorithm '' not supported",
		"NewJWEEncrypt should fail with empty encAlg")

	jweEncrypter, err := NewJWEEncrypt(A256GCM, composite.DIDCommEncType, "", nil, recECKeys)
	require.NoError(t, err, "NewJWEEncrypt should not fail with non empty recipientPubKeys")

	pt := []byte("some msg")
	jwe, err := jweEncrypter.EncryptWithAuthData(pt, []byte("aad value"))
	require.NoError(t, err)
	require.Equal(t, len(recECKeys), len(jwe.Recipients))

	serializedJWE, err := jwe.FullSerialize(json.Marshal)
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
		jweDecrypter := NewJWEDecrypt(nil, recKHs[0])

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
		require.EqualError(t, err, "jwedecrypt: jwe is missing encryption algorithm 'enc' header")

		badJWE.ProtectedHeaders = map[string]interface{}{
			HeaderEncryption: "badEncHeader",
			HeaderType:       "test",
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
				Header: &RecipientHeaders{
					EPK: []byte("somerawbytes"),
				},
			},
			{
				EncryptedKey: "someOtherKey",
				Header: &RecipientHeaders{
					EPK: []byte("someotherrawbytes"),
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
				Header: &RecipientHeaders{
					EPK: mk,
				},
			},
			{
				EncryptedKey: "someOtherKey",
				Header: &RecipientHeaders{
					EPK: mk,
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
		jweDecrypter = NewJWEDecrypt(nil, aeadKH)

		_, err = jweDecrypter.Decrypt(localJWE)
		require.EqualError(t, err, "ecdhes_factory: decryption failed")
	})

	for _, recKH := range recKHs {
		recipientKH := recKH

		t.Run("Decrypting JWE test success ", func(t *testing.T) {
			jweDecrypter := NewJWEDecrypt(nil, recipientKH)

			var msg []byte

			msg, err = jweDecrypter.Decrypt(localJWE)
			require.NoError(t, err)
			require.EqualValues(t, pt, msg)
		})
	}
}

func TestJWEEncryptRoundTripWithSingleRecipient(t *testing.T) {
	recECKeys, recKHs := createRecipients(t, 1)

	jweEncrypter, err := NewJWEEncrypt(A256GCM, composite.DIDCommEncType, "", nil, recECKeys)
	require.NoError(t, err, "NewJWEEncrypt should not fail with non empty recipientPubKeys")

	pt := []byte("some msg")
	jwe, err := jweEncrypter.Encrypt(pt)
	require.NoError(t, err)
	require.Equal(t, len(recECKeys), len(jwe.Recipients))

	serializedJWE, err := jwe.CompactSerialize(json.Marshal)
	require.NoError(t, err)
	require.NotEmpty(t, serializedJWE)

	// try to deserialize with local package
	localJWE, err := Deserialize(serializedJWE)
	require.NoError(t, err)

	jweDecrypter := NewJWEDecrypt(nil, recKHs[0])

	var msg []byte

	msg, err = jweDecrypter.Decrypt(localJWE)
	require.NoError(t, err)
	require.EqualValues(t, pt, msg)
}

func TestInteropWithGoJoseEncryptAndLocalJoseDecryptUsingCompactSerialize(t *testing.T) {
	recECKeys, recKHs := createRecipients(t, 1)
	gjRecipients := convertToGoJoseRecipients(t, recECKeys)

	eo := &jose.EncrypterOptions{}
	gjEncrypter, err := jose.NewEncrypter(jose.A256GCM, gjRecipients[0],
		eo.WithType("didcomm-envelope-enc"))
	require.NoError(t, err)

	pt := []byte("Test secret message")

	// encrypt pt using go-jose encryption
	gjJWEEncrypter, err := gjEncrypter.Encrypt(pt)
	require.NoError(t, err)

	// get go-jose serialized JWE
	gjSerializedJWE, err := gjJWEEncrypter.CompactSerialize()
	require.NoError(t, err)

	// deserialize using local jose package
	localJWE, err := Deserialize(gjSerializedJWE)
	require.NoError(t, err)

	for i, recKH := range recKHs {
		recipientKH := recKH

		t.Run(fmt.Sprintf("%d: Decrypting JWE message encrypted by go-jose test success", i), func(t *testing.T) {
			jweDecrypter := NewJWEDecrypt(nil, recipientKH)

			var msg []byte

			msg, err = jweDecrypter.Decrypt(localJWE)
			require.NoError(t, err)
			require.EqualValues(t, pt, msg)
		})
	}
}

func TestInteropWithGoJoseEncryptAndLocalJoseDecrypt(t *testing.T) {
	recECKeys, recKHs := createRecipients(t, 3)
	gjRecipients := convertToGoJoseRecipients(t, recECKeys)

	eo := &jose.EncrypterOptions{}
	gjEncrypter, err := jose.NewMultiEncrypter(jose.A256GCM, gjRecipients,
		eo.WithType("didcomm-envelope-enc"))
	require.NoError(t, err)

	pt := []byte("Test secret message")
	aad := []byte("Test some auth data")

	// encrypt pt using go-jose encryption
	gjJWEEncrypter, err := gjEncrypter.EncryptWithAuthData(pt, aad)
	require.NoError(t, err)

	// get go-jose serialized JWE
	gjSerializedJWE := gjJWEEncrypter.FullSerialize()

	// deserialize using local jose package
	localJWE, err := Deserialize(gjSerializedJWE)
	require.NoError(t, err)

	for i, recKH := range recKHs {
		recipientKH := recKH

		t.Run(fmt.Sprintf("%d: Decrypting JWE message encrypted by go-jose test success", i), func(t *testing.T) {
			jweDecrypter := NewJWEDecrypt(nil, recipientKH)

			var msg []byte

			msg, err = jweDecrypter.Decrypt(localJWE)
			require.NoError(t, err)
			require.EqualValues(t, pt, msg)
		})
	}
}

func TestInteropWithLocalJoseEncryptAndGoJoseDecrypt(t *testing.T) {
	// get two generated recipient Tink keys
	recECKeys, _ := createRecipients(t, 2)
	// create a normal recipient key (not using Tink)
	rec3PrivKey, err := ecdsa.GenerateKey(subtle.GetCurve(recECKeys[0].Curve), rand.Reader)
	require.NoError(t, err)

	// add third key to recECKeys
	recECKeys = append(recECKeys, &composite.PublicKey{
		X:     rec3PrivKey.PublicKey.X.Bytes(),
		Y:     rec3PrivKey.PublicKey.Y.Bytes(),
		Curve: rec3PrivKey.PublicKey.Curve.Params().Name,
		Type:  "EC",
	})

	// encrypt using local jose package
	jweEncrypter, err := NewJWEEncrypt(A256GCM, composite.DIDCommEncType, "", nil, recECKeys)
	require.NoError(t, err, "NewJWEEncrypt should not fail with non empty recipientPubKeys")

	pt := []byte("some msg")
	jwe, err := jweEncrypter.EncryptWithAuthData(pt, []byte("aad value"))
	require.NoError(t, err)
	require.Equal(t, len(recECKeys), len(jwe.Recipients))

	serializedJWE, err := jwe.FullSerialize(json.Marshal)
	require.NoError(t, err)

	// now parse serializedJWE using go-jose
	gjParsedJWE, err := jose.ParseEncrypted(serializedJWE)
	require.NoError(t, err)

	// Decrypt with third recipient's private key (non Tink key)
	i, _, msg, err := gjParsedJWE.DecryptMulti(rec3PrivKey)
	require.NoError(t, err)
	require.EqualValues(t, pt, msg)

	// the third recipient's index is 2
	require.Equal(t, 2, i)
}

func TestInteropWithLocalJoseEncryptAndGoJoseDecryptUsingCompactSerialization(t *testing.T) {
	var recECKeys []*composite.PublicKey
	// create a normal recipient key (not using Tink)
	recPrivKey, err := ecdsa.GenerateKey(subtle.GetCurve("NIST_P256"), rand.Reader)
	require.NoError(t, err)

	// add third key to recECKeys
	recECKeys = append(recECKeys, &composite.PublicKey{
		X:     recPrivKey.PublicKey.X.Bytes(),
		Y:     recPrivKey.PublicKey.Y.Bytes(),
		Curve: recPrivKey.PublicKey.Curve.Params().Name,
		Type:  "EC",
	})

	// encrypt using local jose package
	jweEncrypter, err := NewJWEEncrypt(A256GCM, composite.DIDCommEncType, "", nil, recECKeys)
	require.NoError(t, err, "NewJWEEncrypt should not fail with non empty recipientPubKeys")

	pt := []byte("some msg")
	jwe, err := jweEncrypter.Encrypt(pt)
	require.NoError(t, err)
	require.Equal(t, len(recECKeys), len(jwe.Recipients))

	serializedJWE, err := jwe.CompactSerialize(json.Marshal)
	require.NoError(t, err)

	// now parse serializedJWE using go-jose
	gjParsedJWE, err := jose.ParseEncrypted(serializedJWE)
	require.NoError(t, err)

	// Decrypt with recipient's private key
	msg, err := gjParsedJWE.Decrypt(recPrivKey)
	require.NoError(t, err)
	require.EqualValues(t, pt, msg)
}

func convertToGoJoseRecipients(t *testing.T, keys []*composite.PublicKey) []jose.Recipient {
	t.Helper()

	var joseRecipients []jose.Recipient

	for _, key := range keys {
		c := subtle.GetCurve(key.Curve)
		gjKey := jose.Recipient{
			Algorithm: jose.ECDH_ES_A256KW,
			Key: &ecdsa.PublicKey{
				Curve: c,
				X:     new(big.Int).SetBytes(key.X),
				Y:     new(big.Int).SetBytes(key.Y),
			},
		}

		joseRecipients = append(joseRecipients, gjKey)
	}

	return joseRecipients
}

// createRecipients and return their public key and keyset.Handle.
func createRecipients(t *testing.T, numberOfEntities int) ([]*composite.PublicKey, []*keyset.Handle) {
	return createECDHEntities(t, numberOfEntities, true)
}

func createECDHEntities(t *testing.T, numberOfEntities int, isECDHES bool) ([]*composite.PublicKey, []*keyset.Handle) {
	t.Helper()

	var (
		r   []*composite.PublicKey
		rKH []*keyset.Handle
	)

	for i := 0; i < numberOfEntities; i++ {
		mrKey, kh := createAndMarshalEntityKey(t, isECDHES)
		ecPubKey := new(composite.PublicKey)
		err := json.Unmarshal(mrKey, ecPubKey)
		require.NoError(t, err)

		r = append(r, ecPubKey)
		rKH = append(rKH, kh)
	}

	return r, rKH
}

// createAndMarshalEntityKey creates a new recipient keyset.Handle, extracts public key, marshals it and returns
// both marshalled public key and original recipient keyset.Handle.
func createAndMarshalEntityKey(t *testing.T, isECDHES bool) ([]byte, *keyset.Handle) {
	t.Helper()

	tmpl := ecdhes.ECDHES256KWAES256GCMKeyTemplate()

	if !isECDHES {
		tmpl = ecdh1pu.ECDH1PU256KWAES256GCMKeyTemplate()
	}

	kh, err := keyset.NewHandle(tmpl)
	require.NoError(t, err)

	pubKH, err := kh.Public()
	require.NoError(t, err)

	buf := new(bytes.Buffer)
	pubKeyWriter := keyio.NewWriter(buf)
	require.NotEmpty(t, pubKeyWriter)

	err = pubKH.WriteWithNoSecrets(pubKeyWriter)
	require.NoError(t, err)

	return buf.Bytes(), kh
}

func TestFailConvertRecKeyToMarshalledJWK(t *testing.T) {
	recKey := &composite.RecipientWrappedKey{
		EPK: composite.PublicKey{
			Curve: "badCurveName",
		},
	}

	_, err := convertRecKeyToMarshalledJWK(recKey)
	require.EqualError(t, err, "unsupported curve")
}

func TestFailNewJWEEncrypt(t *testing.T) {
	recipients := []*composite.PublicKey{
		{
			Curve: "badCurveName",
		},
	}

	_, err := NewJWEEncrypt(A256GCM, composite.DIDCommEncType, "", nil, recipients)
	require.EqualError(t, err, "curve badCurveName not supported")

	recipients, recsKH := createRecipients(t, 2)

	_, err = NewJWEEncrypt(A256GCM, composite.DIDCommEncType, "", recsKH[0], recipients)
	require.EqualError(t, err, "senderKID is required with senderKH")

	// sender key set handle is not ECDH1PU type - should fail
	_, err = NewJWEEncrypt(A256GCM, composite.DIDCommEncType, "1234", recsKH[0], recipients)
	require.EqualError(t, err, "AddRecipientsKeys: extract keyset failed: AddRecipientsKeys: primary "+
		"key not found in keyset")
}

func TestECDH1PU(t *testing.T) {
	recipients, recKHs := createECDHEntities(t, 2, false)
	senders, senderKHs := createECDHEntities(t, 1, false)
	kh := senderKHs[0]
	mockSenderID := "1234"

	senderPubKey, err := json.Marshal(senders[0])
	require.NoError(t, err)

	jweEnc, err := NewJWEEncrypt(A256GCM, composite.DIDCommEncType, mockSenderID, kh, recipients)
	require.NoError(t, err)
	require.NotEmpty(t, jweEnc)

	mockStoreMap := make(map[string][]byte)
	mockStore := &mockstorage.MockStore{
		Store: mockStoreMap,
	}

	pt := []byte("plaintext payload")

	// test JWEEncrypt for ECDH1PU
	jwe, err := jweEnc.Encrypt(pt)
	require.NoError(t, err)

	serializedJWE, err := jwe.FullSerialize(json.Marshal)
	require.NoError(t, err)
	require.NotEmpty(t, serializedJWE)

	localJWE, err := Deserialize(serializedJWE)
	require.NoError(t, err)

	t.Run("Decrypting JWE message without sender key in the third party store should fail", func(t *testing.T) {
		jd := NewJWEDecrypt(mockStore, recKHs[0])
		require.NotEmpty(t, jd)

		_, err = jd.Decrypt(localJWE)
		require.EqualError(t, err, "jwedecrypt: failed to add sender key: failed to get sender key from DB:"+
			" data not found")
	})

	// add sender pubkey into the recipient's mock store to prepare for a successful JWEDecrypt() for each recipient
	mockStoreMap[mockSenderID] = senderPubKey

	for i, recKH := range recKHs {
		recipientKH := recKH

		t.Run(fmt.Sprintf("%d: Decrypting JWE message test success", i), func(t *testing.T) {
			jd := NewJWEDecrypt(mockStore, recipientKH)
			require.NotEmpty(t, jd)

			var msg []byte

			msg, err = jd.Decrypt(localJWE)
			require.NoError(t, err)
			require.EqualValues(t, pt, msg)
		})
	}

	t.Run("addSender failure due to missing store test case", func(t *testing.T) {
		jd := NewJWEDecrypt(nil, recKHs[0])
		require.NotEmpty(t, jd)

		err := jd.addSenderKey("abc")
		require.EqualError(t, err, "unable to decrypt JWE with 'skid' header, third party key store is nil")
	})

	t.Run("addSender failure due to invalid sender key test case", func(t *testing.T) {
		jd := NewJWEDecrypt(mockStore, recKHs[0])
		require.NotEmpty(t, jd)

		senderKey := senders[0]
		senderKey.Curve = "invalidCurve"

		mSenderKey, err := json.Marshal(senderKey)
		require.NoError(t, err)

		mockStoreMap["invalidKey"] = mSenderKey
		err = jd.addSenderKey("invalidKey")
		require.EqualError(t, err, fmt.Sprintf("AddSenderKey: failed to convert senderKey to proto: curve %s"+
			" not supported", senderKey.Curve))
	})
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
		getPrimitive: getECDHESEncPrimitive,
	}

	_, err = jweEncrypter.Encrypt([]byte{})
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

	_, err := jweEncrypter.Encrypt([]byte{})
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

	_, err := jweEncrypter.Encrypt([]byte{})
	require.EqualError(t, err, "jweencrypt: unmarshal encrypted data failed: invalid character 'b' "+
		"looking for beginning of value")
}

type mockCompositeEncrypt struct {
	EncryptValue string
	EncryptError error
}

// Encrypt mocks Encrypt function.
func (e *mockCompositeEncrypt) Encrypt(plainText, aad []byte) ([]byte, error) {
	return []byte(e.EncryptValue), e.EncryptError
}
