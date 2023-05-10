/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jose

import (
	"bytes"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/ecdh"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/keyio"
	cryptoapi "github.com/hyperledger/aries-framework-go/spi/crypto"
)

func TestFailConvertRecKeyToMarshalledJWK(t *testing.T) {
	t.Run("test convertRecEPKToMarshalledJWK using EPK with bad curve", func(t *testing.T) {
		recKey := &cryptoapi.RecipientWrappedKey{
			EPK: cryptoapi.PublicKey{
				Curve: "badCurveName",
				Type:  "EC",
			},
		}

		_, err := convertRecEPKToMarshalledJWK(&recKey.EPK)
		require.EqualError(t, err, "unsupported curve")
	})

	t.Run("test convertRecEPKToMarshalledJWK and buildRecipientHeaders using EPK with bad key type", func(t *testing.T) {
		recKey := &cryptoapi.RecipientWrappedKey{
			EPK: cryptoapi.PublicKey{
				Curve: "P-256",
			},
		}

		_, err := convertRecEPKToMarshalledJWK(&recKey.EPK)
		require.EqualError(t, err, "invalid key type")

		_, err = buildRecipientHeaders(recKey, false)
		require.EqualError(t, err, "failed to convert recipient key to marshalled JWK: invalid key type")
	})
}

func TestBuildRecsWithEPKMissingKeyTypeFailure(t *testing.T) {
	recKey := &cryptoapi.RecipientWrappedKey{
		EPK: cryptoapi.PublicKey{
			Curve: "P-256",
		},
	}

	c, err := tinkcrypto.New()
	require.NoError(t, err)

	recipients, recsKH := createRecipients(t, 2)

	enc, err := NewJWEEncrypt(A256GCM, testEncType, testPayloadType,
		"0", recsKH["0"], recipients, c)
	require.NoError(t, err)

	_, _, err = enc.buildRecs([]*cryptoapi.RecipientWrappedKey{recKey}, true)
	require.EqualError(t, err, "failed to convert recipient key to marshalled JWK: invalid key type")
}

func TestBadSenderKeyType(t *testing.T) {
	c, err := tinkcrypto.New()
	require.NoError(t, err)

	// create a keyset.Handle that fails JWE/ECDH primitive execution (must come from an ECDH key template).
	aeadKT := aead.AES256GCMKeyTemplate()
	aeadKH, err := keyset.NewHandle(aeadKT)
	require.NoError(t, err)

	recipients, _ := createRecipients(t, 2)

	// create jweEncrypter manually with a bad sender type
	jweEncrypter := JWEEncrypt{
		skid:           "123",
		senderKH:       aeadKH,
		recipientsKeys: recipients,
		crypto:         c,
		encAlg:         A256GCM,
	}

	_, err = jweEncrypter.Encrypt([]byte{})
	require.EqualError(t, err, "jweencryptWithSender: failed to wrap cek: wrapCEKForRecipientsWithTagAndEPK: "+
		"wrapKey: 1 failed: wrapKey: deriveKEKAndWrap: error ECDH-1PU kek derivation: derive1PUKEK: EC key derivation "+
		"error derive1PUWithECKey: failed to retrieve sender key: ksToPrivateECDSAKey: failed to extract sender key: "+
		"extractPrivKey: can't extract unsupported private key 'type.googleapis.com/google.crypto.tink.AesGcmKey'")
}

func TestMergeSingleRecipientsHeadersFailureWithUnsetCurve(t *testing.T) {
	aad := map[string]string{"enc": "test"}

	mAAD, err := json.Marshal(aad)
	require.NoError(t, err)

	wk := &cryptoapi.RecipientWrappedKey{
		EPK: cryptoapi.PublicKey{Type: "EC"},
	}

	// fail with aad not base64URL encoded
	_, err = mergeSingleRecipientHeaders(wk, []byte("aad not base64URL encoded"), json.Marshal)
	require.EqualError(t, err, "illegal base64 data at input byte 3")

	badAAD := base64.RawURLEncoding.EncodeToString([]byte("aad not a json format"))

	// fail with aad not being a marshalled json
	_, err = mergeSingleRecipientHeaders(wk, []byte(badAAD), json.Marshal)
	require.EqualError(t, err, "invalid character 'a' looking for beginning of value")

	// fail with epk curve not set
	_, err = mergeSingleRecipientHeaders(wk, []byte(base64.RawURLEncoding.EncodeToString(mAAD)), json.Marshal)
	require.EqualError(t, err, "unsupported curve")

	// set epk curve for subsequent tests
	wk.EPK.Curve = elliptic.P256().Params().Name

	fm := &failingMarshaller{
		numTimesMarshalCalledBeforeReturnErr: 0,
	}

	// fail KID marshalling
	_, err = mergeSingleRecipientHeaders(wk, []byte(base64.RawURLEncoding.EncodeToString(mAAD)), fm.failingMarshal)
	require.EqualError(t, err, errFailingMarshal.Error())

	fm = &failingMarshaller{
		numTimesMarshalCalledBeforeReturnErr: 1,
	}

	// fail Alg marshalling
	_, err = mergeSingleRecipientHeaders(wk, []byte(base64.RawURLEncoding.EncodeToString(mAAD)), fm.failingMarshal)
	require.EqualError(t, err, errFailingMarshal.Error())

	fm = &failingMarshaller{
		numTimesMarshalCalledBeforeReturnErr: 1,
	}

	// fail EPK marshalling
	_, err = mergeSingleRecipientHeaders(wk, []byte(base64.RawURLEncoding.EncodeToString(mAAD)), fm.failingMarshal)
	require.EqualError(t, err, errFailingMarshal.Error())
}

func TestEmptyComputeAuthData(t *testing.T) {
	protecteHeaders := new(map[string]interface{})
	aad := []byte("")
	_, err := computeAuthData(*protecteHeaders, "", aad)
	require.NoError(t, err, "computeAuthData with empty protectedHeaders and empty aad should not fail")
}

// createRecipients and return their public key and keyset.Handle.
func createRecipients(t *testing.T, numberOfEntities int) ([]*cryptoapi.PublicKey, map[string]*keyset.Handle) {
	t.Helper()

	r := make([]*cryptoapi.PublicKey, 0)
	rKH := make(map[string]*keyset.Handle)

	for i := 0; i < numberOfEntities; i++ {
		mrKey, kh := createAndMarshalEntityKey(t)
		ecPubKey := new(cryptoapi.PublicKey)
		err := json.Unmarshal(mrKey, ecPubKey)
		require.NoError(t, err)

		ecPubKey.KID = fmt.Sprint(i)

		r = append(r, ecPubKey)
		rKH[fmt.Sprint(i)] = kh
	}

	return r, rKH
}

// createAndMarshalEntityKey creates a new recipient keyset.Handle, extracts public key, marshals it and returns
// both marshalled public key and original recipient keyset.Handle.
func createAndMarshalEntityKey(t *testing.T) ([]byte, *keyset.Handle) {
	t.Helper()

	tmpl := ecdh.NISTP256ECDHKWKeyTemplate()

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

const (
	testEncType     = "application/test-encrypted+json"
	testPayloadType = "application/test-content+json"
)

func TestFailJWEEncrypt(t *testing.T) {
	c, err := tinkcrypto.New()
	require.NoError(t, err)

	recipients, recsKH := createRecipients(t, 2)

	enc, err := NewJWEEncrypt(A256GCM, testEncType, testPayloadType,
		"0", recsKH["0"], recipients, c)
	require.NoError(t, err)

	enc.encAlg = "Undefined"

	_, err = enc.Encrypt([]byte("test"))
	require.EqualError(t, err, "jweencrypt: failed to get encryption primitive: getECDHEncPrimitive: encAlg"+
		" not supported: 'Undefined'")
}

func TestFailJWEDecrypt(t *testing.T) {
	c, err := tinkcrypto.New()
	require.NoError(t, err)

	recipients, _ := createRecipients(t, 2)

	// encrypt using local jose package
	jweEncrypter, err := NewJWEEncrypt(A256GCM, testEncType, testPayloadType,
		"", nil, recipients, c)
	require.NoError(t, err, "NewJWEEncrypt should not fail with non empty recipientPubKeys")

	pt := []byte("some msg")
	jwe, err := jweEncrypter.Encrypt(pt)
	require.NoError(t, err)
	require.Equal(t, len(recipients), len(jwe.Recipients))

	dec := NewJWEDecrypt(nil, c, nil)
	require.NotEmpty(t, dec)

	jwe.ProtectedHeaders[HeaderEncryption] = "Undefined"

	_, err = dec.decryptJWE(jwe, []byte(""))
	require.EqualError(t, err, "jwedecrypt: failed to get decryption primitive: invalid content encAlg: 'Undefined'")

	delete(jwe.ProtectedHeaders, HeaderEncryption)

	_, err = dec.decryptJWE(jwe, []byte(""))
	require.EqualError(t, err, "jwedecrypt: JWE 'enc' protected header is missing")
}

func TestBuildAPUAPVFailures(t *testing.T) {
	c, err := tinkcrypto.New()
	require.NoError(t, err)

	recipients, _ := createRecipients(t, 3)

	// encrypt using local jose package
	jweEncrypter, err := NewJWEEncrypt(A256GCM, testEncType, testPayloadType,
		"", nil, recipients, c)
	require.NoError(t, err, "NewJWEEncrypt should not fail with non empty recipientPubKeys")

	t.Run("call encryptWithSender and  buildAPUAPV with JWEEncrypter having empty skid", func(t *testing.T) {
		_, err = jweEncrypter.encryptWithSender(nil, nil, nil, nil, nil)
		require.EqualError(t, err, "jweencryptWithSender: cannot create APU/APV with empty sender skid")

		_, _, err = jweEncrypter.buildAPUAPV()
		require.EqualError(t, err, "cannot create APU/APV with empty sender skid")
	})

	t.Run("call buildAPUAPV with JWEEncrypter having empty recipients", func(t *testing.T) {
		jweEncrypter.skid = "skid"
		jweEncrypter.recipientsKeys = nil

		_, _, err = jweEncrypter.buildAPUAPV()
		require.EqualError(t, err, "cannot create APU/APV with empty recipient keys")
	})
}

func TestGenerateEPKAndUpdateAuthDataFor1PUFailure(t *testing.T) {
	c, err := tinkcrypto.New()
	require.NoError(t, err)

	recipients, _ := createRecipients(t, 5)

	recipients[0].Type = "invalidType"

	// encrypt using local jose package
	jweEncrypter, err := NewJWEEncrypt(A256GCM, testEncType, testPayloadType,
		"", nil, recipients, c)
	require.NoError(t, err, "NewJWEEncrypt should not fail with non empty recipientPubKeys")

	epk, authData, authJSON, err := jweEncrypter.generateEPKAndUpdateAuthDataFor1PU(nil, nil, nil, nil)
	require.EqualError(t, err, "generateEPKAndUpdateAuthDataFor1PU: newEPK: invalid key type 'invalidType'")
	require.Empty(t, epk)
	require.Empty(t, authData)
	require.Empty(t, authJSON)

	recipients[0].Type = "EC"
	recipients[0].Curve = "invalid"

	_, _, err = jweEncrypter.newEPK([]byte(""))
	require.EqualError(t, err, "newEPK: ecEPKAndAlg: getCurve: unsupported curve")
}

func TestBuildCommonAuthDataFailure(t *testing.T) {
	c, err := tinkcrypto.New()
	require.NoError(t, err)

	recipients, _ := createRecipients(t, 5)

	recipients[0].Type = "invalid"

	// encrypt using local jose package
	jweEncrypter, err := NewJWEEncrypt(A256GCM, testEncType, testPayloadType,
		"", nil, recipients, c)
	require.NoError(t, err, "NewJWEEncrypt should not fail with non empty recipientPubKeys")

	t.Run("buildCommonAuthData with authData having invalid b64 format", func(t *testing.T) {
		epk, authData, authJSON, err := jweEncrypter.buildCommonAuthData(0, "", "==Badb64Str$$#^",
			nil, nil, nil, nil)
		require.EqualError(t, err, "buildCommonAuthData: authdata decode: illegal base64 data at input byte 0")
		require.Empty(t, epk)
		require.Empty(t, authData)
		require.Empty(t, authJSON)
	})

	t.Run("buildCommonAuthData with authData having invalid json format", func(t *testing.T) {
		epk, authData, authJSON, err := jweEncrypter.buildCommonAuthData(0, "", "badjsonunmarshal",
			nil, nil, nil, nil)
		require.EqualError(t, err, "buildCommonAuthData: authData unmarshall: invalid character 'm' looking "+
			"for beginning of value")
		require.Empty(t, epk)
		require.Empty(t, authData)
		require.Empty(t, authJSON)
	})

	t.Run("buildCommonAuthData with epk having invalid public key type", func(t *testing.T) {
		epk, authData, authJSON, err := jweEncrypter.buildCommonAuthData(0, "", "eyJ0ZXN0IjoidGVzdCJ9",
			nil, nil, nil, &cryptoapi.PrivateKey{
				PublicKey: cryptoapi.PublicKey{Type: "invalid"},
				D:         nil,
			})
		require.EqualError(t, err, "buildCommonAuthData: epk marshall: invalid key type")
		require.Empty(t, epk)
		require.Empty(t, authData)
		require.Empty(t, authJSON)
	})
}

func TestDecodeAPUAPVFailure(t *testing.T) {
	t.Run("decodeAPUAPV with recipient APU header as invalid b64 []byte", func(t *testing.T) {
		_, _, err := decodeAPUAPV(&RecipientHeaders{APU: "=Badb64Str$$#^"})
		require.EqualError(t, err, "illegal base64 data at input byte 0")
	})

	t.Run("decodeAPUAPV with recipient APV header as invalid b64 []byte", func(t *testing.T) {
		_, _, err := decodeAPUAPV(&RecipientHeaders{APV: "=Badb64Str$$#^"})
		require.EqualError(t, err, "illegal base64 data at input byte 0")
	})
}

func TestJWKMarshalEPKFailure(t *testing.T) {
	t.Run("jwkMarshalEPK with protectedHeadersJSON having 'epk' with invalid json format", func(t *testing.T) {
		err := jwkMarshalEPK(map[string]json.RawMessage{HeaderEPK: []byte("badjsonunmarshal")})
		require.EqualError(t, err, "unable to read JWK: invalid character 'b' looking for beginning of value")
	})
}
