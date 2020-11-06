/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jose_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/subtle"
	"github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"

	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/keyio"
	ariesjose "github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/jwkkid"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
)

func TestJWEEncryptRoundTrip(t *testing.T) {
	_, err := ariesjose.NewJWEEncrypt("", "", "", nil, nil, nil)
	require.EqualError(t, err, "empty recipientsPubKeys list",
		"NewJWEEncrypt should fail with empty recipientPubKeys")

	recECKeys, recKHs, _ := createRecipients(t, 20)

	cryptoSvc, kmsSvc := createCryptoAndKMSServices(t, recKHs)

	_, err = ariesjose.NewJWEEncrypt("", "", "", nil, recECKeys, cryptoSvc)
	require.EqualError(t, err, "encryption algorithm '' not supported",
		"NewJWEEncrypt should fail with empty encAlg")

	jweEncrypter, err := ariesjose.NewJWEEncrypt(ariesjose.A256GCM, ariesjose.DIDCommEncType,
		"", nil, recECKeys, cryptoSvc)
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
	localJWE, err := ariesjose.Deserialize(serializedJWE)
	require.NoError(t, err)

	t.Run("Decrypting JWE tests failures", func(t *testing.T) {
		jweDecrypter := ariesjose.NewJWEDecrypt(nil, cryptoSvc, kmsSvc)

		// decrypt empty JWE
		_, err = jweDecrypter.Decrypt(nil)
		require.EqualError(t, err, "jwedecrypt: jwe is nil")

		var badJWE *ariesjose.JSONWebEncryption

		badJWE, err = ariesjose.Deserialize(serializedJWE)
		require.NoError(t, err)

		ph := badJWE.ProtectedHeaders
		badJWE.ProtectedHeaders = nil

		// decrypt JWE with empty ProtectHeaders
		_, err = jweDecrypter.Decrypt(badJWE)
		require.EqualError(t, err, "jwedecrypt: jwe is missing protected headers")

		badJWE.ProtectedHeaders = ariesjose.Headers{}
		badJWE.ProtectedHeaders["somKey"] = "badKey"
		_, err = jweDecrypter.Decrypt(badJWE)
		require.EqualError(t, err, "jwedecrypt: jwe is missing encryption algorithm 'enc' header")

		badJWE.ProtectedHeaders = map[string]interface{}{
			ariesjose.HeaderEncryption: "badEncHeader",
			ariesjose.HeaderType:       "test",
		}

		// decrypt JWE with bad Enc header value
		_, err = jweDecrypter.Decrypt(badJWE)
		require.EqualError(t, err, "jwedecrypt: encryption algorithm 'badEncHeader' not supported")

		badJWE.ProtectedHeaders = ph

		// decrypt JWE with invalid recipient key
		badJWE.Recipients = []*ariesjose.Recipient{
			{
				EncryptedKey: "someKey",
				Header: &ariesjose.RecipientHeaders{
					EPK: []byte("somerawbytes"),
				},
			},
			{
				EncryptedKey: "someOtherKey",
				Header: &ariesjose.RecipientHeaders{
					EPK: []byte("someotherrawbytes"),
				},
			},
		}

		_, err = jweDecrypter.Decrypt(badJWE)
		require.EqualError(t, err, "jwedecrypt: failed to build recipients WK: unable to read "+
			"JWK: invalid character 's' looking for beginning of value")

		// decrypt JWE with unsupported recipient key
		var privKey *rsa.PrivateKey

		privKey, err = rsa.GenerateKey(rand.Reader, 2048)

		unsupportedJWK := ariesjose.JWK{
			JSONWebKey: jose.JSONWebKey{
				Key: &privKey.PublicKey,
			},
		}

		var mk []byte

		mk, err = unsupportedJWK.MarshalJSON()
		require.NoError(t, err)

		badJWE.Recipients = []*ariesjose.Recipient{
			{
				EncryptedKey: "someKey",
				Header: &ariesjose.RecipientHeaders{
					EPK: mk,
				},
			},
			{
				EncryptedKey: "someOtherKey",
				Header: &ariesjose.RecipientHeaders{
					EPK: mk,
				},
			},
		}

		_, err = jweDecrypter.Decrypt(badJWE)
		require.EqualError(t, err, "jwedecrypt: failed to build recipients WK: unsupported recipient key type")
	})

	t.Run("Decrypting JWE test success ", func(t *testing.T) {
		jweDecrypter := ariesjose.NewJWEDecrypt(nil, cryptoSvc, kmsSvc)

		var msg []byte

		msg, err = jweDecrypter.Decrypt(localJWE)
		require.NoError(t, err)
		require.EqualValues(t, pt, msg)
	})
}

func TestJWEEncryptRoundTripWithSingleRecipient(t *testing.T) {
	recECKeys, recKHs, _ := createRecipients(t, 1)

	c, k := createCryptoAndKMSServices(t, recKHs)

	jweEncrypter, err := ariesjose.NewJWEEncrypt(ariesjose.A256GCM, ariesjose.DIDCommEncType, "", nil, recECKeys, c)
	require.NoError(t, err, "NewJWEEncrypt should not fail with non empty recipientPubKeys")

	pt := []byte("some msg")
	jwe, err := jweEncrypter.Encrypt(pt)
	require.NoError(t, err)
	require.Equal(t, len(recECKeys), len(jwe.Recipients))

	serializedJWE, err := jwe.CompactSerialize(json.Marshal)
	require.NoError(t, err)
	require.NotEmpty(t, serializedJWE)

	// try to deserialize with local package
	localJWE, err := ariesjose.Deserialize(serializedJWE)
	require.NoError(t, err)

	jweDecrypter := ariesjose.NewJWEDecrypt(nil, c, k)

	var msg []byte

	msg, err = jweDecrypter.Decrypt(localJWE)
	require.NoError(t, err)
	require.EqualValues(t, pt, msg)
}

func TestInteropWithGoJoseEncryptAndLocalJoseDecryptUsingCompactSerialize(t *testing.T) {
	recECKeys, recKHs, recKIDs := createRecipients(t, 1)
	gjRecipients := convertToGoJoseRecipients(t, recECKeys, recKIDs)

	c, k := createCryptoAndKMSServices(t, recKHs)

	eo := &jose.EncrypterOptions{}
	gjEncrypter, err := jose.NewEncrypter(jose.A256GCM, gjRecipients[0],
		eo.WithType(ariesjose.DIDCommEncType))
	require.NoError(t, err)

	pt := []byte("Test secret message")

	// encrypt pt using go-jose encryption
	gjJWEEncrypter, err := gjEncrypter.Encrypt(pt)
	require.NoError(t, err)

	// get go-jose serialized JWE
	gjSerializedJWE, err := gjJWEEncrypter.CompactSerialize()
	require.NoError(t, err)

	// deserialize using local jose package
	localJWE, err := ariesjose.Deserialize(gjSerializedJWE)
	require.NoError(t, err)

	t.Run("Decrypting JWE message encrypted by go-jose test success", func(t *testing.T) {
		jweDecrypter := ariesjose.NewJWEDecrypt(nil, c, k)

		var msg []byte

		msg, err = jweDecrypter.Decrypt(localJWE)
		require.NoError(t, err)
		require.EqualValues(t, pt, msg)
	})
}

func TestInteropWithGoJoseEncryptAndLocalJoseDecrypt(t *testing.T) {
	recECKeys, recKHs, recKIDs := createRecipients(t, 3)
	gjRecipients := convertToGoJoseRecipients(t, recECKeys, recKIDs)

	c, k := createCryptoAndKMSServices(t, recKHs)

	eo := &jose.EncrypterOptions{}
	gjEncrypter, err := jose.NewMultiEncrypter(jose.A256GCM, gjRecipients,
		eo.WithType(ariesjose.DIDCommEncType))
	require.NoError(t, err)

	pt := []byte("Test secret message")
	aad := []byte("Test some auth data")

	// encrypt pt using go-jose encryption
	gjJWEEncrypter, err := gjEncrypter.EncryptWithAuthData(pt, aad)
	require.NoError(t, err)

	// get go-jose serialized JWE
	gjSerializedJWE := gjJWEEncrypter.FullSerialize()

	// deserialize using local jose package
	localJWE, err := ariesjose.Deserialize(gjSerializedJWE)
	require.NoError(t, err)

	t.Run("Decrypting JWE message encrypted by go-jose test success", func(t *testing.T) {
		jweDecrypter := ariesjose.NewJWEDecrypt(nil, c, k)

		var msg []byte

		msg, err = jweDecrypter.Decrypt(localJWE)
		require.NoError(t, err)
		require.EqualValues(t, pt, msg)
	})
}

func TestInteropWithLocalJoseEncryptAndGoJoseDecrypt(t *testing.T) {
	c, err := tinkcrypto.New()
	require.NoError(t, err)

	// get two generated recipient Tink keys
	recECKeys, _, _ := createRecipients(t, 2)
	// create a normal recipient key (not using Tink)
	rec3PrivKey, err := ecdsa.GenerateKey(subtle.GetCurve(recECKeys[0].Curve), rand.Reader)
	require.NoError(t, err)

	// add third key to recECKeys
	recECKeys = append(recECKeys, &cryptoapi.PublicKey{
		X:     rec3PrivKey.PublicKey.X.Bytes(),
		Y:     rec3PrivKey.PublicKey.Y.Bytes(),
		Curve: rec3PrivKey.PublicKey.Curve.Params().Name,
		Type:  "EC",
	})

	// encrypt using local jose package
	jweEncrypter, err := ariesjose.NewJWEEncrypt(ariesjose.A256GCM, ariesjose.DIDCommEncType, "", nil, recECKeys, c)
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
	var recECKeys []*cryptoapi.PublicKey
	// create a normal recipient key (not using Tink)
	recPrivKey, err := ecdsa.GenerateKey(subtle.GetCurve("NIST_P256"), rand.Reader)
	require.NoError(t, err)

	c, err := tinkcrypto.New()
	require.NoError(t, err)

	// add third key to recECKeys
	recECKeys = append(recECKeys, &cryptoapi.PublicKey{
		X:     recPrivKey.PublicKey.X.Bytes(),
		Y:     recPrivKey.PublicKey.Y.Bytes(),
		Curve: recPrivKey.PublicKey.Curve.Params().Name,
		Type:  "EC",
	})

	// encrypt using local jose package
	jweEncrypter, err := ariesjose.NewJWEEncrypt(ariesjose.A256GCM, ariesjose.DIDCommEncType, "", nil, recECKeys, c)
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

func convertToGoJoseRecipients(t *testing.T, keys []*cryptoapi.PublicKey, kids []string) []jose.Recipient {
	t.Helper()

	var joseRecipients []jose.Recipient

	for i, key := range keys {
		c := subtle.GetCurve(key.Curve)
		gjKey := jose.Recipient{
			KeyID:     kids[i],
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
func createRecipients(t *testing.T, nbOfEntities int) ([]*cryptoapi.PublicKey, map[string]*keyset.Handle, []string) {
	t.Helper()

	r := make([]*cryptoapi.PublicKey, 0)
	rKH := make(map[string]*keyset.Handle)
	rKID := make([]string, 0)

	for i := 0; i < nbOfEntities; i++ {
		mrKey, kh, kid := createAndMarshalEntityKey(t)

		ecPubKey := new(cryptoapi.PublicKey)
		err := json.Unmarshal(mrKey, ecPubKey)
		require.NoError(t, err)

		ecPubKey.KID = kid
		rKH[kid] = kh

		r = append(r, ecPubKey)
		rKID = append(rKID, kid)
	}

	return r, rKH, rKID
}

// createAndMarshalEntityKey creates a new recipient keyset.Handle, extracts public key, marshals it and returns
// both marshalled public key and original recipient keyset.Handle.
func createAndMarshalEntityKey(t *testing.T) ([]byte, *keyset.Handle, string) {
	t.Helper()

	tmpl := ecdh.ECDH256KWAES256GCMKeyTemplate()

	kh, err := keyset.NewHandle(tmpl)
	require.NoError(t, err)

	pubKH, err := kh.Public()
	require.NoError(t, err)

	buf := new(bytes.Buffer)
	pubKeyWriter := keyio.NewWriter(buf)
	require.NotEmpty(t, pubKeyWriter)

	err = pubKH.WriteWithNoSecrets(pubKeyWriter)
	require.NoError(t, err)

	kid, err := jwkkid.CreateKID(buf.Bytes(), kms.ECDH256KWAES256GCMType)
	require.NoError(t, err)

	return buf.Bytes(), kh, kid
}

func TestFailNewJWEEncrypt(t *testing.T) {
	c, err := tinkcrypto.New()
	require.NoError(t, err)

	recipients, recsKH, kids := createRecipients(t, 2)

	_, err = ariesjose.NewJWEEncrypt(ariesjose.A256GCM, ariesjose.DIDCommEncType, "", recsKH[kids[0]], recipients, c)
	require.EqualError(t, err, "senderKID is required with senderKH")
}

func TestECDH1PU(t *testing.T) {
	recipients, recKHs, _ := createRecipients(t, 2)
	senders, senderKHs, senderKIDs := createRecipients(t, 1)

	c, k := createCryptoAndKMSServices(t, recKHs)

	senderPubKey, err := json.Marshal(senders[0])
	require.NoError(t, err)

	jweEnc, err := ariesjose.NewJWEEncrypt(ariesjose.A256GCM, ariesjose.DIDCommEncType, senderKIDs[0],
		senderKHs[senderKIDs[0]], recipients, c)
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

	localJWE, err := ariesjose.Deserialize(serializedJWE)
	require.NoError(t, err)

	t.Run("Decrypting JWE message without sender key in the third party store should fail", func(t *testing.T) {
		jd := ariesjose.NewJWEDecrypt(mockStore, c, k)
		require.NotEmpty(t, jd)

		_, err = jd.Decrypt(localJWE)
		require.EqualError(t, err, "jwedecrypt: failed to add sender public key for skid: failed to get sender"+
			" key from DB: data not found")
	})

	// add sender pubkey into the recipient's mock store to prepare for a successful JWEDecrypt() for each recipient
	mockStoreMap[senderKIDs[0]] = senderPubKey

	t.Run("Decrypting JWE message test success", func(t *testing.T) {
		jd := ariesjose.NewJWEDecrypt(mockStore, c, k)
		require.NotEmpty(t, jd)

		var msg []byte

		msg, err = jd.Decrypt(localJWE)
		require.NoError(t, err)
		require.EqualValues(t, pt, msg)
	})
}

func createCryptoAndKMSServices(t *testing.T, keys map[string]*keyset.Handle) (cryptoapi.Crypto, kms.KeyManager) {
	c, err := tinkcrypto.New()
	require.NoError(t, err)

	k := &mockKMSGetter{
		keys: keys,
	}

	require.NoError(t, err)

	return c, k
}

type mockKMSGetter struct {
	mockkms.KeyManager
	keys map[string]*keyset.Handle
}

func (k *mockKMSGetter) Get(kid string) (interface{}, error) {
	return k.keys[kid], nil
}
