/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jose_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	hybrid "github.com/google/tink/go/hybrid/subtle"
	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/subtle"
	"github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"

	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/keyio"
	ecdhpb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
	ariesjose "github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/jwkkid"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
)

const (
	// EnvelopeEncodingType representing the JWE 'Typ' protected type header for DIDComm V2 (example for tests).
	EnvelopeEncodingType = "application/didcomm-encrypted+json"
	// DIDCommContentEncodingType represent the JWE `Cty` protected type header for DIDComm V2 (example for tests).
	DIDCommContentEncodingType = "application/didcomm-plain+json"
)

func TestJWEEncryptRoundTrip(t *testing.T) {
	_, err := ariesjose.NewJWEEncrypt("", "", "", "", nil, nil, nil)
	require.EqualError(t, err, "empty recipientsPubKeys list",
		"NewJWEEncrypt should fail with empty recipientPubKeys")

	tests := []struct {
		name       string
		kt         *tinkpb.KeyTemplate
		enc        ariesjose.EncAlg
		keyType    kms.KeyType
		nbRec      int
		useCompact bool
	}{
		{
			name:    "P-256 ECDH KW and AES256GCM encryption with 2 recipients (Full serialization)",
			kt:      ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:     ariesjose.A256GCM,
			keyType: kms.NISTP256ECDHKWType,
			nbRec:   2,
		},
		{
			name:    "P-256 ECDH KW and AES256GCM encryption with 1 recipient (Flattened serialization)",
			kt:      ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:     ariesjose.A256GCM,
			keyType: kms.NISTP256ECDHKWType,
			nbRec:   1,
		},
		{
			name:       "P-256 ECDH KW and AES256GCM encryption with 1 recipient (Compact serialization)",
			kt:         ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:        ariesjose.A256GCM,
			keyType:    kms.NISTP256ECDHKWType,
			nbRec:      1,
			useCompact: true,
		},
		{
			name:    "P-384 ECDH KW and AES256GCM encryption with 2 recipients (Full serialization)",
			kt:      ecdh.NISTP384ECDHKWKeyTemplate(),
			enc:     ariesjose.A256GCM,
			keyType: kms.NISTP384ECDHKWType,
			nbRec:   2,
		},
		{
			name:    "P-384 ECDH KW and AES256GCM encryption with 1 recipient (Flattened serialization)",
			kt:      ecdh.NISTP384ECDHKWKeyTemplate(),
			enc:     ariesjose.A256GCM,
			keyType: kms.NISTP384ECDHKWType,
			nbRec:   1,
		},
		{
			name:       "P-384 ECDH KW and AES256GCM encryption with 1 recipient (Compact serialization)",
			kt:         ecdh.NISTP384ECDHKWKeyTemplate(),
			enc:        ariesjose.A256GCM,
			keyType:    kms.NISTP384ECDHKWType,
			nbRec:      1,
			useCompact: true,
		},
		{
			name:    "P-521 ECDH KW and AES256GCM encryption with 2 recipients (Full serialization)",
			kt:      ecdh.NISTP521ECDHKWKeyTemplate(),
			enc:     ariesjose.A256GCM,
			keyType: kms.NISTP521ECDHKWType,
			nbRec:   2,
		},
		{
			name:    "P-521 ECDH KW and AES256GCM encryption with 1 recipient (Flattened serialization)",
			kt:      ecdh.NISTP521ECDHKWKeyTemplate(),
			enc:     ariesjose.A256GCM,
			keyType: kms.NISTP521ECDHKWType,
			nbRec:   1,
		},
		{
			name:       "P-521 ECDH KW and AES256GCM encryption with 1 recipient (Compact serialization)",
			kt:         ecdh.NISTP521ECDHKWKeyTemplate(),
			enc:        ariesjose.A256GCM,
			keyType:    kms.NISTP521ECDHKWType,
			nbRec:      1,
			useCompact: true,
		},
		{
			name:    "X25519 ECDH KW and AES256GCM encryption with 2 recipients (Full serialization)",
			kt:      ecdh.X25519ECDHKWKeyTemplate(),
			enc:     ariesjose.A256GCM,
			keyType: kms.X25519ECDHKWType,
			nbRec:   2,
		},
		{
			name:    "X25519 ECDH KW and AES256GCM encryption with 1 recipient (Flattened serialization)",
			kt:      ecdh.X25519ECDHKWKeyTemplate(),
			enc:     ariesjose.A256GCM,
			keyType: kms.X25519ECDHKWType,
			nbRec:   1,
		},
		{
			name:       "X25519 ECDH KW and AES256GCM encryption with 1 recipient (Compact serialization)",
			kt:         ecdh.X25519ECDHKWKeyTemplate(),
			enc:        ariesjose.A256GCM,
			keyType:    kms.X25519ECDHKWType,
			nbRec:      1,
			useCompact: true,
		},
		{
			name:    "P-256 ECDH KW and XChacha20Poly1305 encryption with 2 recipients (Full serialization)",
			kt:      ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:     ariesjose.XC20P,
			keyType: kms.NISTP256ECDHKWType,
			nbRec:   2,
		},
		{
			name:    "P-256 ECDH KW and XChacha20Poly1305 encryption with 1 recipient (Flattened serialization)",
			kt:      ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:     ariesjose.XC20P,
			keyType: kms.NISTP256ECDHKWType,
			nbRec:   1,
		},
		{
			name:       "P-256 ECDH KW and XChacha20Poly1305 encryption with 1 recipient (Compact serialization)",
			kt:         ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:        ariesjose.XC20P,
			keyType:    kms.NISTP256ECDHKWType,
			nbRec:      1,
			useCompact: true,
		},
		{
			name:    "P-384 ECDH KW and XChacha20Poly1305 encryption with 2 recipients (Full serialization)",
			kt:      ecdh.NISTP384ECDHKWKeyTemplate(),
			enc:     ariesjose.XC20P,
			keyType: kms.NISTP384ECDHKWType,
			nbRec:   2,
		},
		{
			name:    "P-384 ECDH KW and XChacha20Poly1305 encryption with 1 recipient (Flattened serialization)",
			kt:      ecdh.NISTP384ECDHKWKeyTemplate(),
			enc:     ariesjose.XC20P,
			keyType: kms.NISTP384ECDHKWType,
			nbRec:   1,
		},
		{
			name:       "P-384 ECDH KW and XChacha20Poly1305 encryption with 1 recipient (Compact serialization)",
			kt:         ecdh.NISTP384ECDHKWKeyTemplate(),
			enc:        ariesjose.XC20P,
			keyType:    kms.NISTP384ECDHKWType,
			nbRec:      1,
			useCompact: true,
		},
		{
			name:    "P-521 ECDH KW and XChacha20Poly1305 encryption with 2 recipients (Full serialization)",
			kt:      ecdh.NISTP521ECDHKWKeyTemplate(),
			enc:     ariesjose.XC20P,
			keyType: kms.NISTP521ECDHKWType,
			nbRec:   2,
		},
		{
			name:    "P-521 ECDH KW and XChacha20Poly1305 encryption with 1 recipient (Flattened serialization)",
			kt:      ecdh.NISTP521ECDHKWKeyTemplate(),
			enc:     ariesjose.XC20P,
			keyType: kms.NISTP521ECDHKWType,
			nbRec:   1,
		},
		{
			name:       "P-521 ECDH KW and XChacha20Poly1305 encryption with 1 recipient (Compact serialization)",
			kt:         ecdh.NISTP521ECDHKWKeyTemplate(),
			enc:        ariesjose.XC20P,
			keyType:    kms.NISTP521ECDHKWType,
			nbRec:      1,
			useCompact: true,
		},
		{
			name:    "X25519 ECDH KW and XChacha20Poly1305 encryption with 2 recipients (Full serialization)",
			kt:      ecdh.X25519ECDHKWKeyTemplate(),
			enc:     ariesjose.XC20P,
			keyType: kms.X25519ECDHKWType,
			nbRec:   2,
		},
		{
			name:    "X25519 ECDH KW and XChacha20Poly1305 encryption with 1 recipient (Flattened serialization)",
			kt:      ecdh.X25519ECDHKWKeyTemplate(),
			enc:     ariesjose.XC20P,
			keyType: kms.X25519ECDHKWType,
			nbRec:   1,
		},
		{
			name:       "X25519 ECDH KW and XChacha20Poly1305 encryption with 1 recipient (Compact serialization)",
			kt:         ecdh.X25519ECDHKWKeyTemplate(),
			enc:        ariesjose.XC20P,
			keyType:    kms.X25519ECDHKWType,
			nbRec:      1,
			useCompact: true,
		},
	}

	for _, tt := range tests {
		tc := tt
		t.Run(tc.name, func(t *testing.T) {
			t.Log("creating recipients keys..")
			recECKeys, recKHs, _ := createRecipientsByKeyTemplate(t, tc.nbRec, tc.kt, tc.keyType)

			cryptoSvc, kmsSvc := createCryptoAndKMSServices(t, recKHs)

			_, err = ariesjose.NewJWEEncrypt("", "", "", "", nil, recECKeys, cryptoSvc)
			require.EqualError(t, err, "encryption algorithm '' not supported",
				"NewJWEEncrypt should fail with empty encAlg")

			jweEncrypter, err := ariesjose.NewJWEEncrypt(tc.enc, EnvelopeEncodingType,
				DIDCommContentEncodingType, "", nil, recECKeys, cryptoSvc)
			require.NoError(t, err, "NewJWEEncrypt should not fail with non empty recipientPubKeys")

			pt := []byte("secret message")
			aad := []byte("aad value")

			if tc.useCompact { // compact serialization does not use AAD
				aad = nil
			}

			testEncTime := time.Now()
			jwe, err := jweEncrypter.EncryptWithAuthData(pt, aad)
			t.Logf("ECDH-ES KW in EncryptWithAuthData took %v", time.Since(testEncTime))
			require.NoError(t, err)
			require.Equal(t, len(recECKeys), len(jwe.Recipients))

			serializedJWE := ""
			jweStr := ""
			serialization := "Full"

			if tc.useCompact {
				testSerTime := time.Now()
				serializedJWE, err = jwe.CompactSerialize(json.Marshal)
				t.Logf("CompactSerilize took %v", time.Since(testSerTime))
				require.NoError(t, err)
				require.NotEmpty(t, serializedJWE)

				jweStr = serializedJWE
				serialization = "Compact"
			} else {
				testSerTime := time.Now()
				serializedJWE, err = jwe.FullSerialize(json.Marshal)
				t.Logf("JSON Serialize took %v", time.Since(testSerTime))
				require.NoError(t, err)
				require.NotEmpty(t, serializedJWE)

				jweStr, err = prettyPrint([]byte(serializedJWE))
				require.NoError(t, err)
				if tc.nbRec == 1 {
					serialization = "Flattened"
				}
			}

			t.Logf("* anoncrypt JWE (%s serialization): %s", serialization, jweStr)

			mPh, err := json.Marshal(jwe.ProtectedHeaders)
			require.NoError(t, err)

			protectedHeadersStr, err := prettyPrint(mPh)
			require.NoError(t, err)

			t.Logf("* protected headers: %s", protectedHeadersStr)

			// try to deserialize with go-jose (can't decrypt in go-jose since private key is protected by Tink)
			joseJWE, err := jose.ParseEncrypted(serializedJWE)
			require.NoError(t, err)
			require.NotEmpty(t, joseJWE)

			// try to deserialize with local package
			testDeserTime := time.Now()
			localJWE, err := ariesjose.Deserialize(serializedJWE)
			t.Logf("JWE Deserialize took %v", time.Since(testDeserTime))
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

				testDecTime := time.Now()
				msg, err = jweDecrypter.Decrypt(localJWE)
				t.Logf("JWE Decrypt took %v", time.Since(testDecTime))
				require.NoError(t, err)
				require.EqualValues(t, pt, msg)
			})
		})
	}
}

func TestInteropWithGoJoseEncryptAndLocalJoseDecryptUsingCompactSerialize(t *testing.T) {
	recECKeys, recKHs, recKIDs := createRecipients(t, 1)
	gjRecipients := convertToGoJoseRecipients(t, recECKeys, recKIDs)

	c, k := createCryptoAndKMSServices(t, recKHs)

	eo := &jose.EncrypterOptions{}
	gjEncrypter, err := jose.NewEncrypter(jose.A256GCM, gjRecipients[0],
		eo.WithType(EnvelopeEncodingType))
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
		eo.WithType(EnvelopeEncodingType))
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
	jweEncrypter, err := ariesjose.NewJWEEncrypt(ariesjose.A256GCM, EnvelopeEncodingType, DIDCommContentEncodingType,
		"", nil, recECKeys, c)
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

	recECKeys = append(recECKeys, &cryptoapi.PublicKey{
		X:     recPrivKey.PublicKey.X.Bytes(),
		Y:     recPrivKey.PublicKey.Y.Bytes(),
		Curve: recPrivKey.PublicKey.Curve.Params().Name,
		Type:  "EC",
	})

	// encrypt using local jose package
	jweEncrypter, err := ariesjose.NewJWEEncrypt(ariesjose.A256GCM, EnvelopeEncodingType, DIDCommContentEncodingType,
		"", nil, recECKeys, c)
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

func createRecipients(t *testing.T, nbOfEntities int) ([]*cryptoapi.PublicKey, map[string]*keyset.Handle, []string) {
	return createRecipientsByKeyTemplate(t, nbOfEntities, ecdh.NISTP256ECDHKWKeyTemplate(), kms.NISTP256ECDHKWType)
}

// createRecipients and return their public key and keyset.Handle.
func createRecipientsByKeyTemplate(t *testing.T, nbOfEntities int, kt *tinkpb.KeyTemplate,
	kType kms.KeyType) ([]*cryptoapi.PublicKey, map[string]*keyset.Handle, []string) {
	t.Helper()

	r := make([]*cryptoapi.PublicKey, 0)
	rKH := make(map[string]*keyset.Handle)
	rKID := make([]string, 0)

	for i := 0; i < nbOfEntities; i++ {
		mrKey, kh, kid := createAndMarshalEntityKey(t, kt, kType)

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
func createAndMarshalEntityKey(t *testing.T, kt *tinkpb.KeyTemplate,
	kType kms.KeyType) ([]byte, *keyset.Handle, string) {
	t.Helper()

	kh, err := keyset.NewHandle(kt)
	require.NoError(t, err)

	pubKH, err := kh.Public()
	require.NoError(t, err)

	buf := new(bytes.Buffer)
	pubKeyWriter := keyio.NewWriter(buf)
	require.NotEmpty(t, pubKeyWriter)

	err = pubKH.WriteWithNoSecrets(pubKeyWriter)
	require.NoError(t, err)

	kid, err := jwkkid.CreateKID(buf.Bytes(), kType)
	require.NoError(t, err)

	printKey(t, buf.Bytes(), kid)

	return buf.Bytes(), kh, kid
}

func printKey(t *testing.T, mPubKey []byte, kid string) {
	t.Helper()

	pubKey := new(cryptoapi.PublicKey)
	err := json.Unmarshal(mPubKey, pubKey)
	require.NoError(t, err)

	switch pubKey.Type {
	case ecdhpb.KeyType_EC.String():
		t.Logf("** EC key: %s, kid: %s", getPrintedECPubKey(t, pubKey), kid)
	case ecdhpb.KeyType_OKP.String():
		t.Logf("** X25519 key: %s, kid: %s", getPrintedX25519PubKey(t, pubKey), kid)
	default:
		t.Errorf("not supported key type: %s", pubKey.Type)
	}
}

func prettyPrint(msg []byte) (string, error) {
	var prettyJSON bytes.Buffer

	err := json.Indent(&prettyJSON, msg, "", "\t")
	if err != nil {
		return "", err
	}

	return prettyJSON.String(), nil
}

func getPrintedECPubKey(t *testing.T, pubKey *cryptoapi.PublicKey) string {
	crv, err := hybrid.GetCurve(pubKey.Curve)
	require.NoError(t, err)

	jwk := jose.JSONWebKey{
		Key: &ecdsa.PublicKey{
			Curve: crv,
			X:     new(big.Int).SetBytes(pubKey.X),
			Y:     new(big.Int).SetBytes(pubKey.Y),
		},
	}

	jwkByte, err := jwk.MarshalJSON()
	require.NoError(t, err)
	jwkStr, err := prettyPrint(jwkByte)
	require.NoError(t, err)

	return jwkStr
}

func getPrintedX25519PubKey(t *testing.T, pubKeyType *cryptoapi.PublicKey) string {
	jwk := jose.JSONWebKey{
		Key: ed25519.PublicKey(pubKeyType.X),
	}

	jwkByte, err := jwk.MarshalJSON()
	require.NoError(t, err)

	jwkStr, err := prettyPrint(jwkByte)
	require.NoError(t, err)

	return strings.Replace(jwkStr, "Ed25519", "X25519", 1)
}

func TestFailNewJWEEncrypt(t *testing.T) {
	c, err := tinkcrypto.New()
	require.NoError(t, err)

	recipients, recsKH, kids := createRecipients(t, 2)

	_, err = ariesjose.NewJWEEncrypt(ariesjose.A256GCM, EnvelopeEncodingType, DIDCommContentEncodingType,
		"", recsKH[kids[0]], recipients, c)
	require.EqualError(t, err, "senderKID is required with senderKH")
}

func TestECDH1PU(t *testing.T) {
	tests := []struct {
		name       string
		kt         *tinkpb.KeyTemplate
		enc        ariesjose.EncAlg
		keyType    kms.KeyType
		nbRec      int
		useCompact bool
	}{
		{
			name:    "P-256 ECDH KW and AES256GCM encryption with 2 recipients (Full serialization)",
			kt:      ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:     ariesjose.A256GCM,
			keyType: kms.NISTP256ECDHKWType,
			nbRec:   2,
		},
		{
			name:    "P-256 ECDH KW and AES256GCM encryption with 1 recipient (Flattened serialization)",
			kt:      ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:     ariesjose.A256GCM,
			keyType: kms.NISTP256ECDHKWType,
			nbRec:   1,
		},
		{
			name:       "P-256 ECDH KW and AES256GCM encryption with 1 recipient (Compact serialization)",
			kt:         ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:        ariesjose.A256GCM,
			keyType:    kms.NISTP256ECDHKWType,
			nbRec:      1,
			useCompact: true,
		},
		{
			name:    "P-384 ECDH KW and AES256GCM encryption with 2 recipients (Full serialization)",
			kt:      ecdh.NISTP384ECDHKWKeyTemplate(),
			enc:     ariesjose.A256GCM,
			keyType: kms.NISTP384ECDHKWType,
			nbRec:   2,
		},
		{
			name:    "P-384 ECDH KW and AES256GCM encryption with 1 recipient (Flattened serialization)",
			kt:      ecdh.NISTP384ECDHKWKeyTemplate(),
			enc:     ariesjose.A256GCM,
			keyType: kms.NISTP384ECDHKWType,
			nbRec:   1,
		},
		{
			name:       "P-384 ECDH KW and AES256GCM encryption with 1 recipient (Compact serialization)",
			kt:         ecdh.NISTP384ECDHKWKeyTemplate(),
			enc:        ariesjose.A256GCM,
			keyType:    kms.NISTP384ECDHKWType,
			nbRec:      1,
			useCompact: true,
		},
		{
			name:    "P-521 ECDH KW and AES256GCM encryption with 2 recipients (Full serialization)",
			kt:      ecdh.NISTP521ECDHKWKeyTemplate(),
			enc:     ariesjose.A256GCM,
			keyType: kms.NISTP521ECDHKWType,
			nbRec:   2,
		},
		{
			name:    "P-521 ECDH KW and AES256GCM encryption with 1 recipient (Flattened serialization)",
			kt:      ecdh.NISTP521ECDHKWKeyTemplate(),
			enc:     ariesjose.A256GCM,
			keyType: kms.NISTP521ECDHKWType,
			nbRec:   1,
		},
		{
			name:       "P-521 ECDH KW and AES256GCM encryption with 1 recipient (Compact serialization)",
			kt:         ecdh.NISTP521ECDHKWKeyTemplate(),
			enc:        ariesjose.A256GCM,
			keyType:    kms.NISTP521ECDHKWType,
			nbRec:      1,
			useCompact: true,
		},
		{
			name:    "X25519 ECDH KW and AES256GCM encryption with 2 recipients (Full serialization)",
			kt:      ecdh.X25519ECDHKWKeyTemplate(),
			enc:     ariesjose.A256GCM,
			keyType: kms.X25519ECDHKWType,
			nbRec:   2,
		},
		{
			name:    "X25519 ECDH KW and AES256GCM encryption with 1 recipient (Flattened serialization)",
			kt:      ecdh.X25519ECDHKWKeyTemplate(),
			enc:     ariesjose.A256GCM,
			keyType: kms.X25519ECDHKWType,
			nbRec:   1,
		},
		{
			name:       "X25519 ECDH KW and AES256GCM encryption with 1 recipient (Compact serialization)",
			kt:         ecdh.X25519ECDHKWKeyTemplate(),
			enc:        ariesjose.A256GCM,
			keyType:    kms.X25519ECDHKWType,
			nbRec:      1,
			useCompact: true,
		},
		{
			name:    "P-256 ECDH KW and XChacha20Poly1305 encryption with 2 recipients (Full serialization)",
			kt:      ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:     ariesjose.XC20P,
			keyType: kms.NISTP256ECDHKWType,
			nbRec:   2,
		},
		{
			name:    "P-256 ECDH KW and XChacha20Poly1305 encryption with 1 recipient (Flattened serialization)",
			kt:      ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:     ariesjose.XC20P,
			keyType: kms.NISTP256ECDHKWType,
			nbRec:   1,
		},
		{
			name:       "P-256 ECDH KW and XChacha20Poly1305 encryption with 1 recipient (Compact serialization)",
			kt:         ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:        ariesjose.XC20P,
			keyType:    kms.NISTP256ECDHKWType,
			nbRec:      1,
			useCompact: true,
		},
		{
			name:    "P-384 ECDH KW and XChacha20Poly1305 encryption with 2 recipients (Full serialization)",
			kt:      ecdh.NISTP384ECDHKWKeyTemplate(),
			enc:     ariesjose.XC20P,
			keyType: kms.NISTP384ECDHKWType,
			nbRec:   2,
		},
		{
			name:    "P-384 ECDH KW and XChacha20Poly1305 encryption with 1 recipient (Flattened serialization)",
			kt:      ecdh.NISTP384ECDHKWKeyTemplate(),
			enc:     ariesjose.XC20P,
			keyType: kms.NISTP384ECDHKWType,
			nbRec:   1,
		},
		{
			name:       "P-384 ECDH KW and XChacha20Poly1305 encryption with 1 recipient (Compact serialization)",
			kt:         ecdh.NISTP384ECDHKWKeyTemplate(),
			enc:        ariesjose.XC20P,
			keyType:    kms.NISTP384ECDHKWType,
			nbRec:      1,
			useCompact: true,
		},
		{
			name:    "P-521 ECDH KW and XChacha20Poly1305 encryption with 2 recipients (Full serialization)",
			kt:      ecdh.NISTP521ECDHKWKeyTemplate(),
			enc:     ariesjose.XC20P,
			keyType: kms.NISTP521ECDHKWType,
			nbRec:   2,
		},
		{
			name:    "P-521 ECDH KW and XChacha20Poly1305 encryption with 1 recipient (Flattened serialization)",
			kt:      ecdh.NISTP521ECDHKWKeyTemplate(),
			enc:     ariesjose.XC20P,
			keyType: kms.NISTP521ECDHKWType,
			nbRec:   1,
		},
		{
			name:       "P-521 ECDH KW and XChacha20Poly1305 encryption with 1 recipient (Compact serialization)",
			kt:         ecdh.NISTP521ECDHKWKeyTemplate(),
			enc:        ariesjose.XC20P,
			keyType:    kms.NISTP521ECDHKWType,
			nbRec:      1,
			useCompact: true,
		},
		{
			name:    "X25519 ECDH KW and XChacha20Poly1305 encryption with 2 recipients (Full serialization)",
			kt:      ecdh.X25519ECDHKWKeyTemplate(),
			enc:     ariesjose.XC20P,
			keyType: kms.X25519ECDHKWType,
			nbRec:   2,
		},
		{
			name:    "X25519 ECDH KW and XChacha20Poly1305 encryption with 1 recipient (Flattened serialization)",
			kt:      ecdh.X25519ECDHKWKeyTemplate(),
			enc:     ariesjose.XC20P,
			keyType: kms.X25519ECDHKWType,
			nbRec:   1,
		},
		{
			name:       "X25519 ECDH KW and XChacha20Poly1305 encryption with 1 recipient (Compact serialization)",
			kt:         ecdh.X25519ECDHKWKeyTemplate(),
			enc:        ariesjose.XC20P,
			keyType:    kms.X25519ECDHKWType,
			nbRec:      1,
			useCompact: true,
		},
	}

	for _, tt := range tests {
		tc := tt
		t.Run(tc.name, func(t *testing.T) {
			t.Log("creating Sender key..")
			senders, senderKHs, senderKIDs := createRecipientsByKeyTemplate(t, 1, tc.kt, tc.keyType)
			t.Log("creating recipients keys..")
			recipients, recKHs, _ := createRecipientsByKeyTemplate(t, tc.nbRec, tc.kt, tc.keyType)

			c, k := createCryptoAndKMSServices(t, recKHs)

			senderPubKey, err := json.Marshal(senders[0])
			require.NoError(t, err)

			jweEnc, err := ariesjose.NewJWEEncrypt(tc.enc, EnvelopeEncodingType, DIDCommContentEncodingType,
				senderKIDs[0], senderKHs[senderKIDs[0]], recipients, c)
			require.NoError(t, err)
			require.NotEmpty(t, jweEnc)

			mockStoreMap := make(map[string]mockstorage.DBEntry)
			mockStore := &mockstorage.MockStore{
				Store: mockStoreMap,
			}

			pt := []byte("secret message")
			aad := []byte("aad value")

			if tc.useCompact { // Compact serialization does not use aad
				aad = nil
			}

			// test JWEEncrypt for ECDH1PU
			testEncTime := time.Now()
			jwe, err := jweEnc.EncryptWithAuthData(pt, aad)
			t.Logf("ECDH-1PU KW in EncryptWithAuthData took %v", time.Since(testEncTime))
			require.NoError(t, err)

			serializedJWE := ""
			jweStr := ""
			serialization := "Full"

			if tc.useCompact {
				testSerTime := time.Now()
				serializedJWE, err = jwe.CompactSerialize(json.Marshal)
				t.Logf("Compact serialize took %v", time.Since(testSerTime))
				require.NoError(t, err)
				require.NotEmpty(t, serializedJWE)

				jweStr = serializedJWE
				serialization = "Compact"
			} else {
				testSerTime := time.Now()
				serializedJWE, err = jwe.FullSerialize(json.Marshal)
				t.Logf("JSON serialize took %v", time.Since(testSerTime))
				require.NoError(t, err)
				require.NotEmpty(t, serializedJWE)

				jweStr, err = prettyPrint([]byte(serializedJWE))
				require.NoError(t, err)
				if tc.nbRec == 1 {
					serialization = "Flattened"
				}
			}

			t.Logf("* anoncrypt JWE (%s serialization): %s", serialization, jweStr)

			mPh, err := json.Marshal(jwe.ProtectedHeaders)
			require.NoError(t, err)

			protectedHeadersStr, err := prettyPrint(mPh)
			require.NoError(t, err)

			t.Logf("* protected headers: %s", protectedHeadersStr)

			testDeserTime := time.Now()
			localJWE, err := ariesjose.Deserialize(serializedJWE)
			t.Logf("JWE deserialize took %v", time.Since(testDeserTime))
			require.NoError(t, err)

			t.Run("Decrypting JWE message without sender key in the third party store should fail", func(t *testing.T) {
				jd := ariesjose.NewJWEDecrypt(mockStore, c, k)
				require.NotEmpty(t, jd)

				_, err = jd.Decrypt(localJWE)
				require.EqualError(t, err, "jwedecrypt: failed to add sender public key for skid: failed to get sender"+
					" key from DB: data not found")
			})

			// add sender pubkey into the recipient's mock store to prepare for a successful JWEDecrypt() for each recipient
			mockStoreMap[senderKIDs[0]] = mockstorage.DBEntry{Value: senderPubKey}

			t.Run("Decrypting JWE message test success", func(t *testing.T) {
				jd := ariesjose.NewJWEDecrypt(mockStore, c, k)
				require.NotEmpty(t, jd)

				var msg []byte

				testDecTime := time.Now()
				msg, err = jd.Decrypt(localJWE)
				t.Logf("JWE deserialize took %v", time.Since(testDecTime))
				require.NoError(t, err)
				require.EqualValues(t, pt, msg)
			})
		})
	}
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
