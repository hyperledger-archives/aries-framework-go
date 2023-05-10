/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwksupport

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v3"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/util/cryptoutil"

	"github.com/hyperledger/aries-framework-go/spi/kms"

	cryptoapi "github.com/hyperledger/aries-framework-go/spi/crypto"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk"
)

func TestDecodeJWK(t *testing.T) {
	t.Run("Test decode public key success", func(t *testing.T) {
		tests := []struct {
			name    string
			jwkJSON string
		}{
			{
				name: "get public key bytes Ed25519 JWK",
				jwkJSON: `{
							"kty": "OKP",
							"use": "enc",
							"crv": "Ed25519",
							"kid": "sample@sample.id",
							"x": "sEHL6KXs8bUz9Ss2qSWWjhhRMHVjrog0lzFENM132R8",
							"alg": "EdDSA"
						}`,
			},
			{
				name: "get public key bytes X25519 JWK",
				jwkJSON: `{
							"kty": "OKP",
							"use": "enc",
							"crv": "X25519",
							"kid": "sample@sample.id",
							"x": "sEHL6KXs8bUz9Ss2qSWWjhhRMHVjrog0lzFENM132R8"
						}`,
			},
			{
				name: "get public key bytes BBS+ JWK",
				//nolint:lll
				jwkJSON: `{
							"kty": "EC",
							"use": "enc",
							"crv": "BLS12381_G2",
							"kid": "sample@sample.id",
							"x": "tKWJu0SOY7onl4tEyOOH11XBriQN2JgzV-UmjgBMSsNkcAx3_l97SVYViSDBouTVBkBfrLh33C5icDD-4UEDxNO3Wn1ijMHvn2N63DU4pkezA3kGN81jGbwbrsMPpiOF"
						}`,
			},
			{
				name: "get public key bytes RSA JWK",
				jwkJSON: `{
							"kty": "RSA",
							"e": "AQAB",
							"use": "enc",
							"kid": "sample@sample.id",
							"alg": "RS256",
							"n": "1hOl09BUnwY7jFBqoZKa4XDmIuc0YFb4y_5ThiHhLRW68aNG5Vo23n3ugND2GK3PsguZqJ_HrWCGVuVlKTmFg` +
					`JWQD9ZnVcYqScgHpQRhxMBi86PIvXR01D_PWXZZjvTRakpvQxUT5bVBdWnaBHQoxDBt0YIVi5a7x-gXB1aDlts4RTMpfS9BPmEjX` +
					`4lciozwS6Ow_wTO3C2YGa_Our0ptIxr-x_3sMbPCN8Fe_iaBDezeDAm39xCNjFa1E735ipXA4eUW_6SzFJ5-bM2UKba2WE6xUaEa5G1` +
					`MDDHCG5LKKd6Mhy7SSAzPOR2FTKYj89ch2asCPlbjHTu8jS6Iy8"
						}`,
			},
			{
				name: "get public key bytes EC P-256 JWK",
				jwkJSON: `{
							"kty": "EC",
							"use": "enc",
							"crv": "P-256",
							"kid": "sample@sample.id",
							"x": "JR7nhI47w7bxrNkp7Xt1nbmozNn-RB2Q-PWi7KHT8J0",
							"y": "iXmKtH0caOgB1vV0CQwinwK999qdDvrssKhdbiAz9OI",
							"alg": "ES256"
						}`,
			},
			{
				name: "get public key bytes EC P-384 JWK",
				jwkJSON: `{
							"kty": "EC",
							"use": "enc",
							"crv": "P-384",
							"kid": "sample@sample.id",
							"x": "GGFw14WnABx5S__MLwjy7WPgmPzCNbygbJikSqwx1nQ7APAiIyLeiAeZnAFQSr8C",
							"y": "Bjev4lkaRbd4Ery0vnO8Ox4QgIDGbuflmFq0HhL-QHIe3KhqxrqZqbQYGlDNudEv",
							"alg": "ES384"
						}`,
			},
			{
				name: "get public key bytes EC P-521 JWK",
				jwkJSON: `{
							"kty": "EC",
							"use": "enc",
							"crv": "P-521",
							"kid": "sample@sample.id",
							"x": "AZi-AxJkB09qw8dBnNrz53xM-wER0Y5IYXSEWSTtzI5Sdv_5XijQn9z-vGz1pMdww-C75GdpAzp2ghejZJSxbAd6",
							"y": "AZzRvW8NBytGNbF3dyNOMHB0DHCOzGp8oYBv_ZCyJbQUUnq-TYX7j8-PlKe9Ce5acxZzrcUKVtJ4I8JgI5x9oXIW",
							"alg": "ES521"
						}`,
			},
			{
				name: "get public key bytes EC SECP256K1 JWK",
				jwkJSON: `{
    						"kty": "EC",
        					"use": "enc",
        					"crv": "secp256k1",
        					"kid": "sample@sample.id",
        					"x": "YRrvJocKf39GpdTnd-zBFE0msGDqawR-Cmtc6yKoFsM",
        					"y": "kE-dMH9S3mxnTXo0JFEhraCU_tVYFDfpu9tpP1LfVKQ",
        					"alg": "ES256K"
						}`,
			},
			{
				name: "get private key bytes EC SECP256K1 JWK",
				jwkJSON: `{
							"kty": "EC",
							"d": "Lg5xrN8Usd_T-MfqBIs3bUWQCNsXY8hGU-Ru3Joom8E",
							"use": "sig",
							"crv": "secp256k1",
							"kid": "sample@sample.id",
							"x": "dv6X5DheBaFWR2H_yv9pUI2dcmL2XX8m7zgFc9Coaqg",
							"y": "AUVSmytVWP350kV1RHhQ6AcCWaJj8AFt4aNLlDws7C4",
							"alg": "ES256K"
						}`,
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.name, func(t *testing.T) {
				var jwkKey jwk.JWK

				err := json.Unmarshal([]byte(tc.jwkJSON), &jwkKey)
				require.NoError(t, err)

				pkBytes, err := jwkKey.PublicKeyBytes()
				require.NoError(t, err)
				require.NotEmpty(t, pkBytes)

				jwkBytes, err := json.Marshal(&jwkKey)
				require.NoError(t, err)
				require.NotEmpty(t, jwkBytes)

				switch tc.name {
				case "get public key bytes X25519 JWK":
					jwkKey1, err := JWKFromX25519Key(jwkKey.Key.([]byte))
					require.NoError(t, err)
					require.NotNil(t, jwkKey1)
					require.Equal(t, x25519Crv, jwkKey1.Crv)
					require.Equal(t, cryptoutil.Curve25519KeySize, len(jwkKey1.Key.([]byte)))
					require.Equal(t, okpKty, jwkKey1.Kty)

					newJWK, err := PubKeyBytesToJWK(jwkKey.Key.([]byte), kms.X25519ECDHKWType)
					require.NoError(t, err)
					require.Equal(t, x25519Crv, newJWK.Crv)
					require.Equal(t, cryptoutil.Curve25519KeySize, len(newJWK.Key.([]byte)))
					require.Equal(t, okpKty, newJWK.Kty)
				case "get public key bytes BBS+ JWK":
					jwkKey2, err := JWKFromKey(jwkKey.Key)
					require.NoError(t, err)
					require.NotNil(t, jwkKey2)
					require.Equal(t, bls12381G2Crv, jwkKey2.Crv)
					bbsPubKey, ok := jwkKey2.Key.(*bbs12381g2pub.PublicKey)
					require.True(t, ok)
					bbsPubKeyBytes, err := bbsPubKey.Marshal()
					require.NoError(t, err)
					require.Equal(t, bls12381G2Size, len(bbsPubKeyBytes))
					require.Equal(t, ecKty, jwkKey2.Kty)

					newJWK, err := PubKeyBytesToJWK(pkBytes, kms.BLS12381G2Type)
					require.NoError(t, err)
					require.NotNil(t, newJWK)
					require.Equal(t, bls12381G2Crv, newJWK.Crv)
					bbsPubKey, ok = newJWK.Key.(*bbs12381g2pub.PublicKey)
					require.True(t, ok)
					bbsPubKeyBytes, err = bbsPubKey.Marshal()
					require.NoError(t, err)
					require.Equal(t, bls12381G2Size, len(bbsPubKeyBytes))
					require.Equal(t, ecKty, newJWK.Kty)
				case "get public key bytes Ed25519 JWK":
					jwkKey3, err := JWKFromKey(jwkKey.Key)
					require.NoError(t, err)
					require.NotNil(t, jwkKey3)
					require.Equal(t, "Ed25519", jwkKey3.Crv)
					require.Equal(t, ed25519.PublicKeySize, len(jwkKey3.Key.(ed25519.PublicKey)))
					require.Equal(t, okpKty, jwkKey3.Kty)

					newJWK, err := PubKeyBytesToJWK(pkBytes, kms.ED25519Type)
					require.NoError(t, err)
					require.NotNil(t, newJWK)
					require.Equal(t, "Ed25519", newJWK.Crv)
					require.Equal(t, ed25519.PublicKeySize, len(newJWK.Key.(ed25519.PublicKey)))
					require.Equal(t, okpKty, newJWK.Kty)
				case "get public key bytes EC P-256 JWK":
					jwkKey4, err := JWKFromKey(jwkKey.Key)
					require.NoError(t, err)
					require.NotNil(t, jwkKey4)
					require.Equal(t, elliptic.P256().Params().Name, jwkKey4.Crv)
					require.Equal(t, "EC", jwkKey4.Kty)
					ecKey, ok := jwkKey4.Key.(*ecdsa.PublicKey)
					require.True(t, ok)
					require.Equal(t, "JR7nhI47w7bxrNkp7Xt1nbmozNn-RB2Q-PWi7KHT8J0",
						base64.RawURLEncoding.EncodeToString(ecKey.X.Bytes()))
					require.Equal(t, "iXmKtH0caOgB1vV0CQwinwK999qdDvrssKhdbiAz9OI",
						base64.RawURLEncoding.EncodeToString(ecKey.Y.Bytes()))

					newJWK, err := PubKeyBytesToJWK(pkBytes, kms.ECDSAP256TypeIEEEP1363)
					require.NoError(t, err)
					require.NotNil(t, newJWK)
					require.Equal(t, elliptic.P256().Params().Name, newJWK.Crv)
					require.Equal(t, "EC", newJWK.Kty)
					ecKey, ok = newJWK.Key.(*ecdsa.PublicKey)
					require.True(t, ok)
					require.Equal(t, "JR7nhI47w7bxrNkp7Xt1nbmozNn-RB2Q-PWi7KHT8J0",
						base64.RawURLEncoding.EncodeToString(ecKey.X.Bytes()))
					require.Equal(t, "iXmKtH0caOgB1vV0CQwinwK999qdDvrssKhdbiAz9OI",
						base64.RawURLEncoding.EncodeToString(ecKey.Y.Bytes()))
				case "get public key bytes EC P-384 JWK":
					jwkKey5, err := JWKFromKey(jwkKey.Key)
					require.NoError(t, err)
					require.NotNil(t, jwkKey5)
					require.Equal(t, elliptic.P384().Params().Name, jwkKey5.Crv)
					require.Equal(t, "EC", jwkKey5.Kty)
					ecKey, ok := jwkKey5.Key.(*ecdsa.PublicKey)
					require.True(t, ok)
					require.Equal(t, "GGFw14WnABx5S__MLwjy7WPgmPzCNbygbJikSqwx1nQ7APAiIyLeiAeZnAFQSr8C",
						base64.RawURLEncoding.EncodeToString(ecKey.X.Bytes()))
					require.Equal(t, "Bjev4lkaRbd4Ery0vnO8Ox4QgIDGbuflmFq0HhL-QHIe3KhqxrqZqbQYGlDNudEv",
						base64.RawURLEncoding.EncodeToString(ecKey.Y.Bytes()))

					newJWK, err := PubKeyBytesToJWK(pkBytes, kms.ECDSAP384TypeIEEEP1363)
					require.NoError(t, err)
					require.NotNil(t, newJWK)
					require.Equal(t, elliptic.P384().Params().Name, newJWK.Crv)
					require.Equal(t, "EC", newJWK.Kty)
					ecKey, ok = newJWK.Key.(*ecdsa.PublicKey)
					require.True(t, ok)
					require.Equal(t, "GGFw14WnABx5S__MLwjy7WPgmPzCNbygbJikSqwx1nQ7APAiIyLeiAeZnAFQSr8C",
						base64.RawURLEncoding.EncodeToString(ecKey.X.Bytes()))
					require.Equal(t, "Bjev4lkaRbd4Ery0vnO8Ox4QgIDGbuflmFq0HhL-QHIe3KhqxrqZqbQYGlDNudEv",
						base64.RawURLEncoding.EncodeToString(ecKey.Y.Bytes()))
				case "get public key bytes EC P-521 JWK":
					jwkKey6, err := JWKFromKey(jwkKey.Key)
					require.NoError(t, err)
					require.NotNil(t, jwkKey6)
					require.Equal(t, elliptic.P521().Params().Name, jwkKey6.Crv)
					require.Equal(t, "EC", jwkKey6.Kty)
					ecKey, ok := jwkKey6.Key.(*ecdsa.PublicKey)
					require.True(t, ok)
					require.Equal(t, "AZi-AxJkB09qw8dBnNrz53xM-wER0Y5IYXSEWSTtzI5Sdv_5XijQn9z-vGz1pMdww-C75GdpAzp2ghejZJSxbAd6",
						base64.RawURLEncoding.EncodeToString(ecKey.X.Bytes()))
					require.Equal(t, "AZzRvW8NBytGNbF3dyNOMHB0DHCOzGp8oYBv_ZCyJbQUUnq-TYX7j8-PlKe9Ce5acxZzrcUKVtJ4I8JgI5x9oXIW",
						base64.RawURLEncoding.EncodeToString(ecKey.Y.Bytes()))

					newJWK, err := PubKeyBytesToJWK(pkBytes, kms.ECDSAP521TypeIEEEP1363)
					require.NoError(t, err)
					require.NotNil(t, newJWK)
					require.Equal(t, elliptic.P521().Params().Name, newJWK.Crv)
					require.Equal(t, "EC", newJWK.Kty)
					ecKey, ok = newJWK.Key.(*ecdsa.PublicKey)
					require.True(t, ok)
					require.Equal(t, "AZi-AxJkB09qw8dBnNrz53xM-wER0Y5IYXSEWSTtzI5Sdv_5XijQn9z-vGz1pMdww-C75GdpAzp2ghejZJSxbAd6",
						base64.RawURLEncoding.EncodeToString(ecKey.X.Bytes()))
					require.Equal(t, "AZzRvW8NBytGNbF3dyNOMHB0DHCOzGp8oYBv_ZCyJbQUUnq-TYX7j8-PlKe9Ce5acxZzrcUKVtJ4I8JgI5x9oXIW",
						base64.RawURLEncoding.EncodeToString(ecKey.Y.Bytes()))
				default:
					jwkKey7, err := JWKFromKey(jwkKey.Key)
					require.NoError(t, err)
					require.NotNil(t, jwkKey7)
				}
			})
		}
	})
}

func TestJWKFromPublicKeyFailure(t *testing.T) {
	key, err := JWKFromKey(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "create JWK")
	require.Nil(t, key)
}

func TestJWKFromX25519KeyFailure(t *testing.T) {
	key, err := JWKFromX25519Key([]byte(strings.Repeat("a", 33))) // try to create a key larger than X25519
	require.EqualError(t, err, "create JWK: marshalX25519: invalid key")
	require.Nil(t, key)

	key, err = JWKFromX25519Key(nil) // try to create a nil key
	require.EqualError(t, err, "create JWK: marshalX25519: invalid key")
	require.Nil(t, key)
}

func TestBBSJWK(t *testing.T) {
	t.Run("test JWKFromKey() from BBS private key", func(t *testing.T) {
		var jwk1 *jwk.JWK

		_, privateKey, err := bbs12381g2pub.GenerateKeyPair(sha256.New, nil)
		require.NoError(t, err)

		jwkKey := &jwk.JWK{
			JSONWebKey: jose.JSONWebKey{
				Key: privateKey,
			},
			Kty: ecKty,
			Crv: bls12381G2Crv,
		}

		jwk1, err = JWKFromKey(privateKey)
		require.NoError(t, err)
		require.EqualValues(t, jwkKey, jwk1)
	})
}

func TestPubKeyBytesToJWK(t *testing.T) {
	tests := []struct {
		name    string
		keyType kms.KeyType
	}{
		{
			name:    "P-256 IEEE1363 test",
			keyType: kms.ECDSAP256TypeIEEEP1363,
		},
		{
			name:    "P-384 IEEE1363 test",
			keyType: kms.ECDSAP384TypeIEEEP1363,
		},
		{
			name:    "P-521 IEEE1363 test",
			keyType: kms.ECDSAP521TypeIEEEP1363,
		},
		{
			name:    "P-256 DER test",
			keyType: kms.ECDSAP256TypeDER,
		},
		{
			name:    "P-384 DER test",
			keyType: kms.ECDSAP384TypeDER,
		},
		{
			name:    "P-521 DER test",
			keyType: kms.ECDSAP521TypeDER,
		},
		{
			name:    "Ed25519 test",
			keyType: kms.ED25519Type,
		},
		{
			name:    "BLS12381G2 test",
			keyType: kms.BLS12381G2Type,
		},
		{
			name:    "X25519 test",
			keyType: kms.X25519ECDHKWType,
		},
		{
			name:    "P-256 KW test",
			keyType: kms.NISTP256ECDHKWType,
		},
		{
			name:    "P-384 KW test",
			keyType: kms.NISTP384ECDHKWType,
		},
		{
			name:    "P-521 KW test",
			keyType: kms.NISTP521ECDHKWType,
		},
		{
			name:    "undefined type test",
			keyType: "undefined",
		},
	}

	t.Parallel()

	for _, test := range tests {
		tc := test
		t.Run(tc.name, func(t *testing.T) {
			switch tc.keyType {
			case kms.ED25519Type:
				pubKey, _, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)

				jwkKey, err := PubKeyBytesToJWK(pubKey, tc.keyType)
				require.NoError(t, err)
				require.NotEmpty(t, jwkKey)
				require.Equal(t, okpKty, jwkKey.Kty)
				require.Equal(t, "Ed25519", jwkKey.Crv)
			case kms.BLS12381G2Type:
				pubKey, _, err := bbs12381g2pub.GenerateKeyPair(sha256.New, nil)
				require.NoError(t, err)

				keyBytes, err := pubKey.Marshal()
				require.NoError(t, err)

				jwkKey, err := PubKeyBytesToJWK(keyBytes, tc.keyType)
				require.NoError(t, err)
				require.NotEmpty(t, jwkKey)
				require.Equal(t, ecKty, jwkKey.Kty)
				require.Equal(t, bls12381G2Crv, jwkKey.Crv)

				_, err = PubKeyBytesToJWK([]byte("invalidbbsKey"), tc.keyType)
				require.EqualError(t, err, "invalid size of public key")
			case kms.ECDSAP256TypeIEEEP1363, kms.ECDSAP384TypeIEEEP1363, kms.ECDSAP521TypeIEEEP1363:
				crv := getECDSACurve(tc.keyType)
				privKey, err := ecdsa.GenerateKey(crv, rand.Reader)
				require.NoError(t, err)

				keyBytes := elliptic.Marshal(crv, privKey.X, privKey.Y)

				jwkKey, err := PubKeyBytesToJWK(keyBytes, tc.keyType)
				require.NoError(t, err)
				require.NotEmpty(t, jwkKey)
				require.Equal(t, "EC", jwkKey.Kty)
				require.Equal(t, crv.Params().Name, jwkKey.Crv)
			case kms.ECDSAP256TypeDER, kms.ECDSAP384TypeDER, kms.ECDSAP521TypeDER:
				crv := getECDSACurve(tc.keyType)
				privKey, err := ecdsa.GenerateKey(crv, rand.Reader)
				require.NoError(t, err)

				keyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
				require.NoError(t, err)

				jwkKey, err := PubKeyBytesToJWK(keyBytes, tc.keyType)
				require.NoError(t, err)
				require.NotEmpty(t, jwkKey)
				require.Equal(t, "EC", jwkKey.Kty)
				require.Equal(t, crv.Params().Name, jwkKey.Crv)

				_, err = PubKeyBytesToJWK([]byte("invalid EC Key"), tc.keyType)
				require.Error(t, err)
				require.Contains(t, err.Error(), "asn1: structure error: tags don't match")

				pubEdKey, _, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)

				pubEdKeyBytes, err := x509.MarshalPKIXPublicKey(pubEdKey)
				require.NoError(t, err)

				_, err = PubKeyBytesToJWK(pubEdKeyBytes, tc.keyType)
				require.EqualError(t, err, "invalid EC key")
			case kms.NISTP256ECDHKWType, kms.NISTP384ECDHKWType, kms.NISTP521ECDHKWType:
				crv := getECDSACurve(tc.keyType)
				privKey, err := ecdsa.GenerateKey(crv, rand.Reader)
				require.NoError(t, err)

				pubKey := &cryptoapi.PublicKey{
					X:     privKey.X.Bytes(),
					Y:     privKey.Y.Bytes(),
					Curve: crv.Params().Name,
					Type:  "EC",
				}

				keyBytes, err := json.Marshal(pubKey)
				require.NoError(t, err)

				jwkKey, err := PubKeyBytesToJWK(keyBytes, tc.keyType)
				require.NoError(t, err)
				require.NotEmpty(t, jwkKey)
				require.Equal(t, "EC", jwkKey.Kty)
				require.Equal(t, crv.Params().Name, jwkKey.Crv)

				_, err = PubKeyBytesToJWK([]byte("invalid EC Key"), tc.keyType)
				require.EqualError(t, err, "invalid character 'i' looking for beginning of value")
			case kms.X25519ECDHKWType:
				pubKeyBytes := make([]byte, 32)
				_, err := rand.Read(pubKeyBytes)
				require.NoError(t, err)

				jwkKey, err := PubKeyBytesToJWK(pubKeyBytes, tc.keyType)
				require.NoError(t, err)
				require.NotEmpty(t, jwkKey)
				require.Equal(t, okpKty, jwkKey.Kty)
				require.Equal(t, x25519Crv, jwkKey.Crv)
			default:
				_, err := PubKeyBytesToJWK([]byte{}, tc.keyType)
				require.EqualError(t, err, "convertPubKeyJWK: invalid key type: undefined")
			}
		})
	}
}

func TestEmptyCurve(t *testing.T) {
	crv := getECDSACurve(kms.ChaCha20Poly1305)
	require.Empty(t, crv)
}

func TestPublicKeyFromJWK(t *testing.T) {
	prv256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jwk256PrivKey, err := JWKFromKey(prv256Key)
	require.NoError(t, err)

	jwk256PubKey, err := JWKFromKey(&prv256Key.PublicKey)
	require.NoError(t, err)

	prv384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	jwk384PrivKey, err := JWKFromKey(prv384Key)
	require.NoError(t, err)

	jwk384PubKey, err := JWKFromKey(&prv384Key.PublicKey)
	require.NoError(t, err)

	prv521Key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	jwk521PrivKey, err := JWKFromKey(prv521Key)
	require.NoError(t, err)

	jwk521PubKey, err := JWKFromKey(&prv521Key.PublicKey)
	require.NoError(t, err)

	edPubKey, edPrivKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	jwkEdPrivKey, err := JWKFromKey(edPrivKey)
	require.NoError(t, err)

	jwkEdPubKey, err := JWKFromKey(edPubKey)
	require.NoError(t, err)

	bbsPubKey, bbsPrivKey, err := bbs12381g2pub.GenerateKeyPair(sha256.New, nil)
	require.NoError(t, err)

	jwkBLSPrivKey, err := JWKFromKey(bbsPrivKey)
	require.NoError(t, err)

	jwkBLSPubKey, err := JWKFromKey(bbsPubKey)
	require.NoError(t, err)

	tests := []struct {
		name   string
		jwkKey *jwk.JWK
	}{
		{
			name:   "success p-256 key from JWK with private key",
			jwkKey: jwk256PrivKey,
		},
		{
			name:   "success p-256 key from JWK with public key",
			jwkKey: jwk256PubKey,
		},
		{
			name:   "success p-384 key from JWK with private key",
			jwkKey: jwk384PrivKey,
		},
		{
			name:   "success p-384 key from JWK with public key",
			jwkKey: jwk384PubKey,
		},
		{
			name:   "success p-521 key from JWK with private key",
			jwkKey: jwk521PrivKey,
		},
		{
			name:   "success p-521 key from JWK with public key",
			jwkKey: jwk521PubKey,
		},
		{
			name:   "success ed25519 key from JWK with private key",
			jwkKey: jwkEdPrivKey,
		},
		{
			name:   "success ed25519 key from JWK with public key",
			jwkKey: jwkEdPubKey,
		},
		{
			name:   "success BBS key from JWK with private key",
			jwkKey: jwkBLSPrivKey,
		},
		{
			name:   "success BBS key from JWK with public key",
			jwkKey: jwkBLSPubKey,
		},
		{
			name: "fail invalid key type",
			jwkKey: &jwk.JWK{
				JSONWebKey: jose.JSONWebKey{
					Key: "badKeytype",
				},
				Kty: "",
				Crv: "",
			},
		},
	}

	for _, tt := range tests {
		tc := tt

		t.Run(tc.name, func(t *testing.T) {
			var pubKey *cryptoapi.PublicKey

			pubKey, err = PublicKeyFromJWK(tc.jwkKey)
			if strings.HasPrefix(tc.name, "success ") {
				require.NoError(t, err)
				require.Equal(t, tc.jwkKey.Crv, pubKey.Curve)
			} else if strings.EqualFold(tc.name, "fail invalid key type") {
				require.EqualError(t, err, fmt.Sprintf("publicKeyFromJWK: unsupported jwk key type %T", tc.jwkKey.Key))
			}
		})
	}

	t.Run("failure with empty jwk", func(t *testing.T) {
		_, err = PublicKeyFromJWK(nil)
		require.EqualError(t, err, "publicKeyFromJWK: jwk is empty")
	})
}
