/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jose

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/square/go-jose/v3"
	"github.com/square/go-jose/v3/json"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

func TestHeaders_GetJWK(t *testing.T) {
	headers := Headers{}

	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	jwk := JWK{
		JSONWebKey: jose.JSONWebKey{
			Key:       pubKey,
			KeyID:     "kid",
			Algorithm: "EdDSA",
		},
	}

	jwkBytes, err := json.Marshal(&jwk)
	require.NoError(t, err)

	var jwkMap map[string]interface{}

	err = json.Unmarshal(jwkBytes, &jwkMap)
	require.NoError(t, err)

	headers["jwk"] = jwkMap

	parsedJWK, ok := headers.JWK()
	require.True(t, ok)
	require.NotNil(t, parsedJWK)

	// jwk is not present
	delete(headers, "jwk")
	parsedJWK, ok = headers.JWK()
	require.False(t, ok)
	require.Nil(t, parsedJWK)

	// jwk is not a map
	headers["jwk"] = "not a map"
	parsedJWK, ok = headers.JWK()
	require.False(t, ok)
	require.Nil(t, parsedJWK)
}

func TestDecodePublicKey(t *testing.T) {
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
							"kty": "OKP",
							"use": "enc",
							"crv": "BLS12381G2",
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
				name: "get public key bytes EC P-526 JWK",
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
				var jwk JWK

				err := json.Unmarshal([]byte(tc.jwkJSON), &jwk)
				require.NoError(t, err)

				pkBytes, err := jwk.PublicKeyBytes()
				require.NoError(t, err)
				require.NotEmpty(t, pkBytes)

				jwkBytes, err := json.Marshal(&jwk)
				require.NoError(t, err)
				require.NotEmpty(t, jwkBytes)

				switch tc.name {
				case "get public key bytes X25519 JWK":
					jwkKey, err := JWKFromX25519Key(jwk.Key.([]byte))
					require.NoError(t, err)
					require.NotNil(t, jwkKey)
					require.Equal(t, x25519Crv, jwkKey.Crv)
					require.Equal(t, cryptoutil.Curve25519KeySize, len(jwkKey.Key.([]byte)))
					require.Equal(t, okpKty, jwkKey.Kty)
				case "get public key bytes BBS+ JWK":
					jwkKey, err := JWKFromKey(jwk.Key)
					require.NoError(t, err)
					require.NotNil(t, jwkKey)
					require.Equal(t, bls12381G2Crv, jwkKey.Crv)
					bbsPubKey, ok := jwkKey.Key.(*bbs12381g2pub.PublicKey)
					require.True(t, ok)
					bbsPubKeyBytes, err := bbsPubKey.Marshal()
					require.NoError(t, err)
					require.Equal(t, bls12381G2Size, len(bbsPubKeyBytes))
					require.Equal(t, okpKty, jwkKey.Kty)
				default:
					jwkKey, err := JWKFromKey(jwk.Key)
					require.NoError(t, err)
					require.NotNil(t, jwkKey)
				}
			})
		}
	})

	t.Run("Test decode public key failure", func(t *testing.T) {
		tests := []struct {
			name    string
			jwkJSON string
			err     string
		}{
			{
				name:    "attempt public key bytes from invalid JSON bytes",
				jwkJSON: `}`,
				err:     "invalid character",
			},
			{
				name: "attempt public key bytes from invalid curve",
				jwkJSON: `{
							"kty": "EC",
    						"use": "enc",
    						"crv": "sec12341",
    						"kid": "sample@sample.id",
    						"x": "wQehEGTVCu32yp8IwTaBCqPUIYslyd-WoFRsfDKE9II",
    						"y": "rIJO8RmkExUecJ5i15L9OC7rl7pwmYFR8QQgdM1ERWI",
   						 	"alg": "ES256"
						}`,
				err: "unsupported elliptic curve 'sec12341'",
			},
			{
				name: "attempt public key bytes from invalid JSON bytes",
				jwkJSON: `{
							"kty": "EC",
    						"use": "enc",
    						"crv": "secp256k1",
    						"kid": "sample@sample.id",
    						"x": "",
    						"y": "",
   						 	"alg": "ES256"
						}`,
				err: "unable to read JWK: invalid JWK",
			},
			{
				name: "attempt public key bytes from invalid JSON bytes",
				jwkJSON: `{
							"kty": "EC",
    						"use": "enc",
    						"crv": "secp256k1",
    						"kid": "sample@sample.id",
    						"x": "wQehEGTVCu32yp8IwTaBCqPUIYslyd-WoFRsfDKE9II",
    						"y": "",
   						 	"alg": "ES256"
						}`,
				err: "unable to read JWK: invalid JWK",
			},
			{
				name: "attempt public key bytes from invalid JSON bytes",
				jwkJSON: `{
							"kty": "EC",
    						"use": "enc",
    						"crv": "secp256k1",
    						"kid": "sample@sample.id",
    						"x": "x",
    						"y": "y",
   						 	"alg": "ES256"
						}`,
				err: "unable to read JWK",
			},
			{
				name: "X is not defined",
				jwkJSON: `{
							"kty": "EC",
    						"use": "enc",
    						"crv": "secp256k1",
    						"kid": "sample@sample.id",
    						"y": "rIJO8RmkExUecJ5i15L9OC7rl7pwmYFR8QQgdM1ERWI",
   						 	"alg": "ES256"
						}`,
				err: "invalid JWK",
			},
			{
				name: "X is not defined X25519",
				jwkJSON: `{
    						"kty": "OKP",
    						"use": "enc",
    						"crv": "X25519",
    						"kid": "sample@sample.id"
						}`,
				err: "invalid JWK",
			},
			{
				name: "Y is not defined",
				jwkJSON: `{
							"kty": "EC",
    						"use": "enc",
    						"crv": "secp256k1",
    						"kid": "sample@sample.id",
    						"x": "wQehEGTVCu32yp8IwTaBCqPUIYslyd-WoFRsfDKE9II",
   						 	"alg": "ES256"
						}`,
				err: "invalid JWK",
			},
			{
				name: "Y is not defined",
				jwkJSON: `{
							"kty": "EC",
    						"use": "enc",
    						"crv": "secp256k1",
    						"kid": "sample@sample.id",
    						"x": "wQehEGTVCu32yp8IwTaBCqPUIYslyd-WoFRsfDKE9II",
    						"y": "rIJO8RmkExUecJ5i15L9OC7rl7pwmYFR8QQgdM1ERWI",
							"d": "",
							"alg": "ES256"
						}`,
				err: "invalid JWK",
			},
			{
				name: "Y is not defined",
				jwkJSON: `{
							"kty": "EC",
    						"use": "enc",
    						"crv": "secp256k1",
    						"kid": "sample@sample.id",
    						"x": "wQehEGTVCu32yp8IwTaBCqPUIYslyd-WoFRsfDKE9II",
    						"y": "rIJO8RmkExUecJ5i15L9OC7rl7pwmYFR8QQgdM1ERWO",
							"alg": "ES256"
						}`,
				err: "unable to read JWK: invalid JWK",
			},
			{
				name: "attempt public key bytes from invalid JSON bytes",
				jwkJSON: `{
							"kty": "EC",
    						"use": "enc",
    						"crv": "secp256k1",
    						"kid": "sample@sample.id",
    						"x": "{",
    						"y": "y",
   						 	"alg": "ES256"
						}`,
				err: "unable to read JWK",
			},
			{
				name: "invalid X25519",
				jwkJSON: `{
    						"kty": "OKP",
    						"use": "enc",
    						"crv": "X25519",
    						"x": "wQehEGTVCu32yp8IwTaBCqPUIYslyd-WoFRsfDKE9IIrIJO8RmkExUecJ5i15L9OC7rl7pwmYFR8QQgdM1ERWO",
    						"kid": "sample@sample.id"
						}`,
				err: "unable to read X25519 JWE: invalid JWK",
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.name, func(t *testing.T) {
				var jwk JWK
				err := json.Unmarshal([]byte(tc.jwkJSON), &jwk)
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.err)
			})
		}
	})
}

func TestByteBufferUnmarshalFailure(t *testing.T) {
	bb := &byteBuffer{}
	err := bb.UnmarshalJSON([]byte("{"))
	require.Error(t, err)
}

func TestCurveSize(t *testing.T) {
	require.Equal(t, 32, curveSize(btcec.S256()))
	require.Equal(t, 32, curveSize(elliptic.P256()))
	require.Equal(t, 28, curveSize(elliptic.P224()))
	require.Equal(t, 48, curveSize(elliptic.P384()))
	require.Equal(t, 66, curveSize(elliptic.P521()))
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

	key = &JWK{
		JSONWebKey: jose.JSONWebKey{
			Key: "abc", // try to create an invalid X25519 key type (string instead of []byte)
		},
	}

	_, err = marshalX25519(key)
	require.EqualError(t, err, "marshalX25519: invalid key")
}

func TestJWK_PublicKeyBytesValidation(t *testing.T) {
	jwk := &JWK{
		JSONWebKey: jose.JSONWebKey{
			Key:   "key of invalid type",
			KeyID: "pubkey#123",
		},
	}

	// unsupported public key type
	pkBytes, err := jwk.PublicKeyBytes()
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported public key type in kid 'pubkey#123'")
	require.Empty(t, pkBytes)
}

func TestJWK_BBSKeyValidation(t *testing.T) {
	_, privateKey, err := bbs12381g2pub.GenerateKeyPair(sha256.New, nil)
	require.NoError(t, err)

	jwk := &JWK{
		JSONWebKey: jose.JSONWebKey{
			Key: privateKey,
		},
		Kty: okpKty,
		Crv: bls12381G2Crv,
	}

	t.Run("test MarshalJSON/UnmarshalJSON", func(t *testing.T) {
		var mJWK []byte

		mJWK, err = jwk.MarshalJSON()
		require.NoError(t, err)

		t.Logf("marshaled JWK: %s", mJWK)

		jwk2 := &JWK{}
		err = jwk2.UnmarshalJSON(mJWK)
		require.NoError(t, err)
		require.EqualValues(t, jwk, jwk2)
	})

	t.Run("test JWKFromKey() from BBS private key", func(t *testing.T) {
		var jwk3 *JWK

		jwk3, err = JWKFromKey(privateKey)
		require.NoError(t, err)
		require.EqualValues(t, jwk, jwk3)
	})

	t.Run("test BBS private key jwk.PublicKeyBytes()", func(t *testing.T) {
		var pubKeyBytes []byte

		pubKeyBytes, err = jwk.PublicKeyBytes()
		require.NoError(t, err)
		require.NotEmpty(t, pubKeyBytes)
	})

	t.Run("test UnmarshalJSON of valid BBS private key JWK - with both x and d headers", func(t *testing.T) {
		//nolint:lll
		goodJWK := `{
	"kty":"OKP",
	"crv":"BLS12381G2",
	"x":"oUd1c-NsWZy2oCaST4CRW1naLjgYY3OhHgTMie4uzgrB5VuVqx0pdYf4XWWlnEkZERnpMhgo2re4tQtdCguhI4OIGyAXFaML8D6E1ZYO8B0WmysMZUnC5BWWEfOid1lu",
	"d":"MhYilAbhICa8T6m0U2gLAgLvPEsF05XN1yYHZgkfAK4"
}`

		jwk4 := &JWK{}

		err = jwk4.UnmarshalJSON([]byte(goodJWK))
		require.NoError(t, err)
	})

	t.Run("test UnmarshalJSON of invalid BBS private key JWK - no x header", func(t *testing.T) {
		goodJWK := `{
	"kty":"OKP",
	"crv":"BLS12381G2",
	"d":"MhYilAbhICa8T6m0U2gLAgLvPEsF05XN1yYHZgkfAK4"
}`

		jwk4 := &JWK{}

		err = jwk4.UnmarshalJSON([]byte(goodJWK))
		require.EqualError(t, err, "unable to read BBS+ JWE: invalid JWK")
	})

	t.Run("test UnmarshalJSON of valid BBS public key JWK", func(t *testing.T) {
		//nolint:lll
		goodJWK := `{
	"kty":"OKP",
	"crv":"BLS12381G2",
	"x":"oUd1c-NsWZy2oCaST4CRW1naLjgYY3OhHgTMie4uzgrB5VuVqx0pdYf4XWWlnEkZERnpMhgo2re4tQtdCguhI4OIGyAXFaML8D6E1ZYO8B0WmysMZUnC5BWWEfOid1lu"
}`

		jwk4 := &JWK{}

		err = jwk4.UnmarshalJSON([]byte(goodJWK))
		require.NoError(t, err)
	})

	t.Run("test UnmarshalJSON of invalid BBS public key JWK - x wrong size", func(t *testing.T) {
		goodJWK := `{
	"kty":"OKP",
	"crv":"BLS12381G2",
	"x":"oUd1"
}`

		jwk4 := &JWK{}

		err = jwk4.UnmarshalJSON([]byte(goodJWK))
		require.EqualError(t, err, "unable to read BBS+ JWE: invalid JWK")
	})

	t.Run("test UnmarshalJSON of invalid BBS private key JWK - d wrong size", func(t *testing.T) {
		//nolint:lll
		goodJWK := `{
	"kty":"OKP",
	"crv":"BLS12381G2",
	"x":"oUd1c-NsWZy2oCaST4CRW1naLjgYY3OhHgTMie4uzgrB5VuVqx0pdYf4XWWlnEkZERnpMhgo2re4tQtdCguhI4OIGyAXFaML8D6E1ZYO8B0WmysMZUnC5BWWEfOid1lu",
	"d":"MhYi"
}`

		jwk4 := &JWK{}

		err = jwk4.UnmarshalJSON([]byte(goodJWK))
		require.EqualError(t, err, "unable to read BBS+ JWE: invalid JWK")
	})
}

func TestJWK_KeyType(t *testing.T) {
	t.Run("success: get KeyType from JWK", func(t *testing.T) {
		testCases := []struct {
			jwk     string
			keyType kms.KeyType
		}{
			{
				jwk: `{
					"kty": "OKP",
					"use": "enc",
					"crv": "Ed25519",
					"kid": "sample@sample.id",
					"x": "sEHL6KXs8bUz9Ss2qSWWjhhRMHVjrog0lzFENM132R8",
					"alg": "EdDSA"
				}`,
				keyType: kms.ED25519Type,
			},
			{
				jwk: `{
					"kty": "OKP",
					"use": "enc",
					"crv": "X25519",
					"kid": "sample@sample.id",
					"x": "sEHL6KXs8bUz9Ss2qSWWjhhRMHVjrog0lzFENM132R8"
				}`,
				keyType: kms.X25519ECDHKWType,
			},
			{
				//nolint:lll
				jwk: `{
					"kty": "OKP",
					"use": "enc",
					"crv": "BLS12381G2",
					"kid": "sample@sample.id",
					"x": "tKWJu0SOY7onl4tEyOOH11XBriQN2JgzV-UmjgBMSsNkcAx3_l97SVYViSDBouTVBkBfrLh33C5icDD-4UEDxNO3Wn1ijMHvn2N63DU4pkezA3kGN81jGbwbrsMPpiOF"
				}`,
				keyType: kms.BLS12381G2Type,
			},
			{
				jwk: `{
					"kty": "EC",
					"use": "enc",
					"crv": "secp256k1",
					"kid": "sample@sample.id",
					"x": "YRrvJocKf39GpdTnd-zBFE0msGDqawR-Cmtc6yKoFsM",
					"y": "kE-dMH9S3mxnTXo0JFEhraCU_tVYFDfpu9tpP1LfVKQ",
					"alg": "ES256K"
				}`,
				keyType: kms.ECDSASecp256k1TypeIEEEP1363,
			},
			{
				jwk: `{
					"kty": "EC",
					"use": "enc",
					"crv": "P-256",
					"kid": "sample@sample.id",
					"x": "JR7nhI47w7bxrNkp7Xt1nbmozNn-RB2Q-PWi7KHT8J0",
					"y": "iXmKtH0caOgB1vV0CQwinwK999qdDvrssKhdbiAz9OI",
					"alg": "ES256"
				}`,
				keyType: kms.ECDSAP256TypeIEEEP1363,
			},
			{
				jwk: `{
					"kty": "EC",
					"kid": "sample@sample.id",
					"crv": "P-384",
					"x": "SNJT8Q-irydV5yppI-blGNuRTPf8sCYuL_tO92SLrufdlEgDll9cRuBLACrlBz2x",
					"y": "zIYfra2_y2hnc35sIwA1jiDx5rKmG3mX6162HkAodTJIpUYxw2rz1qHiwVcaU2tY",
					"alg": "ES384"
				}`,
				keyType: kms.ECDSAP384TypeIEEEP1363,
			},
			{
				jwk: `{
					"kty": "EC",
					"kid": "sample@sample.id",
					"crv": "P-521",
					"d": "AfcmEHp9Nd_X005hBoKEs8bvMzIH0OMYodQUw8xRWpUGOq31cyXV1dUvX-S8uSaBIbh2w-fy_OaolBmvTe3Il5Rw",
					"x": "AMIjmQpOT7oz5e8CJZQVi3cxCdF0gdmnNE8qmi5Y3_1-6gRzHoaXGs_TBcAvNgD8UCYhk3FWA8aLChJ9BjEUi44m",
					"y": "AIfNzFdbyI1rfRrcY7orl3wTXT-C_kWhyWdr3K3rSS8WbwXhqg9jb29iEoE8izpCnuoJbC_FsMf2WbI_1iNomfB4",
					"alg": "ES512"
				}`,
				keyType: kms.ECDSAP521TypeIEEEP1363,
			},
		}

		t.Parallel()

		for _, testCase := range testCases {
			t.Run(fmt.Sprintf("KeyType %s", testCase.keyType), func(t *testing.T) {
				j := JWK{}
				e := j.UnmarshalJSON([]byte(testCase.jwk))
				require.NoError(t, e)

				kt, e := j.KeyType()
				require.NoError(t, e)
				require.Equal(t, testCase.keyType, kt)
			})
		}
	})

	t.Run("fail to get KeyType from JWK", func(t *testing.T) {
		// RSA keys not currently supported by JWK.KeyType(), replace with another if RSA gets supported
		keyJSON := `{
			"kty": "RSA",
			"e": "AQAB",
			"use": "enc",
			"kid": "sample@sample.id",
			"alg": "RS256",
			"n": "1hOl09BUnwY7jFBqoZKa4XDmIuc0YFb4y_5ThiHhLRW68aNG5Vo23n3ugND2GK3PsguZqJ_HrWCGVuVlKTmFg` +
			`JWQD9ZnVcYqScgHpQRhxMBi86PIvXR01D_PWXZZjvTRakpvQxUT5bVBdWnaBHQoxDBt0YIVi5a7x-gXB1aDlts4RTMpfS9BPmEjX` +
			`4lciozwS6Ow_wTO3C2YGa_Our0ptIxr-x_3sMbPCN8Fe_iaBDezeDAm39xCNjFa1E735ipXA4eUW_6SzFJ5-bM2UKba2WE6xUaEa5G1` +
			`MDDHCG5LKKd6Mhy7SSAzPOR2FTKYj89ch2asCPlbjHTu8jS6Iy8"
		}`

		j := JWK{}
		e := j.UnmarshalJSON([]byte(keyJSON))
		require.NoError(t, e)

		kt, e := j.KeyType()
		require.Error(t, e)
		require.Equal(t, kms.KeyType(""), kt)
		require.Contains(t, e.Error(), "no keytype recognized for jwk")
	})

	t.Run("test ed25519 with []byte key material", func(t *testing.T) {
		jwkJSON := `{
			"kty": "OKP",
			"use": "enc",
			"crv": "Ed25519",
			"kid": "sample@sample.id",
			"x": "sEHL6KXs8bUz9Ss2qSWWjhhRMHVjrog0lzFENM132R8",
			"alg": "EdDSA"
		}`

		j := JWK{}
		e := j.UnmarshalJSON([]byte(jwkJSON))
		require.NoError(t, e)

		k, err := j.PublicKeyBytes()
		require.NoError(t, err)

		j.Key = k

		kt, e := j.KeyType()
		require.NoError(t, e)
		require.Equal(t, kms.ED25519Type, kt)
	})

	t.Run("test secp256k1 with []byte key material", func(t *testing.T) {
		jwkJSON := `{
			"kty": "EC",
			"use": "enc",
			"crv": "secp256k1",
			"kid": "sample@sample.id",
			"x": "YRrvJocKf39GpdTnd-zBFE0msGDqawR-Cmtc6yKoFsM",
			"y": "kE-dMH9S3mxnTXo0JFEhraCU_tVYFDfpu9tpP1LfVKQ",
			"alg": "ES256K"
		}`

		j := JWK{}
		e := j.UnmarshalJSON([]byte(jwkJSON))
		require.NoError(t, e)

		pkb, err := j.PublicKeyBytes()
		require.NoError(t, err)

		j.Key = pkb

		kt, e := j.KeyType()
		require.NoError(t, e)
		require.Equal(t, kms.ECDSASecp256k1TypeIEEEP1363, kt)
	})

	t.Run("fail to get ecdsa keytype for (unsupported) p-224", func(t *testing.T) {
		eckey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		require.NoError(t, err)

		kt, err := ecdsaPubKeyType(&eckey.PublicKey)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no keytype recognized for ecdsa jwk")
		require.Equal(t, kms.KeyType(""), kt)
	})
}
