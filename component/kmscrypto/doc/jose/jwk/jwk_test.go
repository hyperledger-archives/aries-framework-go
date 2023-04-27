/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/json"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/spi/kms"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
)

func TestDecodePublicKey(t *testing.T) {
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
				name: "D is not defined",
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
				var j JWK
				err := json.Unmarshal([]byte(tc.jwkJSON), &j)
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

func TestJWKFromX25519KeyFailure(t *testing.T) {
	key := &JWK{
		JSONWebKey: jose.JSONWebKey{
			Key: "abc", // try to create an invalid X25519 key type (string instead of []byte)
		},
	}

	_, err := marshalX25519(key)
	require.EqualError(t, err, "marshalX25519: invalid key")

	invalidKey := make([]byte, 10)

	n, err := rand.Read(invalidKey)
	require.NoError(t, err)
	require.Equal(t, 10, n)

	key.Key = invalidKey // try with key larger than X25519 key length

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

	jwkKey := &JWK{
		JSONWebKey: jose.JSONWebKey{
			Key: privateKey,
		},
		Kty: ecKty,
		Crv: bls12381G2Crv,
	}

	t.Run("test MarshalJSON/UnmarshalJSON", func(t *testing.T) {
		var mJWK []byte

		mJWK, err = jwkKey.MarshalJSON()
		require.NoError(t, err)

		t.Logf("marshaled JWK: %s", mJWK)

		jwk2 := &JWK{}
		err = jwk2.UnmarshalJSON(mJWK)
		require.NoError(t, err)
		require.EqualValues(t, jwkKey, jwk2)
	})

	t.Run("test BBS private key jwk.PublicKeyBytes()", func(t *testing.T) {
		var pubKeyBytes []byte

		pubKeyBytes, err = jwkKey.PublicKeyBytes()
		require.NoError(t, err)
		require.NotEmpty(t, pubKeyBytes)
	})

	t.Run("test UnmarshalJSON of valid BBS private key JWK - with both x and d headers", func(t *testing.T) {
		//nolint:lll
		goodJWK := `{
	"kty":"EC",
	"crv":"BLS12381_G2",
	"x":"oUd1c-NsWZy2oCaST4CRW1naLjgYY3OhHgTMie4uzgrB5VuVqx0pdYf4XWWlnEkZERnpMhgo2re4tQtdCguhI4OIGyAXFaML8D6E1ZYO8B0WmysMZUnC5BWWEfOid1lu",
	"d":"MhYilAbhICa8T6m0U2gLAgLvPEsF05XN1yYHZgkfAK4"
}`

		jwk4 := &JWK{}

		err = jwk4.UnmarshalJSON([]byte(goodJWK))
		require.NoError(t, err)
	})

	t.Run("test UnmarshalJSON of invalid BBS private key JWK - no x header", func(t *testing.T) {
		goodJWK := `{
	"kty":"EC",
	"crv":"BLS12381_G2",
	"d":"MhYilAbhICa8T6m0U2gLAgLvPEsF05XN1yYHZgkfAK4"
}`

		jwk4 := &JWK{}

		err = jwk4.UnmarshalJSON([]byte(goodJWK))
		require.EqualError(t, err, "unable to read BBS+ JWE: invalid JWK")
	})

	t.Run("test UnmarshalJSON of valid BBS public key JWK", func(t *testing.T) {
		//nolint:lll
		goodJWK := `{
	"kty":"EC",
	"crv":"BLS12381_G2",
	"x":"oUd1c-NsWZy2oCaST4CRW1naLjgYY3OhHgTMie4uzgrB5VuVqx0pdYf4XWWlnEkZERnpMhgo2re4tQtdCguhI4OIGyAXFaML8D6E1ZYO8B0WmysMZUnC5BWWEfOid1lu"
}`

		jwk4 := &JWK{}

		err = jwk4.UnmarshalJSON([]byte(goodJWK))
		require.NoError(t, err)
	})

	t.Run("test UnmarshalJSON of invalid BBS public key JWK - x wrong size", func(t *testing.T) {
		goodJWK := `{
	"kty":"EC",
	"crv":"BLS12381_G2",
	"x":"oUd1"
}`

		jwk4 := &JWK{}

		err = jwk4.UnmarshalJSON([]byte(goodJWK))
		require.EqualError(t, err, "unable to read BBS+ JWE: invalid JWK")
	})

	t.Run("test UnmarshalJSON of invalid BBS private key JWK - d wrong size", func(t *testing.T) {
		//nolint:lll
		goodJWK := `{
	"kty":"EC",
	"crv":"BLS12381_G2",
	"x":"oUd1c-NsWZy2oCaST4CRW1naLjgYY3OhHgTMie4uzgrB5VuVqx0pdYf4XWWlnEkZERnpMhgo2re4tQtdCguhI4OIGyAXFaML8D6E1ZYO8B0WmysMZUnC5BWWEfOid1lu",
	"d":"MhYi"
}`

		jwk4 := &JWK{}

		err = jwk4.UnmarshalJSON([]byte(goodJWK))
		require.EqualError(t, err, "unable to read BBS+ JWE: invalid JWK")
	})

	t.Run("test UnmarshalJSON of invalid BBS public key JWK - x wrong value", func(t *testing.T) {
		//nolint:lll
		goodJWK := `{
	"kty":"EC",
	"crv":"BLS12381_G2",
	"x":"pUd1c-NsWZy2oCaST4CRW1naLjgYY3OhHgTMie4uzgrB5VuVqx0pdYf4XWWlnEkZERnpMhko2re4tQtdCguhI4OIGyAXFaML8D6E1ZYO8B0WmysMZUnC5BWWEfOhc6tv"
}`

		jwk4 := &JWK{}

		err = jwk4.UnmarshalJSON([]byte(goodJWK))
		require.EqualError(t, err, "unable to read BBS+ JWE: jwk invalid public key unmarshal: deserialize "+
			"public key: failure [set bytes failed [point is not on curve]]")
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
					"kty": "EC",
					"use": "enc",
					"crv": "BLS12381_G2",
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
			{
				jwk: `{
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
				keyType: kms.RSAPS256Type,
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

				mJWK, err := j.MarshalJSON()
				require.NoError(t, err)
				require.NotEmpty(t, mJWK)

				keyBytes, err := j.PublicKeyBytes()
				require.NoError(t, err)
				require.NotEmpty(t, keyBytes)
			})
		}
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
