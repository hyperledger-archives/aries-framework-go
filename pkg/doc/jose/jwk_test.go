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
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/square/go-jose/v3"
	"github.com/square/go-jose/v3/json"
	"github.com/stretchr/testify/require"
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

func TestJWK_PublicKeyBytesValidation(t *testing.T) {
	// invalid public key
	privKey, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	require.NoError(t, err)

	jwk := &JWK{
		JSONWebKey: jose.JSONWebKey{
			Key:       &privKey.PublicKey,
			Algorithm: "ES256",
			KeyID:     "pubkey#123",
		},
		Crv: "P-256",
		Kty: "EC",
	}

	pkBytes, err := jwk.PublicKeyBytes()
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to read public key bytes")
	require.Empty(t, pkBytes)

	// unsupported public key type
	jwk.Key = "key of invalid type"
	pkBytes, err = jwk.PublicKeyBytes()
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported public key type in kid 'pubkey#123'")
	require.Empty(t, pkBytes)
}
