/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"

	btcec "github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/stretchr/testify/require"
)

const jwtTestCredential = `
{
	"@context": [
	  "https://www.w3.org/2018/credentials/v1",
	  "https://www.w3.org/2018/credentials/examples/v1"
	],
	"type": ["VerifiableCredential", "UniversityDegreeCredential"],
	"credentialSubject": {
	  "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
	  "degree": {
		"type": "BachelorDegree",
		"university": "MIT"
	  }
	},
  "issuer": {
    "id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
    "name": "Example University"
  },
  "issuanceDate": "2010-01-01T19:23:24Z",
  "expirationDate": "2020-01-01T19:23:24Z"
}
`

const keyID = "1"

func TestNewCredentialFromJWS(t *testing.T) {
	testCred := []byte(jwtTestCredential)

	keyFetcher := createKeyFetcher(t)

	t.Run("Decoding credential from JWS", func(t *testing.T) {
		vcFromJWT, _, err := NewCredential(
			createJWS(t, testCred, false),
			WithPublicKeyFetcher(keyFetcher))

		require.NoError(t, err)

		vc, _, err := NewCredential(testCred)
		require.NoError(t, err)

		require.Equal(t, vc, vcFromJWT)
	})

	t.Run("Decoding credential from JWS with minimized fields of \"vc\" claim", func(t *testing.T) {
		vcFromJWT, _, err := NewCredential(
			createJWS(t, testCred, true),
			WithPublicKeyFetcher(keyFetcher))

		require.NoError(t, err)

		vc, _, err := NewCredential(testCred)
		require.NoError(t, err)

		require.Equal(t, vc, vcFromJWT)
	})

	t.Run("Failed JWT signature verification of credential", func(t *testing.T) {
		vc, vcBytes, err := NewCredential(
			createJWS(t, testCred, true),
			// passing holder's key, while expecting issuer one
			WithPublicKeyFetcher(func(issuerID, keyID string) (interface{}, error) {
				publicKey, err := readPublicKey(filepath.Join(certPrefix, "holder_public.pem"))
				require.NoError(t, err)
				require.NotNil(t, publicKey)

				return publicKey, nil
			}))

		require.Error(t, err)
		require.Contains(t, err.Error(), "JWS decoding: unmarshal VC JWT claims")
		require.Nil(t, vc)
		require.Nil(t, vcBytes)
	})

	t.Run("Failed public key fetching", func(t *testing.T) {
		vc, vcBytes, err := NewCredential(
			createJWS(t, testCred, true),

			WithPublicKeyFetcher(func(issuerID, keyID string) (interface{}, error) {
				return nil, errors.New("test: public key is not found")
			}))

		require.Error(t, err)
		require.Nil(t, vc)
		require.Nil(t, vcBytes)
	})

	t.Run("Not defined public key fetcher", func(t *testing.T) {
		vc, vcBytes, err := NewCredential(createJWS(t, testCred, true))

		require.Error(t, err)
		require.Contains(t, err.Error(), "public key fetcher is not defined")
		require.Nil(t, vc)
		require.Nil(t, vcBytes)
	})
}

func TestNewCredentialFromJWS_EdDSA(t *testing.T) {
	vcBytes := []byte(jwtTestCredential)

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	vc, _, err := NewCredential(vcBytes)
	require.NoError(t, err)

	// marshal credential into JWS using EdDSA (Ed25519 signature algorithm).
	jwtClaims, err := vc.JWTClaims(false)
	require.NoError(t, err)
	vcJWSStr, err := jwtClaims.MarshalJWS(EdDSA, privKey, vc.Issuer.ID+"#keys-"+keyID)
	require.NoError(t, err)

	// unmarshal credential from JWS
	vcFromJWS, _, err := NewCredential(
		[]byte(vcJWSStr),
		WithPublicKeyFetcher(SingleKey(pubKey)))
	require.NoError(t, err)

	// unmarshalled credential must be the same as original one
	require.Equal(t, vc, vcFromJWS)
}

func TestNewCredentialFromJWS_ES256K(t *testing.T) {
	vcBytes := []byte(jwtTestCredential)

	privateKey, err := btcec.GeneratePrivateKey()
	require.NoError(t, err)

	vc, _, err := NewCredential(vcBytes)
	require.NoError(t, err)

	// marshal credential into JWS using EdDSA (Ed25519 signature algorithm).
	jwtClaims, err := vc.JWTClaims(false)
	require.NoError(t, err)
	vcJWSStr, err := jwtClaims.MarshalJWS(ES256K, privateKey.ToECDSA(), vc.Issuer.ID+"#keys-"+keyID)
	require.NoError(t, err)

	// unmarshal credential from JWS
	vcFromJWS, _, err := NewCredential(
		[]byte(vcJWSStr),
		WithPublicKeyFetcher(SingleKey(privateKey.PubKey().ToECDSA())))
	require.NoError(t, err)

	// unmarshalled credential must be the same as original one
	require.Equal(t, vc, vcFromJWS)
}

func TestNewCredentialFromUnsecuredJWT(t *testing.T) {
	testCred := []byte(jwtTestCredential)

	t.Run("Unsecured JWT decoding with no fields minimization", func(t *testing.T) {
		vcFromJWT, _, err := NewCredential(createUnsecuredJWT(t, testCred, false))

		require.NoError(t, err)

		vc, _, err := NewCredential(testCred)
		require.NoError(t, err)

		require.Equal(t, vc, vcFromJWT)
	})

	t.Run("Unsecured JWT decoding with minimized fields", func(t *testing.T) {
		vcFromJWT, _, err := NewCredential(createUnsecuredJWT(t, testCred, true))

		require.NoError(t, err)

		vc, _, err := NewCredential(testCred)
		require.NoError(t, err)

		require.Equal(t, vc, vcFromJWT)
	})
}

func TestJwtWithExtension(t *testing.T) {
	keyFetcher := WithPublicKeyFetcher(createKeyFetcher(t))
	vcJWS := createJWS(t, []byte(jwtTestCredential), true)

	// Decode to base credential.
	cred, _, err := NewCredential(vcJWS, keyFetcher)
	require.NoError(t, err)
	require.NotNil(t, cred)

	// Decode to the Credential extension.
	udc, err := NewUniversityDegreeCredential(vcJWS, keyFetcher)
	require.NoError(t, err)
	require.NotNil(t, udc)

	// Compare that base credentials are the same.
	require.Equal(t, udc.Base, *cred)
}

func TestRefineVcIssuerFromJwtClaims(t *testing.T) {
	t.Run("refine verifiable credential issuer defined by plain id", func(t *testing.T) {
		vcMap := map[string]interface{}{
			"issuer": "id to override",
		}
		refineVCIssuerFromJWTClaims(vcMap, "did:example:76e12ec712ebc6f1c221ebfeb1f")
		require.Equal(t, "did:example:76e12ec712ebc6f1c221ebfeb1f", vcMap["issuer"])
	})

	t.Run("refine verifiable credential issuer defined by structure", func(t *testing.T) {
		issuerMap := map[string]interface{}{"id": "id to override", "name": "Example University"}
		vcMap := map[string]interface{}{
			"issuer": issuerMap,
		}
		refineVCIssuerFromJWTClaims(vcMap, "did:example:76e12ec712ebc6f1c221ebfeb1f")
		// issuer id is refined
		require.Equal(t, "did:example:76e12ec712ebc6f1c221ebfeb1f", issuerMap["id"])
		// issuer name remains the same (i.e. not erased)
		require.Equal(t, "Example University", issuerMap["name"])
	})

	t.Run("refine not defined verifiable credential issuer", func(t *testing.T) {
		vcMap := make(map[string]interface{})
		refineVCIssuerFromJWTClaims(vcMap, "did:example:76e12ec712ebc6f1c221ebfeb1f")
		require.Equal(t, "did:example:76e12ec712ebc6f1c221ebfeb1f", vcMap["issuer"])
	})
}

func createKeyFetcher(t *testing.T) func(issuerID string, keyID string) (interface{}, error) {
	return func(issuerID, keyID string) (interface{}, error) {
		require.Equal(t, "did:example:76e12ec712ebc6f1c221ebfeb1f", issuerID)
		require.Equal(t, "did:example:76e12ec712ebc6f1c221ebfeb1f#keys-1", keyID)

		publicKey, err := readPublicKey(filepath.Join(certPrefix, "issuer_public.pem"))
		require.NoError(t, err)
		require.NotNil(t, publicKey)

		return publicKey, nil
	}
}

func createJWS(t *testing.T, cred []byte, minimize bool) []byte {
	vc, _, err := NewCredential(cred)
	require.NoError(t, err)

	privateKey, err := readPrivateKey(filepath.Join(certPrefix, "issuer_private.pem"))
	require.NoError(t, err)

	jwtClaims, err := vc.JWTClaims(minimize)
	require.NoError(t, err)
	vcJWT, err := jwtClaims.MarshalJWS(RS256, privateKey, vc.Issuer.ID+"#keys-"+keyID)
	require.NoError(t, err)

	return []byte(vcJWT)
}

func createUnsecuredJWT(t *testing.T, cred []byte, minimize bool) []byte {
	vc, _, err := NewCredential(cred)
	require.NoError(t, err)

	jwtClaims, err := vc.JWTClaims(minimize)
	require.NoError(t, err)
	vcJWT, err := jwtClaims.MarshalUnsecuredJWT()
	require.NoError(t, err)

	return []byte(vcJWT)
}
