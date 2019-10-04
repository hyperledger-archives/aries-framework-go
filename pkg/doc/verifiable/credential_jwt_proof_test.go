/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/square/go-jose/v3/jwt"
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

	t.Run("JWS decoding with fields minimization", func(t *testing.T) {
		vcFromJWT, err := NewCredential(
			createJWS(t, testCred, false),
			WithJWTPublicKeyFetcher(keyFetcher))

		require.NoError(t, err)

		vc, err := NewCredential(testCred)
		require.NoError(t, err)

		require.Equal(t, vc, vcFromJWT)
	})

	t.Run("JWS decoding with minimized fields", func(t *testing.T) {
		vcFromJWT, err := NewCredential(
			createJWS(t, testCred, true),
			WithJWTPublicKeyFetcher(keyFetcher))

		require.NoError(t, err)

		vc, err := NewCredential(testCred)
		require.NoError(t, err)

		require.Equal(t, vc, vcFromJWT)
	})

	t.Run("Failed JWT signature verification", func(t *testing.T) {
		_, err := NewCredential(
			createJWS(t, testCred, true),

			// passing holder's key, while expecting issuer one
			WithJWTPublicKeyFetcher(func(issuerID, keyID string) (interface{}, error) {
				publicKey, err := readPublicKey(filepath.Join(certPrefix, "holder_public.pem"))
				require.NoError(t, err)
				require.NotNil(t, publicKey)

				return publicKey, nil
			}))

		require.Error(t, err)
		require.Contains(t, err.Error(), "JWS decoding failed")
	})

	t.Run("Failed public key fetching", func(t *testing.T) {
		_, err := NewCredential(
			createJWS(t, testCred, true),

			// passing holder's key, while expecting issuer one
			WithJWTPublicKeyFetcher(func(issuerID, keyID string) (interface{}, error) {
				return nil, errors.New("test: public key is not found")
			}))

		require.Error(t, err)
	})
}

func TestNewCredentialFromUnsecuredJWT(t *testing.T) {
	testCred := []byte(jwtTestCredential)

	t.Run("Unsecured JWT decoding with fields minimization", func(t *testing.T) {
		vcFromJWT, err := NewCredential(
			createUnsecuredJWT(t, testCred, false),
			WithUnsecuredJWT())

		require.NoError(t, err)

		vc, err := NewCredential(testCred)
		require.NoError(t, err)

		require.Equal(t, vc, vcFromJWT)
	})

	t.Run("Unsecured JWT decoding with minimized fields", func(t *testing.T) {
		vcFromJWT, err := NewCredential(
			createUnsecuredJWT(t, testCred, true),
			WithUnsecuredJWT())

		require.NoError(t, err)

		vc, err := NewCredential(testCred)
		require.NoError(t, err)

		require.Equal(t, vc, vcFromJWT)
	})

	t.Run("Failed JWT signature verification", func(t *testing.T) {
		_, err := NewCredential(
			[]byte("invalid unsecured JWT"),
			WithUnsecuredJWT())

		require.Error(t, err)
		require.Contains(t, err.Error(), "unsecured JWT decoding failed")
	})
}

func TestJwtWithExtension(t *testing.T) {
	// Decode to base credential.
	cred, err := NewCredential(
		createJWS(t, []byte(jwtTestCredential), true),
		WithJWTPublicKeyFetcher(createKeyFetcher(t)),
	)
	require.NoError(t, err)
	require.NotNil(t, cred)

	// Check that it's match our VC extension.
	require.Contains(t, cred.Context, "https://www.w3.org/2018/credentials/examples/v1")
	require.Contains(t, cred.Type, "UniversityDegreeCredential")

	// Decode to the Credential extension.
	udc := &UniversityDegreeCredential{}
	udcBaseCred, err := NewCredential(
		[]byte(validCredential),
		WithDecoders([]CredentialDecoder{udc.decode}),
		WithTemplate(udc.credential),
	)
	require.NoError(t, err)
	require.NotNil(t, udcBaseCred)
	require.Equal(t, &udc.Base, udcBaseCred)
}

func TestRefineVcIssuerFromJwtClaims(t *testing.T) {
	t.Run("refine verifiable credential issuer defined by plain id", func(t *testing.T) {
		raw := &rawCredential{Issuer: "id to override"}
		refineVCIssuerFromJWTClaims(raw, "did:example:76e12ec712ebc6f1c221ebfeb1f")
		require.Equal(t, "did:example:76e12ec712ebc6f1c221ebfeb1f", raw.Issuer)
	})

	t.Run("refine verifiable credential issuer defined by structure", func(t *testing.T) {
		issuerMap := map[string]interface{}{"id": "id to override", "name": "Example University"}
		raw := &rawCredential{Issuer: issuerMap}
		refineVCIssuerFromJWTClaims(raw, "did:example:76e12ec712ebc6f1c221ebfeb1f")
		require.Equal(t, "Example University", issuerMap["name"])
		require.Equal(t, "did:example:76e12ec712ebc6f1c221ebfeb1f", issuerMap["id"])
	})
}

func TestRefineVcFromJwtClaims(t *testing.T) {
	issuerID := "did:example:76e12ec712ebc6f1c221ebfeb1f"
	issued := time.Date(2019, time.August, 10, 0, 0, 0, 0, time.UTC)
	vcID := "http://example.edu/credentials/3732"
	expired := time.Date(2029, time.August, 10, 0, 0, 0, 0, time.UTC)

	rawCred := &rawCredential{Issuer: "unknown"}
	credClaims := &JWTCredClaims{
		Claims: &jwt.Claims{
			Issuer:    issuerID,
			NotBefore: jwt.NewNumericDate(issued),
			ID:        vcID,
			IssuedAt:  jwt.NewNumericDate(issued),
			Expiry:    jwt.NewNumericDate(expired),
		},
		Credential: rawCred,
	}

	credClaims.refineCredFromJWTClaims()

	require.Equal(t, issuerID, rawCred.Issuer)
	require.Equal(t, issued, *rawCred.Issued)
	require.Equal(t, expired, *rawCred.Expired)
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
	vc, err := NewCredential(cred)
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
	vc, err := NewCredential(cred)
	require.NoError(t, err)

	jwtClaims, err := vc.JWTClaims(minimize)
	require.NoError(t, err)
	vcJWT, err := jwtClaims.MarshalUnsecuredJWT()
	require.NoError(t, err)

	return []byte(vcJWT)
}
