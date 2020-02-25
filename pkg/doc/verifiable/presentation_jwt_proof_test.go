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
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewPresentationFromJWS(t *testing.T) {
	vpBytes := []byte(validPresentation)

	keyFetcher := createPresKeyFetcher(t)

	t.Run("Decoding presentation from JWS", func(t *testing.T) {
		jws := createPresJWS(t, vpBytes, false)
		vpFromJWT, err := NewPresentation(jws, WithPresPublicKeyFetcher(keyFetcher))
		require.NoError(t, err)

		vp, err := NewPresentation(vpBytes)
		require.NoError(t, err)

		require.Equal(t, vp, vpFromJWT)
	})

	t.Run("Decoding presentation from JWS with minimized fields of \"vp\" claim", func(t *testing.T) {
		jws := createPresJWS(t, vpBytes, true)
		vpFromJWT, err := NewPresentation(jws, WithPresPublicKeyFetcher(keyFetcher))
		require.NoError(t, err)

		vp, err := NewPresentation(vpBytes)
		require.NoError(t, err)

		require.Equal(t, vp, vpFromJWT)
	})

	t.Run("Failed JWT signature verification of presentation", func(t *testing.T) {
		jws := createPresJWS(t, vpBytes, true)
		vp, err := NewPresentation(
			jws,
			// passing issuers's key, while expecting issuer one
			WithPresPublicKeyFetcher(func(issuerID, keyID string) (interface{}, error) {
				publicKey, err := readPublicKey(filepath.Join(certPrefix, "issuer_public.pem"))
				require.NoError(t, err)
				require.NotNil(t, publicKey)

				return publicKey, nil
			}))

		require.Error(t, err)
		require.Contains(t, err.Error(), "decoding of Verifiable Presentation from JWS")
		require.Nil(t, vp)
	})

	t.Run("Failed public key fetching", func(t *testing.T) {
		jws := createPresJWS(t, vpBytes, true)
		vp, err := NewPresentation(
			jws,
			WithPresPublicKeyFetcher(func(issuerID, keyID string) (interface{}, error) {
				return nil, errors.New("test: public key is not found")
			}))

		require.Error(t, err)
		require.Contains(t, err.Error(), "test: public key is not found")
		require.Nil(t, vp)
	})

	t.Run("Not defined public key fetcher", func(t *testing.T) {
		vp, err := NewPresentation(createPresJWS(t, vpBytes, true))

		require.Error(t, err)
		require.Contains(t, err.Error(), "public key fetcher is not defined")
		require.Nil(t, vp)
	})
}

func TestNewPresentationFromJWS_EdDSA(t *testing.T) {
	vpBytes := []byte(validPresentation)

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	vp, err := NewPresentation(vpBytes)
	require.NoError(t, err)

	// marshal presentation into JWS using EdDSA (Ed25519 signature algorithm).
	jwtClaims, err := vp.JWTClaims([]string{}, false)
	require.NoError(t, err)

	vpJWSStr, err := jwtClaims.MarshalJWS(EdDSA, getEd25519TestSigner(privKey), vp.Holder+"#keys-"+keyID)
	require.NoError(t, err)

	// unmarshal presentation from JWS
	vpFromJWS, err := NewPresentation(
		[]byte(vpJWSStr),
		WithPresPublicKeyFetcher(SingleKey(pubKey)))
	require.NoError(t, err)

	// unmarshalled presentation must be the same as original one
	require.Equal(t, vp, vpFromJWS)
}

func TestNewPresentationFromUnsecuredJWT(t *testing.T) {
	vpBytes := []byte(validPresentation)

	t.Run("Decoding presentation from unsecured JWT", func(t *testing.T) {
		vpFromJWT, err := NewPresentation(createPresUnsecuredJWT(t, vpBytes, false))

		require.NoError(t, err)

		vp, err := NewPresentation(vpBytes)
		require.NoError(t, err)

		require.Equal(t, vp, vpFromJWT)
	})

	t.Run("Decoding presentation from unsecured JWT with minimized fields of \"vp\" claim", func(t *testing.T) {
		vpFromJWT, err := NewPresentation(createPresUnsecuredJWT(t, vpBytes, true))

		require.NoError(t, err)

		vp, err := NewPresentation(vpBytes)
		require.NoError(t, err)

		require.Equal(t, vp, vpFromJWT)
	})
}

func TestNewPresentationWithVCJWT(t *testing.T) {
	r := require.New(t)

	// Create and encode VP.
	issued := time.Date(2010, time.January, 1, 19, 23, 24, 0, time.UTC)
	expired := time.Date(2020, time.January, 1, 19, 23, 24, 0, time.UTC)

	vc := &Credential{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1"},
		ID: "http://example.edu/credentials/1872",
		Types: []string{
			"VerifiableCredential",
			"UniversityDegreeCredential"},
		Subject: UniversityDegreeSubject{
			ID:     "did:example:ebfeb1f712ebc6f1c276e12ec21",
			Name:   "Jayden Doe",
			Spouse: "did:example:c276e12ec21ebfeb1f712ebc6f1",
			Degree: UniversityDegree{
				Type:       "BachelorDegree",
				University: "MIT",
			},
		},
		Issuer: Issuer{
			ID:   "did:example:76e12ec712ebc6f1c221ebfeb1f",
			Name: "Example University",
		},
		Issued:  &issued,
		Expired: &expired,
		Schemas: []TypedID{},
	}

	vcJWTClaims, e := vc.JWTClaims(true)
	r.NoError(e)

	issuerPrivKey, e := readPrivateKey(filepath.Join(certPrefix, "issuer_private.pem"))
	r.NoError(e)

	vcJWS, e := vcJWTClaims.MarshalJWS(RS256, getRS256TestSigner(issuerPrivKey), "issuer-key")
	r.NoError(e)
	r.NotNil(vcJWS)

	t.Run("Presentation with VC defined as JWS", func(t *testing.T) {
		// Create and encode VP.
		vp := &Presentation{
			Context: []string{
				"https://www.w3.org/2018/credentials/v1"},
			ID:     "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c",
			Type:   []string{"VerifiablePresentation"},
			Holder: "did:example:ebfeb1f712ebc6f1c276e12ec21",
		}
		err := vp.SetCredentials(vcJWS)
		r.NoError(err)

		holderPubKey, holderPrivKey, err := ed25519.GenerateKey(rand.Reader)
		r.NoError(err)

		jwtClaims, err := vp.JWTClaims([]string{}, true)
		require.NoError(t, err)

		vpJWS, err := jwtClaims.MarshalJWS(EdDSA, getEd25519TestSigner(holderPrivKey), "holder-key")
		r.NoError(err)

		// Decode VP
		vpDecoded, err := NewPresentation([]byte(vpJWS), WithPresPublicKeyFetcher(
			func(issuerID, keyID string) (interface{}, error) {
				switch keyID {
				case "holder-key":
					return holderPubKey, nil
				case "issuer-key":
					return issuerPrivKey.Public(), nil
				default:
					return nil, errors.New("unexpected key")
				}
			}))
		r.NoError(err)
		vpCreds, err := vpDecoded.MarshalledCredentials()
		r.NoError(err)
		r.Len(vpCreds, 1)

		vcDecoded, _, err := NewCredential(vpCreds[0])
		r.NoError(err)

		r.Equal(vc.stringJSON(t), vcDecoded.stringJSON(t))
	})

	t.Run("Presentation with VC defined as VC struct", func(t *testing.T) {
		// Create and encode VP.
		vp := &Presentation{
			Context: []string{
				"https://www.w3.org/2018/credentials/v1"},
			ID:     "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c",
			Type:   []string{"VerifiablePresentation"},
			Holder: "did:example:ebfeb1f712ebc6f1c276e12ec21",
		}
		err := vp.SetCredentials(vc)
		r.NoError(err)

		holderPubKey, holderPrivKey, err := ed25519.GenerateKey(rand.Reader)
		r.NoError(err)

		jwtClaims, err := vp.JWTClaims([]string{}, true)
		require.NoError(t, err)

		vpJWS, err := jwtClaims.MarshalJWS(EdDSA, getEd25519TestSigner(holderPrivKey), "holder-key")
		r.NoError(err)

		// Decode VP
		vpDecoded, err := NewPresentation([]byte(vpJWS), WithPresPublicKeyFetcher(SingleKey(holderPubKey)))
		r.NoError(err)
		vpCreds, err := vpDecoded.MarshalledCredentials()
		r.NoError(err)
		r.Len(vpCreds, 1)

		vcDecoded, _, err := NewCredential(vpCreds[0])
		r.NoError(err)

		r.Equal(vc.stringJSON(t), vcDecoded.stringJSON(t))
	})

	t.Run("Failed check of VC due to invalid JWS", func(t *testing.T) {
		// Create and encode VP.
		vp := &Presentation{
			Context: []string{
				"https://www.w3.org/2018/credentials/v1"},
			ID:     "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c",
			Type:   []string{"VerifiablePresentation"},
			Holder: "did:example:ebfeb1f712ebc6f1c276e12ec21",
		}
		err := vp.SetCredentials(vcJWS)
		r.NoError(err)

		holderPubKey, holderPrivKey, err := ed25519.GenerateKey(rand.Reader)
		r.NoError(err)

		jwtClaims, err := vp.JWTClaims([]string{}, true)
		require.NoError(t, err)

		vpJWS, err := jwtClaims.MarshalJWS(EdDSA, getEd25519TestSigner(holderPrivKey), "holder-key")
		r.NoError(err)

		// Decode VP
		vp, err = NewPresentation([]byte(vpJWS), WithPresPublicKeyFetcher(
			func(issuerID, keyID string) (interface{}, error) {
				switch keyID {
				case "holder-key":
					return holderPubKey, nil
				case "issuer-key":
					// here we return invalid public key
					anotherPubKey, _, gerr := ed25519.GenerateKey(rand.Reader)
					r.NoError(gerr)
					return anotherPubKey, nil
				default:
					r.NoError(err)
					return nil, errors.New("unexpected key")
				}
			}))
		r.Error(err)
		r.Contains(err.Error(), "decode credentials of presentation")
		r.Contains(err.Error(), "JWS decoding")
		r.Nil(vp)
	})
}

func createPresJWS(t *testing.T, vpBytes []byte, minimize bool) []byte {
	vp, err := NewPresentation(vpBytes)
	require.NoError(t, err)

	privateKey, err := readPrivateKey(filepath.Join(certPrefix, "holder_private.pem"))
	require.NoError(t, err)

	jwtClaims, err := vp.JWTClaims([]string{}, minimize)
	require.NoError(t, err)

	vpJWT, err := jwtClaims.MarshalJWS(RS256, getRS256TestSigner(privateKey), vp.Holder+"#keys-"+keyID)
	require.NoError(t, err)

	return []byte(vpJWT)
}

func createPresKeyFetcher(t *testing.T) func(issuerID string, keyID string) (interface{}, error) {
	return func(issuerID, keyID string) (interface{}, error) {
		require.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", issuerID)
		require.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21#keys-1", keyID)

		publicKey, err := readPublicKey(filepath.Join(certPrefix, "holder_public.pem"))
		require.NoError(t, err)
		require.NotNil(t, publicKey)

		return publicKey, nil
	}
}

func createPresUnsecuredJWT(t *testing.T, cred []byte, minimize bool) []byte {
	vp, err := NewPresentation(cred)
	require.NoError(t, err)

	jwtClaims, err := vp.JWTClaims([]string{}, minimize)
	require.NoError(t, err)

	vpJWT, err := jwtClaims.MarshalUnsecuredJWT()
	require.NoError(t, err)

	return []byte(vpJWT)
}
