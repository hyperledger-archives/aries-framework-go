/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/models/signature/verifier"
	utiltime "github.com/hyperledger/aries-framework-go/component/models/util/time"
	"github.com/hyperledger/aries-framework-go/spi/kms"
)

func TestParsePresentationFromJWS(t *testing.T) {
	vpBytes := []byte(validPresentation)

	holderSigner, err := newCryptoSigner(kms.RSARS256Type)
	require.NoError(t, err)

	keyFetcher := createPresKeyFetcher(holderSigner.PublicKeyBytes())

	t.Run("Decoding presentation from JWS", func(t *testing.T) {
		jws := createPresJWS(t, vpBytes, false, holderSigner)
		vpFromJWT, err := newTestPresentation(t, jws, WithPresPublicKeyFetcher(keyFetcher))
		require.NoError(t, err)

		vp, err := newTestPresentation(t, vpBytes)
		require.NoError(t, err)

		// Validate the JWT field, then clear it to validate against the original presentation.
		require.Equal(t, string(jws), vpFromJWT.JWT)
		vpFromJWT.JWT = ""

		require.Equal(t, vp, vpFromJWT)
	})

	t.Run("Decoding presentation from JWS with minimized fields of \"vp\" claim", func(t *testing.T) {
		jws := createPresJWS(t, vpBytes, true, holderSigner)
		vpFromJWT, err := newTestPresentation(t, jws, WithPresPublicKeyFetcher(keyFetcher))
		require.NoError(t, err)

		vp, err := newTestPresentation(t, vpBytes)
		require.NoError(t, err)

		require.Equal(t, string(jws), vpFromJWT.JWT)
		vpFromJWT.JWT = ""

		require.Equal(t, vp, vpFromJWT)
	})

	t.Run("Failed JWT signature verification of presentation", func(t *testing.T) {
		jws := createPresJWS(t, vpBytes, true, holderSigner)
		vp, err := newTestPresentation(t,
			jws,
			// passing issuers's key, while expecting holder's one
			WithPresPublicKeyFetcher(func(issuerID, keyID string) (*verifier.PublicKey, error) {
				issuerSigner, err := newCryptoSigner(kms.RSARS256Type)
				require.NoError(t, err)

				return &verifier.PublicKey{
					Type:  kms.RSARS256,
					Value: issuerSigner.PublicKeyBytes(),
				}, nil
			}))

		require.Error(t, err)
		require.Contains(t, err.Error(), "decoding of Verifiable Presentation from JWS")
		require.Nil(t, vp)
	})

	t.Run("Failed public key fetching", func(t *testing.T) {
		jws := createPresJWS(t, vpBytes, true, holderSigner)
		vp, err := newTestPresentation(t,
			jws,
			WithPresPublicKeyFetcher(func(issuerID, keyID string) (*verifier.PublicKey, error) {
				return nil, errors.New("test: public key is not found")
			}))

		require.Error(t, err)
		require.Contains(t, err.Error(), "test: public key is not found")
		require.Nil(t, vp)
	})

	t.Run("Not defined public key fetcher", func(t *testing.T) {
		vp, err := newTestPresentation(t, createPresJWS(t, vpBytes, true, holderSigner))

		require.Error(t, err)
		require.Contains(t, err.Error(), "public key fetcher is not defined")
		require.Nil(t, vp)
	})
}

func TestParsePresentationFromJWS_EdDSA(t *testing.T) {
	vpBytes := []byte(validPresentation)

	signer, err := newCryptoSigner(kms.ED25519Type)
	require.NoError(t, err)

	vp, err := newTestPresentation(t, vpBytes)
	require.NoError(t, err)

	// marshal presentation into JWS using EdDSA (Ed25519 signature algorithm).
	jwtClaims, err := vp.JWTClaims([]string{}, false)
	require.NoError(t, err)

	vpJWSStr, err := jwtClaims.MarshalJWS(EdDSA, signer, vp.Holder+"#keys-"+keyID)
	require.NoError(t, err)

	// unmarshal presentation from JWS
	vpFromJWS, err := newTestPresentation(t,
		[]byte(vpJWSStr),
		WithPresPublicKeyFetcher(SingleKey(signer.PublicKeyBytes(), kms.ED25519)))
	require.NoError(t, err)

	require.Equal(t, vpJWSStr, vpFromJWS.JWT)
	vpFromJWS.JWT = ""

	// unmarshalled presentation must be the same as original one
	require.Equal(t, vp, vpFromJWS)
}

func TestParsePresentationFromUnsecuredJWT(t *testing.T) {
	vpBytes := []byte(validPresentation)

	t.Run("Decoding presentation from unsecured JWT", func(t *testing.T) {
		vpFromJWT, err := newTestPresentation(t, createPresUnsecuredJWT(t, vpBytes, false))

		require.NoError(t, err)

		vp, err := newTestPresentation(t, vpBytes)
		require.NoError(t, err)

		require.Equal(t, vp, vpFromJWT)
	})

	t.Run("Decoding presentation from unsecured JWT with minimized fields of \"vp\" claim", func(t *testing.T) {
		vpFromJWT, err := newTestPresentation(t, createPresUnsecuredJWT(t, vpBytes, true))

		require.NoError(t, err)

		vp, err := newTestPresentation(t, vpBytes)
		require.NoError(t, err)

		require.Equal(t, vp, vpFromJWT)
	})
}

func TestParsePresentationWithVCJWT(t *testing.T) {
	r := require.New(t)

	// Create and encode VP.
	issued := time.Date(2010, time.January, 1, 19, 23, 24, 0, time.UTC)
	expired := time.Date(2020, time.January, 1, 19, 23, 24, 0, time.UTC)

	vc := &Credential{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1",
		},
		ID: "http://example.edu/credentials/1872",
		Types: []string{
			"VerifiableCredential",
			"UniversityDegreeCredential",
		},
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
			ID:           "did:example:76e12ec712ebc6f1c221ebfeb1f",
			CustomFields: CustomFields{"name": "Example University"},
		},
		Issued:  utiltime.NewTime(issued),
		Expired: utiltime.NewTime(expired),
		Schemas: []TypedID{},
	}

	vcJWTClaims, err := vc.JWTClaims(true)
	r.NoError(err)

	issuerSigner, err := newCryptoSigner(kms.RSARS256Type)
	r.NoError(err)

	vcJWS, err := vcJWTClaims.MarshalJWS(RS256, issuerSigner, "did:123#issuer-key")
	r.NoError(err)
	r.NotNil(vcJWS)

	t.Run("Presentation with VC defined as JWS", func(t *testing.T) {
		// Create and encode VP.
		vp, err := NewPresentation(WithJWTCredentials(vcJWS))
		r.NoError(err)

		vp.ID = "urn:uuid:2978344f-8596-4c3a-a978-8fcaba3903c"
		vp.Holder = "did:example:fbfeb1f712ebc6f1c276e12ec21"

		holderSigner, err := newCryptoSigner(kms.ED25519Type)
		r.NoError(err)

		jwtClaims, err := vp.JWTClaims([]string{}, true)
		require.NoError(t, err)

		vpJWS, err := jwtClaims.MarshalJWS(EdDSA, holderSigner, "did:123#holder-key")
		r.NoError(err)

		publicKeyFetcher := func(issuerID, keyID string) (*verifier.PublicKey, error) {
			switch keyID {
			case "holder-key":
				return &verifier.PublicKey{
					Type:  kms.ED25519,
					Value: holderSigner.PublicKeyBytes(),
				}, nil
			case "issuer-key":
				return &verifier.PublicKey{
					Type:  kms.RSARS256,
					Value: issuerSigner.PublicKeyBytes(),
				}, nil
			default:
				return nil, errors.New("unexpected key")
			}
		}

		// Decode VP
		vpDecoded, err := newTestPresentation(t, []byte(vpJWS), WithPresPublicKeyFetcher(publicKeyFetcher))
		r.NoError(err)
		vpCreds, err := vpDecoded.MarshalledCredentials()
		r.NoError(err)
		r.Len(vpCreds, 1)

		vcDecoded, err := parseTestCredential(t, vpCreds[0], WithPublicKeyFetcher(publicKeyFetcher))
		r.NoError(err)

		r.Equal(fmt.Sprintf("%q", vcJWS), vcDecoded.stringJSON(t))
	})

	t.Run("Presentation with VC defined as VC struct", func(t *testing.T) {
		// Create and encode VP.
		vp, err := NewPresentation(WithCredentials(vc))
		r.NoError(err)

		vp.ID = "urn:uuid:5978344f-8596-4c3a-a978-8fcaba3903c"
		vp.Holder = "did:example:abfeb1f712ebc6f1c276e12ec21"

		holderSigner, err := newCryptoSigner(kms.ED25519Type)
		r.NoError(err)

		jwtClaims, err := vp.JWTClaims([]string{}, true)
		require.NoError(t, err)

		vpJWS, err := jwtClaims.MarshalJWS(EdDSA, holderSigner, "did:123#holder-key")
		r.NoError(err)

		// Decode VP
		vpDecoded, err := newTestPresentation(t, []byte(vpJWS), WithPresPublicKeyFetcher(
			SingleKey(holderSigner.PublicKeyBytes(), kms.ED25519)))
		r.NoError(err)
		vpCreds, err := vpDecoded.MarshalledCredentials()
		r.NoError(err)
		r.Len(vpCreds, 1)

		vcDecoded, err := parseTestCredential(t, vpCreds[0])
		r.NoError(err)

		r.Equal(vc.stringJSON(t), vcDecoded.stringJSON(t))
	})

	t.Run("Failed check of VC due to invalid JWS", func(t *testing.T) {
		vp, err := NewPresentation(WithJWTCredentials(vcJWS))
		r.NoError(err)

		vp.ID = "urn:uuid:0978344f-8596-4c3a-a978-8fcaba3903c"
		vp.Holder = "did:example:ebfeb2f712ebc6f1c276e12ec21"

		holderSigner, err := newCryptoSigner(kms.ED25519Type)
		r.NoError(err)

		jwtClaims, err := vp.JWTClaims([]string{}, true)
		require.NoError(t, err)

		vpJWS, err := jwtClaims.MarshalJWS(EdDSA, holderSigner, "did:123#holder-key")
		r.NoError(err)

		// Decode VP
		vp, err = newTestPresentation(t, []byte(vpJWS), WithPresPublicKeyFetcher(
			func(issuerID, keyID string) (*verifier.PublicKey, error) {
				switch keyID {
				case "holder-key":
					return &verifier.PublicKey{
						Type:  kms.ED25519,
						Value: holderSigner.PublicKeyBytes(),
					}, nil
				case "issuer-key":
					// here we return invalid public key
					anotherPubKey, _, gerr := ed25519.GenerateKey(rand.Reader)
					r.NoError(gerr)

					return &verifier.PublicKey{
						Type:  kms.ED25519,
						Value: anotherPubKey,
					}, nil
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

func createPresJWS(t *testing.T, vpBytes []byte, minimize bool, signer Signer) []byte {
	vp, err := newTestPresentation(t, vpBytes)
	require.NoError(t, err)

	jwtClaims, err := vp.JWTClaims([]string{}, minimize)
	require.NoError(t, err)

	vpJWT, err := jwtClaims.MarshalJWS(RS256, signer, vp.Holder+"#keys-"+keyID)
	require.NoError(t, err)

	return []byte(vpJWT)
}

func createPresKeyFetcher(pubKeyBytes []byte) func(issuerID string, keyID string) (*verifier.PublicKey, error) {
	return func(issuerID, keyID string) (*verifier.PublicKey, error) {
		return &verifier.PublicKey{
			Type:  kms.RSARS256,
			Value: pubKeyBytes,
		}, nil
	}
}

func createPresUnsecuredJWT(t *testing.T, cred []byte, minimize bool) []byte {
	vp, err := newTestPresentation(t, cred)
	require.NoError(t, err)

	jwtClaims, err := vp.JWTClaims([]string{}, minimize)
	require.NoError(t, err)

	vpJWT, err := jwtClaims.MarshalUnsecuredJWT()
	require.NoError(t, err)

	return []byte(vpJWT)
}
