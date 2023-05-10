/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/models/did"
	"github.com/hyperledger/aries-framework-go/component/models/did/endpoint"
	"github.com/hyperledger/aries-framework-go/component/models/signature/verifier"
	"github.com/hyperledger/aries-framework-go/spi/kms"
	"github.com/hyperledger/aries-framework-go/spi/vdr"
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

func TestParseCredentialFromJWS(t *testing.T) {
	testCred := []byte(jwtTestCredential)

	ed25519Signer, err := newCryptoSigner(kms.ED25519Type)
	require.NoError(t, err)

	ed25519KeyFetcher := createDIDKeyFetcher(t, ed25519Signer.PublicKeyBytes(), "76e12ec712ebc6f1c221ebfeb1f")

	rs256Signer, err := newCryptoSigner(kms.RSARS256Type)
	require.NoError(t, err)

	t.Run("Decoding credential from JWS", func(t *testing.T) {
		vcFromJWT, err := parseTestCredential(t,
			createEdDSAJWS(t, testCred, ed25519Signer, false),
			WithPublicKeyFetcher(ed25519KeyFetcher))

		require.NoError(t, err)

		vc, err := parseTestCredential(t, testCred)
		require.NoError(t, err)

		require.NotEqual(t, "", vcFromJWT.JWT)
		vcFromJWT.JWT = ""

		require.Equal(t, vc, vcFromJWT)
	})

	t.Run("Decoding credential from JWS with minimized fields of \"vc\" claim", func(t *testing.T) {
		vcFromJWT, err := parseTestCredential(t,
			createEdDSAJWS(t, testCred, ed25519Signer, true),
			WithPublicKeyFetcher(ed25519KeyFetcher))

		require.NoError(t, err)

		vc, err := parseTestCredential(t, testCred)
		require.NoError(t, err)

		require.NotEqual(t, "", vcFromJWT.JWT)
		vcFromJWT.JWT = ""

		require.Equal(t, vc, vcFromJWT)
	})

	t.Run("Failed JWT signature verification of credential", func(t *testing.T) {
		vc, err := parseTestCredential(t,
			createRS256JWS(t, testCred, rs256Signer, true),
			// passing holder's key, while expecting issuer one
			WithPublicKeyFetcher(func(issuerID, keyID string) (*verifier.PublicKey, error) {
				holderSigner, err := newCryptoSigner(kms.RSARS256Type)
				require.NoError(t, err)

				return &verifier.PublicKey{
					Type:  kms.RSARS256,
					Value: holderSigner.PublicKeyBytes(),
				}, nil
			}))

		require.Error(t, err)
		require.Contains(t, err.Error(), "JWS decoding: unmarshal VC JWT claims")
		require.Nil(t, vc)
	})

	t.Run("Failed public key fetching", func(t *testing.T) {
		vc, err := parseTestCredential(t,
			createRS256JWS(t, testCred, rs256Signer, true),

			WithPublicKeyFetcher(func(issuerID, keyID string) (*verifier.PublicKey, error) {
				return nil, errors.New("test: public key is not found")
			}))

		require.Error(t, err)
		require.Nil(t, vc)
	})

	t.Run("Not defined public key fetcher", func(t *testing.T) {
		vc, err := parseTestCredential(t, createRS256JWS(t, testCred, rs256Signer, true))

		require.Error(t, err)
		require.Contains(t, err.Error(), "public key fetcher is not defined")
		require.Nil(t, vc)
	})
}

func TestParseCredentialFromJWS_EdDSA(t *testing.T) {
	vcBytes := []byte(jwtTestCredential)

	signer, err := newCryptoSigner(kms.ED25519Type)
	require.NoError(t, err)

	vc, err := parseTestCredential(t, vcBytes)
	require.NoError(t, err)

	vcJWSStr := createEdDSAJWS(t, vcBytes, signer, false)

	// unmarshal credential from JWS
	vcFromJWS, err := parseTestCredential(t,
		vcJWSStr,
		WithPublicKeyFetcher(SingleKey(signer.PublicKeyBytes(), kms.ED25519)))
	require.NoError(t, err)

	require.NotEqual(t, "", vcFromJWS.JWT)
	vcFromJWS.JWT = ""

	// unmarshalled credential must be the same as original one
	require.Equal(t, vc, vcFromJWS)
}

func TestParseCredentialFromUnsecuredJWT(t *testing.T) {
	testCred := []byte(jwtTestCredential)

	t.Run("Unsecured JWT decoding with no fields minimization", func(t *testing.T) {
		vcFromJWT, err := parseTestCredential(t, createUnsecuredJWT(t, testCred, false))

		require.NoError(t, err)

		vc, err := parseTestCredential(t, testCred)
		require.NoError(t, err)

		require.Equal(t, vc, vcFromJWT)
	})

	t.Run("Unsecured JWT decoding with minimized fields", func(t *testing.T) {
		vcFromJWT, err := parseTestCredential(t, createUnsecuredJWT(t, testCred, true))

		require.NoError(t, err)

		vc, err := parseTestCredential(t, testCred)
		require.NoError(t, err)

		require.Equal(t, vc, vcFromJWT)
	})
}

func TestJwtWithExtension(t *testing.T) {
	signer, err := newCryptoSigner(kms.RSARS256Type)
	require.NoError(t, err)

	keyFetcher := WithPublicKeyFetcher(func(issuerID, keyID string) (*verifier.PublicKey, error) {
		return &verifier.PublicKey{
			Type:  kms.RSARS256,
			Value: signer.PublicKeyBytes(),
		}, nil
	})

	vcJWS := createRS256JWS(t, []byte(jwtTestCredential), signer, true)

	// Decode to base credential.
	cred, err := parseTestCredential(t, vcJWS, keyFetcher)
	require.NoError(t, err)
	require.NotNil(t, cred)

	// Decode to the Credential extension.
	udc, err := NewUniversityDegreeCredential(t, vcJWS, keyFetcher)
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

func createDIDKeyFetcher(t *testing.T, pub ed25519.PublicKey, didID string) PublicKeyFetcher {
	const (
		didFormat    = "did:%s:%s"
		didPKID      = "%s#keys-%d"
		didServiceID = "%s#endpoint-%d"
		method       = "example"
	)

	id := fmt.Sprintf(didFormat, method, didID)
	pubKeyID := fmt.Sprintf(didPKID, id, 1)
	pubKey := did.NewVerificationMethodFromBytes(pubKeyID, "Ed25519VerificationKey2018", id, pub)
	services := []did.Service{
		{
			ID:              fmt.Sprintf(didServiceID, id, 1),
			Type:            "did-communication",
			ServiceEndpoint: endpoint.NewDIDCommV1Endpoint("http://localhost:47582"),
			Priority:        0,
			RecipientKeys:   []string{pubKeyID},
		},
	}
	createdTime := time.Now()
	didDoc := &did.Doc{
		Context:            []string{did.ContextV1},
		ID:                 id,
		VerificationMethod: []did.VerificationMethod{*pubKey},
		Service:            services,
		Created:            &createdTime,
		Updated:            &createdTime,
	}

	v := &mockResolver{
		didDoc: didDoc,
	}

	resolver := NewVDRKeyResolver(v)
	require.NotNil(t, resolver)

	return resolver.resolvePublicKey
}

func createRS256JWS(t *testing.T, cred []byte, signer Signer, minimize bool) []byte {
	vc, err := parseTestCredential(t, cred)
	require.NoError(t, err)

	jwtClaims, err := vc.JWTClaims(minimize)
	require.NoError(t, err)
	vcJWT, err := jwtClaims.MarshalJWS(RS256, signer, vc.Issuer.ID+"#keys-"+keyID)
	require.NoError(t, err)

	return []byte(vcJWT)
}

func createEdDSAJWS(t *testing.T, cred []byte, signer Signer, minimize bool) []byte {
	vc, err := parseTestCredential(t, cred)
	require.NoError(t, err)

	jwtClaims, err := vc.JWTClaims(minimize)
	require.NoError(t, err)
	vcJWT, err := jwtClaims.MarshalJWS(EdDSA, signer, vc.Issuer.ID+"#keys-"+keyID)
	require.NoError(t, err)

	return []byte(vcJWT)
}

func createUnsecuredJWT(t *testing.T, cred []byte, minimize bool) []byte {
	vc, err := parseTestCredential(t, cred)
	require.NoError(t, err)

	jwtClaims, err := vc.JWTClaims(minimize)
	require.NoError(t, err)
	vcJWT, err := jwtClaims.MarshalUnsecuredJWT()
	require.NoError(t, err)

	return []byte(vcJWT)
}

type mockResolver struct {
	didDoc *did.Doc
}

func (m *mockResolver) Resolve(string, ...vdr.DIDMethodOption) (*did.DocResolution, error) {
	return &did.DocResolution{
		DIDDocument: m.didDoc,
	}, nil
}
