/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
)

func Test_keyResolverAdapter_Resolve(t *testing.T) {
	t.Run("successful public key resolving", func(t *testing.T) {
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		kra := &keyResolverAdapter{pubKeyFetcher: SingleKey([]byte(pubKey))}
		resolvedPubKey, err := kra.Resolve("did1#key1")
		require.NoError(t, err)
		require.Equal(t, []byte(pubKey), resolvedPubKey)
	})

	t.Run("error wrong key format", func(t *testing.T) {
		kra := &keyResolverAdapter{pubKeyFetcher: func(issuerID, keyID string) (interface{}, error) {
			return nil, nil
		}}
		resolvedPubKey, err := kra.Resolve("any")
		require.Error(t, err)
		require.EqualError(t, err, "wrong id [any] to resolve")
		require.Nil(t, resolvedPubKey)
	})

	t.Run("error at public key resolving (e.g. not found)", func(t *testing.T) {
		kra := &keyResolverAdapter{pubKeyFetcher: func(issuerID, keyID string) (interface{}, error) {
			return nil, errors.New("no key found")
		}}
		resolvedPubKey, err := kra.Resolve("did1#key1")
		require.Error(t, err)
		require.EqualError(t, err, "no key found")
		require.Nil(t, resolvedPubKey)
	})

	t.Run("returned public key is not []byte", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		kra := &keyResolverAdapter{pubKeyFetcher: SingleKey(privateKey.Public())}
		resolvedPubKey, err := kra.Resolve("did1#key1")
		require.Error(t, err)
		require.EqualError(t, err, "expecting []byte public key")
		require.Nil(t, resolvedPubKey)
	})
}

type dummyKeyResolver []byte

func (kr dummyKeyResolver) Resolve(string) ([]byte, error) {
	return kr, nil
}

// This example is generated using https://transmute-industries.github.io/vc-greeting-card
func TestLinkedDataProofVerifier(t *testing.T) {
	pubKeyBytes := base58.Decode("BoLcfbmL1yXgfCvc1MDAQg4xsR7D8Wo9zYLCu2vvCwgn")
	pubKey := ed25519.PublicKey(pubKeyBytes)

	//nolint:lll
	vcStr := `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "id": "https://example.com/credentials/1872",
  "type": [
    "VerifiableCredential",
    "UniversityDegreeCredential"
  ],
  "issuer": "did:key:z6Mkj7of2aaooXhTJvJ5oCL9ZVcAS472ZBuSjYyXDa4bWT32",
  "issuanceDate": "2020-01-17T15:14:09.724Z",
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "degree": {
      "type": "BachelorDegree"
    },
    "name": "Jayden Doe",
    "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
  },
  "proof": {
    "type": "Ed25519Signature2018",
    "created": "2018-03-15T00:00:00Z",
    "jws": "eyJhbGciOiJFZDI1NTE5U2lnbmF0dXJlMjAxOCIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..vc5PCbRaTId2IRptkqJwNDlzZqW-wfGdcl0MWcNrrNCFxZgmgiNU7ZYUtz7ui9yVrVl-NL84F8KrCra7pyruDw",
    "verificationMethod": "did:example:123456#key1"
  }
}
`

	documentVerifier := verifier.New(dummyKeyResolver(pubKey))
	err := documentVerifier.Verify([]byte(vcStr))
	require.NoError(t, err)
}

func TestLinkedDataProofSigner(t *testing.T) {
	privKeyBytes := base58.Decode("2XYB4TtEgPZxTuRocH8DGoZjjnnPwpwUW9acH1kTCTC8SM9177XHNhzMZu2DNxHdFhi7DACECdieY9D2yngmXZcj") //nolint:lll
	privKey := ed25519.PrivateKey(privKeyBytes)

	vcJSON := `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "id": "https://example.com/credentials/1872",
  "type": [
    "VerifiableCredential",
    "UniversityDegreeCredential"
  ],
  "issuer": "did:key:z6Mkj7of2aaooXhTJvJ5oCL9ZVcAS472ZBuSjYyXDa4bWT32",
  "issuanceDate": "2020-01-17T15:14:09.724Z",
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "degree": {
      "type": "BachelorDegree"
    },
    "name": "Jayden Doe",
    "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
  }
}
`

	vc, _, err := NewCredential([]byte(vcJSON))
	require.NoError(t, err)

	created, err := time.Parse(time.RFC3339, "2018-03-15T00:00:00Z")
	require.NoError(t, err)

	err = vc.AddLinkedDataProof(&LinkedDataProofContext{
		SignatureType:           "Ed25519Signature2018",
		Suite:                   ed25519signature2018.New(ed25519signature2018.WithSigner(getSigner(privKey))),
		SignatureRepresentation: SignatureJWS,
		Created:                 &created,
		VerificationMethod:      "did:example:123456#key1",
	})
	require.NoError(t, err)

	require.Len(t, vc.Proofs, 1)

	p := vc.Proofs[0]

	require.Equal(t, "Ed25519Signature2018", p["type"])
	require.Equal(t, "2018-03-15T00:00:00Z", p["created"])
	require.Equal(t, "did:example:123456#key1", p["verificationMethod"])
	require.Equal(t, "eyJhbGciOiJFZDI1NTE5U2lnbmF0dXJlMjAxOCIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..quV5KM2HNIEe4qldY3CwAm8o266UEWWFqVuvJ4P7nYC7bWkQhtH8py5uZanrTkEFjIn0ly1TQgpR3nuC9q2ZCQ", p["jws"]) //nolint:lll
}
