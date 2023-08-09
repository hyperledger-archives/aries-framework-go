/*
Copyright Gen Digital Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/models/did"
	"github.com/hyperledger/aries-framework-go/component/models/verifiable"

	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr"
)

func TestNewVDRKeyResolver(t *testing.T) {
	resolver := NewVDRKeyResolver(vdr.New())

	require.NotNil(t, resolver)
}

func TestDIDKeyResolver_Resolve(t *testing.T) {
	r := require.New(t)

	didDoc := createDIDDoc()
	publicKey := didDoc.VerificationMethod[0]
	authentication := didDoc.Authentication[0]
	assertionMethod := didDoc.AssertionMethod[0]

	v := &mockvdr.MockVDRegistry{
		ResolveValue: didDoc,
	}

	resolver := NewVDRKeyResolver(v)
	r.NotNil(resolver)

	pubKey, err := resolver.PublicKeyFetcher()(didDoc.ID, publicKey.ID)
	r.NoError(err)
	r.Equal(publicKey.Value, pubKey.Value)
	r.Equal("Ed25519VerificationKey2018", pubKey.Type)
	r.NotNil(pubKey.JWK)
	r.Equal(pubKey.JWK.Algorithm, "EdDSA")

	authPubKey, err := resolver.PublicKeyFetcher()(didDoc.ID, authentication.VerificationMethod.ID)
	r.NoError(err)
	r.Equal(authentication.VerificationMethod.Value, authPubKey.Value)
	r.Equal("Ed25519VerificationKey2018", authPubKey.Type)
	r.NotNil(authPubKey.JWK)
	r.Equal(authPubKey.JWK.Algorithm, "EdDSA")

	assertMethPubKey, err := resolver.PublicKeyFetcher()(didDoc.ID, assertionMethod.VerificationMethod.ID)
	r.NoError(err)
	r.Equal(assertionMethod.VerificationMethod.Value, assertMethPubKey.Value)
	r.Equal("Ed25519VerificationKey2018", assertMethPubKey.Type)

	pubKey, err = resolver.PublicKeyFetcher()(didDoc.ID, "invalid key")
	r.Error(err)
	r.EqualError(err, fmt.Sprintf("public key with KID invalid key is not found for DID %s", didDoc.ID))
	r.Nil(pubKey)

	v.ResolveErr = errors.New("resolver error")
	pubKey, err = resolver.PublicKeyFetcher()(didDoc.ID, "")
	r.Error(err)
	r.EqualError(err, fmt.Sprintf("resolve DID %s: resolver error", didDoc.ID))
	r.Nil(pubKey)
}

//nolint:lll
func createDIDDoc() *did.Doc {
	didDocJSON := `{
  "@context": [
    "https://w3id.org/did/v1"
  ],
  "id": "did:test:2WxUJa8nVjXr5yS69JWoKZ",
  "verificationMethod": [
    {
      "controller": "did:test:8STcrCQFzFxKey7YSbj62A",
      "id": "did:test:8STcrCQFzFxKey7YSbj62A#keys-1",
      "publicKeyJwk": {
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "x": "PD34BecP4G7UcAj2u1ygB9MX31jJnqtkJFvkR1o8nIE"
      },
      "type": "Ed25519VerificationKey2018"
    }
  ],
  "service": [
    {
      "id": "did:test:8STcrCQFzFxKey7YSbj62A#endpoint-1",
      "priority": 0,
      "recipientKeys": [
        "did:test:8STcrCQFzFxKey7YSbj62A#keys-1"
      ],
      "routingKeys": null,
      "serviceEndpoint": "http://localhost:47582",
      "type": "did-communication"
    }
  ],
  "authentication": [
    {
      "controller": "did:test:2WxUJa8nVjXr5yS69JWoKZ",
      "id": "did:test:2WxUJa8nVjXr5yS69JWoKZ#keys-1",
      "publicKeyJwk": {
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "x": "DEfkntM3vCV5WtS-1G9cBMmkNJSPlVdjwSdHmHbirTg"
      },
      "type": "Ed25519VerificationKey2018"
    }
  ],
  "assertionMethod": [
    {
      "id": "did:v1:test:nym:z6MkfG5HTrBXzsAP8AbayNpG3ZaoyM4PCqNPrdWQRSpHDV6J#z6MkqfvdBsFw4QdGrZrnx7L1EKfY5zh9tT4gumUGsMMEZHY3",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:v1:test:nym:z6MkfG5HTrBXzsAP8AbayNpG3ZaoyM4PCqNPrdWQRSpHDV6J",
      "publicKeyBase58": "CDfabd1Vis8ok526GYNAPE7YGRRJUZpLDkZM35PDe4kf"
    }
  ],
  "created": "2020-04-13T12:51:08.274813+03:00",
  "updated": "2020-04-13T12:51:08.274813+03:00"
}`

	didDoc, err := did.ParseDocument([]byte(didDocJSON))
	if err != nil {
		panic(err)
	}

	return didDoc
}

func TestOptions(t *testing.T) {
	opts := []MakeSDJWTOption{
		MakeSDJWTWithRecursiveClaimsObjects([]string{"aa", "bb"}),
		MakeSDJWTWithAlwaysIncludeObjects([]string{"cc", "dd"}),
		MakeSDJWTWithNonSelectivelyDisclosableClaims([]string{"xx", "yy"}),
		MakeSDJWTWithVersion(100500),
	}

	opt := &verifiable.MakeSDJWTOpts{}
	for _, o := range opts {
		o(opt)
	}

	assert.Equal(t, []string{"aa", "bb"}, opt.GetRecursiveClaimsObject())
	assert.Equal(t, []string{"cc", "dd"}, opt.GetAlwaysIncludeObject())
	assert.Equal(t, []string{"xx", "yy"}, opt.GetNonSDClaims())
}
