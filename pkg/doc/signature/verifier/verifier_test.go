/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifier

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/proof"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

func TestVerify(t *testing.T) {
	// happy path
	okKeyResolver := &testKeyResolver{
		publicKey: &PublicKey{
			Type:  kms.ED25519,
			Value: []byte("signature"),
		},
	}

	v, err := New(okKeyResolver, &testSignatureSuite{accept: true})
	require.NoError(t, err)
	require.NotNil(t, v)

	err = v.Verify([]byte(validDoc))
	require.NoError(t, err)

	// invalid json passed
	err = v.Verify([]byte("not json"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to unmarshal json ld document")

	// proof not found
	err = v.Verify([]byte("{}"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "proof not found")

	// public key ID is not found
	var doc map[string]interface{}
	err = json.Unmarshal([]byte(validDoc), &doc)
	require.NoError(t, err)

	p, ok := doc["proof"].(map[string]interface{})
	require.True(t, ok)
	delete(p, "verificationMethod")

	docWithoutProofValue, err := json.Marshal(doc)
	require.NoError(t, err)

	err = v.Verify(docWithoutProofValue)
	require.Error(t, err)
	require.EqualError(t, err, "no public key ID")

	// public key is not resolved
	v, err = New(&testKeyResolver{
		err: errors.New("public key is not resolved"),
	}, &testSignatureSuite{accept: true})
	require.NoError(t, err)

	err = v.Verify([]byte(validDoc))
	require.Error(t, err)
	require.EqualError(t, err, "public key is not resolved")

	// signature suite is not found
	v, err = New(okKeyResolver, &testSignatureSuite{accept: false})
	require.NoError(t, err)

	err = v.Verify([]byte(validDoc))
	require.Error(t, err)
	require.EqualError(t, err, "signature type Ed25519Signature2018 not supported")

	// verify data creation error
	v, err = New(okKeyResolver, &testSignatureSuite{
		canonicalDocumentError: errors.New("get canonical document error"),
		accept:                 true,
	})
	require.NoError(t, err)

	err = v.Verify([]byte(validDoc))
	require.Error(t, err)
	require.EqualError(t, err, "get canonical document error")

	// verification error
	v, err = New(okKeyResolver, &testSignatureSuite{
		verifyError: errors.New("verify data error"),
		accept:      true,
	})
	require.NoError(t, err)

	err = v.Verify([]byte(validDoc))
	require.Error(t, err)
	require.EqualError(t, err, "verify data error")

	// no signature suite passed
	v, err = New(okKeyResolver)
	require.Error(t, err)
	require.EqualError(t, err, "at least one suite must be provided")
	require.Nil(t, v)
}

func Test_getProofVerifyValue(t *testing.T) {
	jwsSignature := base64.RawURLEncoding.EncodeToString([]byte("signature"))

	// signatureValue
	p := &proof.Proof{
		SignatureRepresentation: proof.SignatureProofValue,
		ProofValue:              []byte("proof value"),
		JWS:                     "j.w." + jwsSignature,
	}
	proofVerifyValue, err := getProofVerifyValue(p)
	require.NoError(t, err)
	require.Equal(t, []byte("proof value"), proofVerifyValue)

	// JWS
	p.SignatureRepresentation = proof.SignatureJWS
	proofVerifyValue, err = getProofVerifyValue(p)
	require.NoError(t, err)
	require.Equal(t, []byte("signature"), proofVerifyValue)

	// unsupported signature holding
	p.SignatureRepresentation = proof.SignatureRepresentation(-1)
	proofVerifyValue, err = getProofVerifyValue(p)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported signature representation")
	require.Nil(t, proofVerifyValue)
}

type testKeyResolver struct {
	publicKey *PublicKey
	err       error
}

func (r *testKeyResolver) Resolve(string) (*PublicKey, error) {
	return r.publicKey, r.err
}

//nolint:lll
const validDoc = `
{
  "@context": [
    "https://w3id.org/did/v1"
  ],
  "id": "did:example:123456789abcdefghi",
  "publicKey": [
    {
      "id": "did:example:123456789abcdefghi#keys-1",
      "type": "Secp256k1VerificationKey2018",
      "controller": "did:example:123456789abcdefghi",
      "publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
    }
  ],
  "created": "2002-10-10T17:00:00Z",
  "proof": {
    "type": "Ed25519Signature2018",
    "verificationMethod": "did:example:123456#key1",
    "created": "2011-09-23T20:21:34Z",
    "proofValue": "ABC"
  }
}
`

type testSignatureSuite struct {
	canonicalDocument      []byte
	canonicalDocumentError error

	digest []byte

	verifyError error

	accept bool

	compactProof bool
}

func (s *testSignatureSuite) GetCanonicalDocument(map[string]interface{},
	...jsonld.CanonicalizationOpts) ([]byte, error) {
	return s.canonicalDocument, s.canonicalDocumentError
}

func (s *testSignatureSuite) GetDigest([]byte) []byte {
	return s.digest
}

func (s *testSignatureSuite) Verify(*PublicKey, []byte, []byte) error {
	return s.verifyError
}

func (s *testSignatureSuite) Accept(string) bool {
	return s.accept
}

func (s *testSignatureSuite) CompactProof() bool {
	return s.compactProof
}
