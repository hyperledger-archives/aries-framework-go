/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifier

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/proof"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/signer"
)

func TestVerify(t *testing.T) {
	signedDocBytes, testKeyResolver := getDefaultSignedDoc()
	v := New(testKeyResolver)
	err := v.Verify(signedDocBytes)
	require.Nil(t, err)

	// test invalid json
	err = v.Verify([]byte("not json"))
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "failed to unmarshal json ld document")

	// test proof not found
	err = v.Verify([]byte(validDoc))
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "proof not found")
}

func TestVerifyObject(t *testing.T) {
	jsonLdObject, tkr := getDefaultSignedDocObject()

	// happy path
	v := New(tkr)
	err := v.verifyObject(jsonLdObject)
	require.Nil(t, err)

	// test invalid signature suite
	proofs, err := proof.GetProofs(jsonLdObject)
	require.NoError(t, err)

	proofs[0].Type = "non-existent"
	err = proof.AddProof(jsonLdObject, proofs[0])
	require.NoError(t, err)

	err = v.verifyObject(jsonLdObject)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "signature type non-existent not supported")

	// test key resolver error - key not found
	v = New(&testKeyResolver{})
	err = v.verifyObject(jsonLdObject)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "key not found")

	// test signature error - pass in invalid proof value
	jsonLdObject, tkr = getDefaultSignedDocObject()
	proofs, err = proof.GetProofs(jsonLdObject)
	require.NoError(t, err)

	proofs[0].ProofValue = []byte("invalid")
	err = proof.AddProof(jsonLdObject, proofs[0])
	require.NoError(t, err)

	v = New(tkr)
	err = v.verifyObject(jsonLdObject)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "signature doesn't match")
}

func getDefaultSignedDoc() ([]byte, keyResolver) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	const creator = "key-1"

	keys := make(map[string][]byte)
	keys[creator] = pubKey

	context := signer.Context{Creator: creator,
		SignatureType: "Ed25519Signature2018",
		Signer:        getSigner(privKey)}

	doc := getDefaultDoc()

	docBytes, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}

	s := signer.New()

	signedDocBytes, err := s.Sign(&context, docBytes)
	if err != nil {
		panic(err)
	}

	return signedDocBytes, &testKeyResolver{Keys: keys}
}

func getDefaultSignedDocObject() (map[string]interface{}, keyResolver) {
	signedDocBytes, testKeyResolver := getDefaultSignedDoc()

	var jsonLdObject map[string]interface{}

	err := json.Unmarshal(signedDocBytes, &jsonLdObject)
	if err != nil {
		panic(err)
	}

	return jsonLdObject, testKeyResolver
}

func getDefaultDoc() map[string]interface{} {
	var doc map[string]interface{}

	err := json.Unmarshal([]byte(validDoc), &doc)
	if err != nil {
		panic(err)
	}

	return doc
}

func getSigner(privKey []byte) *testSigner {
	return &testSigner{privateKey: privKey}
}

type testSigner struct {
	privateKey []byte
}

func (s *testSigner) Sign(doc []byte) ([]byte, error) {
	if l := len(s.privateKey); l != ed25519.PrivateKeySize {
		return nil, errors.New("ed25519: bad private key length")
	}

	return ed25519.Sign(s.privateKey, doc), nil
}

type testKeyResolver struct {
	Keys map[string][]byte
}

func (r *testKeyResolver) Resolve(id string) ([]byte, error) {
	key, ok := r.Keys[id]
	if !ok {
		return nil, errors.New("key not found")
	}

	return key, nil
}

//nolint:lll
const validDoc = `{
  "@context": ["https://w3id.org/did/v1"],
  "id": "did:example:123456789abcdefghi",
  "publicKey": [
    {
      "id": "did:example:123456789abcdefghi#keys-1",
      "type": "Secp256k1VerificationKey2018",
      "controller": "did:example:123456789abcdefghi",
      "publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
    }
  ],
  "created": "2002-10-10T17:00:00Z"
}`
