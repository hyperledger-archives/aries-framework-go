/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifier

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/proof"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/signer"
)

func TestNew(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// default ed25519signature2018 signature suite is created
	_, testKeyResolver := getDefaultSignedDoc(proof.SignatureProofValue, privKey, pubKey)
	verifier := New(testKeyResolver)
	require.Len(t, verifier.signatureSuites, 1)
}

func TestVerify(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	signedDocBytes, testKeyResolver := getDefaultSignedDoc(proof.SignatureProofValue, privKey, pubKey)
	v := New(testKeyResolver, ed25519signature2018.New())
	err = v.Verify(signedDocBytes)
	require.Nil(t, err)

	// test invalid json
	err = v.Verify([]byte("not json"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to unmarshal json ld document")

	// test proof not found
	err = v.Verify([]byte(validDoc))
	require.Error(t, err)
	require.Contains(t, err.Error(), "proof not found")
}

func TestVerifyJWSProof(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	signedDocBytes, testKeyResolver := getDefaultSignedDoc(proof.SignatureJWS, privKey, pubKey)
	v := New(testKeyResolver)
	err = v.Verify(signedDocBytes)
	require.NoError(t, err)
}

func TestVerifyObject(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	jsonLdObject, tkr := getDefaultSignedDocObject(proof.SignatureProofValue, privKey, pubKey)

	suite := ed25519signature2018.New()

	// happy path
	v := New(tkr, suite)
	err = v.verifyObject(jsonLdObject)
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
	v = New(&testKeyResolver{}, suite)
	err = v.verifyObject(jsonLdObject)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "key not found")

	// test signature error - pass in invalid proof value
	jsonLdObject, tkr = getDefaultSignedDocObject(proof.SignatureProofValue, privKey, pubKey)
	proofs, err = proof.GetProofs(jsonLdObject)
	require.NoError(t, err)

	proofs[0].ProofValue = []byte("invalid")
	err = proof.AddProof(jsonLdObject, proofs[0])
	require.NoError(t, err)

	v = New(tkr, suite)
	err = v.verifyObject(jsonLdObject)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "signature doesn't match")
}

func TestVerifyJWSObject(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	jsonLdObject, tkr := getDefaultSignedDocObject(proof.SignatureJWS, privKey, pubKey)

	// happy path
	v := New(tkr)
	err = v.verifyObject(jsonLdObject)
	require.Nil(t, err)

	// test invalid signature suite
	proofs, err := proof.GetProofs(jsonLdObject)
	require.NoError(t, err)

	proofs[0].JWS = "invalid JWT.."

	err = proof.AddProof(jsonLdObject, proofs[0])
	require.NoError(t, err)

	err = v.verifyObject(jsonLdObject)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid JWT")
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

func getDefaultSignedDoc(signatureRepr proof.SignatureRepresentation, privKey, pubKey []byte) ([]byte, keyResolver) {
	const creator = "key-1"

	keys := make(map[string][]byte)
	keys[creator] = pubKey

	context := signer.Context{Creator: creator,
		SignatureType:           "Ed25519Signature2018",
		SignatureRepresentation: signatureRepr}

	doc := getDefaultDoc()

	docBytes, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}

	s := signer.New(ed25519signature2018.New(
		ed25519signature2018.WithSigner(
			getSigner(privKey))))

	signedDocBytes, err := s.Sign(&context, docBytes)
	if err != nil {
		panic(err)
	}

	return signedDocBytes, &testKeyResolver{Keys: keys}
}

func getDefaultSignedDocObject(signatureRepr proof.SignatureRepresentation, privKey, pubKey []byte) (
	map[string]interface{}, keyResolver) {
	signedDocBytes, testKeyResolver := getDefaultSignedDoc(signatureRepr, privKey, pubKey)

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
