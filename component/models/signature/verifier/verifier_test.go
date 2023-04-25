/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifier

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/models/ld/processor"
	"github.com/hyperledger/aries-framework-go/component/models/ld/proof"
	"github.com/hyperledger/aries-framework-go/component/models/signature/api"
	"github.com/hyperledger/aries-framework-go/spi/kms"
)

//go:embed testdata/valid_doc.jsonld
var validDoc string //nolint:gochecknoglobals

func TestVerify(t *testing.T) {
	// happy path
	okKeyResolver := &testKeyResolver{
		publicKey: &api.PublicKey{
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
	publicKey *api.PublicKey
	err       error
}

func (r *testKeyResolver) Resolve(string) (*api.PublicKey, error) {
	return r.publicKey, r.err
}

type testSignatureSuite struct {
	canonicalDocument      []byte
	canonicalDocumentError error

	digest       []byte
	verifyError  error
	accept       bool
	compactProof bool
}

func (s *testSignatureSuite) GetCanonicalDocument(map[string]interface{}, ...processor.Opts) ([]byte, error) {
	return s.canonicalDocument, s.canonicalDocumentError
}

func (s *testSignatureSuite) GetDigest([]byte) []byte {
	return s.digest
}

func (s *testSignatureSuite) Verify(*api.PublicKey, []byte, []byte) error {
	return s.verifyError
}

func (s *testSignatureSuite) Accept(string) bool {
	return s.accept
}

func (s *testSignatureSuite) CompactProof() bool {
	return s.compactProof
}
