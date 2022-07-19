//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"testing"

	"github.com/stretchr/testify/require"

	clapi "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/cl/api"
	"github.com/hyperledger/ursa-wrapper-go/pkg/libursa/ursa"
)

func NewTestCLProver(t *testing.T) *CLProver {
	prover, err := NewCLProver(CreateMasterSecretKeyJson(t))
	require.NoError(t, err)
	return prover
}

func NewTestCLIssuer(t *testing.T) *CLIssuer {
	issuer, err := NewCLIssuer(CreateCredentialDefinitionJson(t))
	require.NoError(t, err)
	return issuer
}

func NewTestValues(t *testing.T, credOffer clapi.CredentialOffer) map[string]interface{} {
	return map[string]interface{}{"attr1": 5, "attr2": "aaa"}
}

func NewTestPresentationRequest(t *testing.T) *clapi.PresentationRequest {
	nonce, err := ursa.NewNonce()
	require.NoError(t, err)
	item := clapi.PresentationRequestItem{
		RevealedAttrs: []string{"attr2"},
		Predicates: []*clapi.Predicate{
			{
				PType: "GE",
				Attr:  "attr1",
				Value: 4,
			},
		},
	}
	return &clapi.PresentationRequest{
		Items: []*clapi.PresentationRequestItem{&item},
		Nonce: nonce,
	}
}

func CreateMasterSecretKeyJson(t *testing.T) []byte {
	masterSecret, err := ursa.NewMasterSecret()
	require.NoError(t, err)
	masterSecretJson, err := masterSecret.ToJSON()
	require.NoError(t, err)
	return masterSecretJson
}

func CreateCredentialDefinitionJson(t *testing.T) ([]byte, []byte, []byte, []string) {
	attrs := []string{"attr1", "attr2"}
	schema, nonSchema, err := BuildSchema(attrs)
	require.NoError(t, err)

	credDef, err := ursa.NewCredentialDef(schema, nonSchema, false)

	privKeyJson, err := credDef.PrivKey.ToJSON()
	require.NoError(t, err)
	pubKeyJson, err := credDef.PubKey.ToJSON()
	require.NoError(t, err)
	proofJson, err := credDef.KeyCorrectnessProof.ToJSON()
	require.NoError(t, err)

	require.NoError(t, err)
	return privKeyJson, pubKeyJson, proofJson, attrs
}

func Verify(
	t *testing.T, presentationReq *clapi.PresentationRequest, proof *clapi.Proof, credDef *clapi.CredentialDefinition,
) error {
	verifier, err := ursa.NewProofVerifier()
	require.NoError(t, err)

	subProof := proof.SubProofs[0]
	schema, nonSchema, err := BuildSchema(subProof.Attrs)
	if err != nil {
		return err
	}
	defer schema.Free()
	defer nonSchema.Free()

	err = verifier.AddSubProofRequest(
		subProof.SubProof, schema, nonSchema, credDef.CredPubKey,
	)
	require.NoError(t, err)

	return verifier.Verify(proof.Proof, presentationReq.Nonce)
}
