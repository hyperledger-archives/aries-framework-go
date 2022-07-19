//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package prover

import (
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/stretchr/testify/require"

	clapi "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/cl/api"
	clsubtle "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/cl/subtle"
)

func TestCLMasterSecretKeyTemplateSuccess(t *testing.T) {
	kt := MasterSecretKeyTemplate()
	kh, err := keyset.NewHandle(kt)
	require.NoError(t, err)
	require.NotEmpty(t, kh)

	// now test the CL primitives with these keyset handles
	prover, err := NewProver(kh)
	defer prover.Free()
	require.NoError(t, err)
	issuer := clsubtle.NewTestCLIssuer(t)
	defer issuer.Free()

	credDef, err := issuer.GetCredentialDefinition()
	require.NoError(t, err)

	credOffer, err := issuer.CreateCredentialOffer()
	defer credOffer.Free()
	require.NoError(t, err)

	credReq, err := prover.CreateCredentialRequest(credOffer, credDef, "myproverID")
	defer credReq.Free()
	require.NoError(t, err)
	require.NotEmpty(t, credReq.Nonce)
	require.NotEmpty(t, credReq.BlindedCredentialSecrets)
	require.Equal(t, "myproverID", credReq.ProverId)

	values := clsubtle.NewTestValues(t, *credOffer)
	cred, err := issuer.IssueCredential(values, credReq, credOffer)
	defer cred.Free()
	require.NoError(t, err)

	err = prover.ProcessCredential(cred, credReq, credDef)
	require.NoError(t, err)

	presReq := clsubtle.NewTestPresentationRequest(t)
	defer presReq.Free()

	proof, err := prover.CreateProof(presReq, []*clapi.Credential{cred}, []*clapi.CredentialDefinition{credDef})
	defer proof.Free()

	require.NoError(t, err)
	require.NotEmpty(t, proof)
	require.NotEmpty(t, proof.Proof)
	require.NotEmpty(t, proof.SubProofs)
	require.NotEmpty(t, proof.SubProofs[0])
	require.NotEmpty(t, proof.SubProofs[0].Attrs)
	require.NotEmpty(t, proof.SubProofs[0].SubProof)

	err = clsubtle.Verify(t, presReq, proof, credDef)
	require.NoError(t, err)
}
