//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"testing"

	clapi "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/cl/api"
	"github.com/stretchr/testify/require"
)

func TestIsCLProver(t *testing.T) {
	clProver := NewTestCLProver(t)
	defer clProver.Free()

	_, ok := interface{}(clProver).(clapi.Prover)
	require.True(t, ok)
}

func TestCreateCredentialRequest(t *testing.T) {
	clProver := NewTestCLProver(t)
	defer clProver.Free()
	clIssuer := NewTestCLIssuer(t)
	defer clIssuer.Free()

	credDef, err := clIssuer.GetCredentialDefinition()
	require.NoError(t, err)

	credOffer, err := clIssuer.CreateCredentialOffer()
	defer credOffer.Free()
	require.NoError(t, err)

	credReq, err := clProver.CreateCredentialRequest(credOffer, credDef, "myproverID")
	defer credReq.Free()

	require.NoError(t, err)
	require.NotEmpty(t, credReq.Nonce)
	require.NotEmpty(t, credReq.BlindedCredentialSecrets)
	require.Equal(t, "myproverID", credReq.ProverId)
}

func TestProcessCredential(t *testing.T) {
	clProver := NewTestCLProver(t)
	defer clProver.Free()
	clIssuer := NewTestCLIssuer(t)
	defer clIssuer.Free()

	credDef, err := clIssuer.GetCredentialDefinition()
	require.NoError(t, err)

	credOffer, err := clIssuer.CreateCredentialOffer()
	defer credOffer.Free()
	require.NoError(t, err)

	credReq, err := clProver.CreateCredentialRequest(credOffer, credDef, "proverID")
	defer credReq.Free()
	require.NoError(t, err)

	values := NewTestValues(t, *credOffer)
	cred, err := clIssuer.IssueCredential(values, credReq, credOffer)
	defer cred.Free()
	require.NoError(t, err)

	err = clProver.ProcessCredential(cred, credReq, credDef)
	require.NoError(t, err)
}

func TestCreateProof(t *testing.T) {
	clProver := NewTestCLProver(t)
	defer clProver.Free()
	clIssuer := NewTestCLIssuer(t)
	defer clIssuer.Free()

	credDef, err := clIssuer.GetCredentialDefinition()
	require.NoError(t, err)

	credOffer, err := clIssuer.CreateCredentialOffer()
	defer credOffer.Free()
	require.NoError(t, err)

	credReq, err := clProver.CreateCredentialRequest(credOffer, credDef, "proverID")
	defer credReq.Free()
	require.NoError(t, err)

	values := NewTestValues(t, *credOffer)
	cred, err := clIssuer.IssueCredential(values, credReq, credOffer)
	defer cred.Free()
	require.NoError(t, err)

	err = clProver.ProcessCredential(cred, credReq, credDef)
	require.NoError(t, err)

	presReq := NewTestPresentationRequest(t)
	defer presReq.Free()

	proof, err := clProver.CreateProof(presReq, []*clapi.Credential{cred}, []*clapi.CredentialDefinition{credDef})
	defer proof.Free()

	require.NoError(t, err)
	require.NotEmpty(t, proof)
	require.NotEmpty(t, proof.Proof)
	require.NotEmpty(t, proof.SubProofs)
	require.NotEmpty(t, proof.SubProofs[0])
	require.NotEmpty(t, proof.SubProofs[0].Attrs)
	require.NotEmpty(t, proof.SubProofs[0].SubProof)

	err = Verify(t, presReq, proof, credDef)
	require.NoError(t, err)
}
