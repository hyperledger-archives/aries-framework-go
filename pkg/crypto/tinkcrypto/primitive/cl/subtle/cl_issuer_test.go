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

func TestIsCLIssuer(t *testing.T) {
	clIssuer := NewTestCLIssuer(t)
	defer clIssuer.Free()

	_, ok := interface{}(clIssuer).(clapi.Issuer)
	require.True(t, ok)
}

func TestGetCredentialDefinition(t *testing.T) {
	clIssuer := NewTestCLIssuer(t)
	defer clIssuer.Free()

	credDef, err := clIssuer.GetCredentialDefinition()

	require.NoError(t, err)
	require.NotEmpty(t, credDef.Attrs)
	require.NotEmpty(t, credDef.CredPubKey)
	require.NotEmpty(t, credDef.CredDefCorrectnessProof)
}

func TestCreateCredOffer(t *testing.T) {
	clIssuer := NewTestCLIssuer(t)
	defer clIssuer.Free()

	credOffer, err := clIssuer.CreateCredentialOffer()
	defer credOffer.Free()

	require.NoError(t, err)
	require.NotEmpty(t, credOffer.Nonce)
}

func TestIssueCredential(t *testing.T) {
	clIssuer := NewTestCLIssuer(t)
	defer clIssuer.Free()
	clProver := NewTestCLProver(t)
	defer clProver.Free()

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
	require.NotEmpty(t, cred)
	require.NotEmpty(t, cred.Signature)
	require.NotEmpty(t, cred.Values)
	require.NotEmpty(t, cred.SigProof)
}
