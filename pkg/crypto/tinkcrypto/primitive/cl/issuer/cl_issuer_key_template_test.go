//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuer

import (
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/stretchr/testify/require"

	clsubtle "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/cl/subtle"
)

func TestCLCredDefKeyTemplateSuccess(t *testing.T) {
	attrs := []string{"attr1", "attr2"}
	kt := CredDefKeyTemplate(attrs)
	kh, err := keyset.NewHandle(kt)
	require.NoError(t, err)
	require.NotEmpty(t, kh)

	pkHandle, err := kh.Public()
	require.NoError(t, err)
	require.NotEmpty(t, pkHandle)

	// now test the CL primitives with these keyset handles
	issuer, err := NewIssuer(kh)
	defer issuer.Free()
	require.NoError(t, err)
	prover := clsubtle.NewTestCLProver(t)
	defer prover.Free()

	credDef, err := issuer.GetCredentialDefinition()
	require.NoError(t, err)
	require.NotEmpty(t, credDef.Attrs)
	require.NotEmpty(t, credDef.CredPubKey)
	require.NotEmpty(t, credDef.CredDefCorrectnessProof)

	credOffer, err := issuer.CreateCredentialOffer()
	defer credOffer.Free()
	require.NoError(t, err)
	require.NotEmpty(t, credOffer.Nonce)

	credReq, err := prover.CreateCredentialRequest(credOffer, credDef, "proverID")
	defer credReq.Free()
	require.NoError(t, err)

	values := clsubtle.NewTestValues(t, *credOffer)
	cred, err := issuer.IssueCredential(values, credReq, credOffer)
	defer cred.Free()

	require.NoError(t, err)
	require.NotEmpty(t, cred)
	require.NotEmpty(t, cred.Signature)
	require.NotEmpty(t, cred.Values)
	require.NotEmpty(t, cred.SigProof)
}
