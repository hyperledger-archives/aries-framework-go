//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/hyperledger/ursa-wrapper-go/pkg/libursa/ursa"
	"github.com/stretchr/testify/require"

	clsubtle "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/cl/subtle"
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
	signer, err := NewSigner(kh)
	require.NoError(t, err)

	defer signer.Free() // nolint: errcheck

	clBlinder := clsubtle.NewTestCLBlinder(t)
	defer clBlinder.Free() // nolint: errcheck

	vals := clsubtle.NewTestValues(t)
	blindedVals, err := clBlinder.Blind(vals)
	require.NoError(t, err)

	_blindedVals, err := ursa.CredentialValuesFromJSON(blindedVals)
	require.NoError(t, err)

	pubKey, err := ExportCredDefPubKey(pkHandle)
	require.NoError(t, err)
	require.NotEmpty(t, pubKey)

	_pubKey, err := ursa.CredentialPublicKeyFromJSON(pubKey)
	require.NoError(t, err)
	require.NotEmpty(t, _pubKey)

	defer _pubKey.Free() // nolint: errcheck

	correctnessProof, err := signer.GetCorrectnessProof()
	require.NoError(t, err)
	require.NotEmpty(t, correctnessProof)

	_correctnessProof, err := ursa.CredentialKeyCorrectnessProofFromJSON(correctnessProof)
	require.NoError(t, err)
	require.NotEmpty(t, _correctnessProof)

	secrets, proof, offerNonce, requestNonce := clsubtle.NewBlindedSecretsWithNonces(t,
		_pubKey,
		_correctnessProof,
		_blindedVals)

	sig, sigProof, err := signer.Sign(vals, secrets, proof, [][]byte{offerNonce, requestNonce}, "did:example")
	require.NoError(t, err)
	require.NotEmpty(t, sig)
	require.NotEmpty(t, sigProof)
}
