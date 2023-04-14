//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"testing"

	"github.com/hyperledger/ursa-wrapper-go/pkg/libursa/ursa"
	"github.com/stretchr/testify/require"

	clapi "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/cl/api"
)

func TestIsCLSigner(t *testing.T) {
	clSigner := NewTestCLSigner(t)
	defer clSigner.Free() // nolint: errcheck

	_, ok := interface{}(clSigner).(clapi.Signer)
	require.True(t, ok)
}

func TestGetCorrectnessProof(t *testing.T) {
	clSigner := NewTestCLSigner(t)
	defer clSigner.Free() // nolint: errcheck

	correctnessProof, err := clSigner.GetCorrectnessProof()
	require.NoError(t, err)
	require.NotEmpty(t, correctnessProof)
}

func TestSign(t *testing.T) {
	clBlinder := NewTestCLBlinder(t)
	defer clBlinder.Free() // nolint: errcheck

	clSigner := NewTestCLSigner(t)
	defer clSigner.Free() // nolint: errcheck

	vals := NewTestValues(t)
	blindedVals, err := clBlinder.Blind(vals)
	require.NoError(t, err)

	_blindedVals, err := ursa.CredentialValuesFromJSON(blindedVals)
	require.NoError(t, err)

	defer _blindedVals.Free() // nolint: errcheck

	secrets, proof, offerNonce, requestNonce := NewBlindedSecretsWithNonces(t,
		clSigner.pubKey, clSigner.correctnessProof, _blindedVals)

	sig, sigProof, err := clSigner.Sign(vals, secrets, proof, [][]byte{offerNonce, requestNonce}, "did:example")
	require.NoError(t, err)
	require.NotEmpty(t, sig)
	require.NotEmpty(t, sigProof)
}
