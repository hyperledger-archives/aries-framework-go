//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package blinder

import (
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/stretchr/testify/require"

	clsubtle "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/cl/subtle"
)

func TestCLMasterSecretKeyTemplateSuccess(t *testing.T) {
	kt := MasterSecretKeyTemplate()
	kh, err := keyset.NewHandle(kt)
	require.NoError(t, err)
	require.NotEmpty(t, kh)

	// now test the CL primitives with these keyset handles
	blinder, err := NewBlinder(kh)
	require.NoError(t, err)

	values := clsubtle.NewTestValues(t)

	blindedVals, err := blinder.Blind(values)
	require.NoError(t, err)
	require.NotEmpty(t, blindedVals)
}
