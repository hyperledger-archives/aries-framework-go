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

	clapi "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/cl/api"
)

func TestIsCLBlinder(t *testing.T) {
	clBlinder := NewTestCLBlinder(t)
	defer clBlinder.Free() // nolint: errcheck

	_, ok := interface{}(clBlinder).(clapi.Blinder)
	require.True(t, ok)
}

func TestBlind(t *testing.T) {
	clBlinder := NewTestCLBlinder(t)
	defer clBlinder.Free() // nolint: errcheck

	values := NewTestValues(t)

	blindedVals, err := clBlinder.Blind(values)
	require.NoError(t, err)
	require.NotEmpty(t, blindedVals)
}
