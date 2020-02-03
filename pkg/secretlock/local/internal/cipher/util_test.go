/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package cipher

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreateAESCipherWithLongKey(t *testing.T) {
	veryLongMK := make([]byte, 99)
	for i := range veryLongMK {
		veryLongMK[i] = 'a'
	}

	mk, err := CreateAESCipher(veryLongMK)
	require.Error(t, err)
	require.Empty(t, mk)
}

func TestCreateAESCipherWithValidKey(t *testing.T) {
	mkWithValidSize := make([]byte, 32)
	for i := range mkWithValidSize {
		mkWithValidSize[i] = 'a'
	}

	mk, err := CreateAESCipher(mkWithValidSize)
	require.NoError(t, err)
	require.NotEmpty(t, mk)
}
