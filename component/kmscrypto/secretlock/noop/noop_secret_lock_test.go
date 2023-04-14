/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package noop

import (
	"testing"

	"github.com/hyperledger/aries-framework-go/spi/secretlock"
	"github.com/stretchr/testify/require"
)

func TestNoLock(t *testing.T) {
	noopLock := NoLock{}

	ct, err := noopLock.Encrypt("", &secretlock.EncryptRequest{
		Plaintext: "testKey",
	})
	require.NoError(t, err)
	require.Equal(t, ct.Ciphertext, "testKey")

	pt, err := noopLock.Decrypt("", &secretlock.DecryptRequest{
		Ciphertext: "testKey",
	})
	require.NoError(t, err)
	require.Equal(t, pt.Plaintext, "testKey")
}
