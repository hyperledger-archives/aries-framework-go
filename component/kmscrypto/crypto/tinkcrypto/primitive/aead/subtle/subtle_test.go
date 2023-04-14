/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead/subtle"
)

func TestValidateAESKeySize(t *testing.T) {
	var i uint32
	for i = 0; i < 65; i++ {
		err := subtle.ValidateAESKeySize(i)

		switch i {
		case 16, 24, 32: // Valid key sizes.
			require.NoError(t, err)

		default:
			// Invalid key sizes.
			require.Errorf(t, err, "invalid key size (%d) should not be accepted", i)

			require.Contains(t, err.Error(), "invalid AES key size; want 16, 24 or 32")
		}
	}
}
