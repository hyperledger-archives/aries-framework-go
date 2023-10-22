/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbsplusthresholdpub_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	bbs "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbsplusthresholdpub"
)

func TestParseSignature(t *testing.T) {
	sigBytes := []byte{179, 22, 156, 110, 6, 135, 216, 0, 253, 221, 34, 23, 84, 99, 206, 177, 70, 39, 227, 170, 31, 198, 153, 146, 254, 80, 87, 165, 43, 147, 216, 60, 240, 196, 31, 200, 191, 85, 46, 230, 229, 198, 52, 94, 39, 178, 132, 7, 20, 151, 53, 123, 253, 84, 174, 230, 112, 210, 136, 122, 249, 50, 146, 214, 210, 252, 142, 158, 39, 0, 128, 216, 193, 210, 12, 195, 20, 250, 40, 251, 3, 48, 32, 63, 3, 72, 128, 226, 173, 209, 93, 73, 253, 95, 122, 81, 60, 8, 9, 70, 136, 171, 193, 249, 190, 245, 171, 187, 253, 25, 107, 201} //nolint:lll

	signature, err := bbs.ParseSignature(sigBytes)
	require.NoError(t, err)

	sigBytes2, err := signature.ToBytes()
	require.NoError(t, err)
	require.Equal(t, sigBytes, sigBytes2)

	// invalid G1 signature part
	invalidSigBytes := make([]byte, len(sigBytes))
	signature, err = bbs.ParseSignature(invalidSigBytes)
	require.Error(t, err)
	require.Contains(t, err.Error(), "deserialize G1 compressed signature")
	require.Nil(t, signature)
}
