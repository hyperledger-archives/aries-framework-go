/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"testing"

	commonpb "github.com/google/tink/go/proto/common_go_proto"
	"github.com/google/tink/go/subtle/hybrid"
	"github.com/google/tink/go/subtle/random"
	"github.com/stretchr/testify/require"
)

func TestWrap(t *testing.T) {
	keySize := 32
	curve, err := hybrid.GetCurve(commonpb.EllipticCurveType_NIST_P256.String())
	require.NoError(t, err)

	recPvt, err := hybrid.GenerateECDHKeyPair(curve)
	require.NoError(t, err)

	recPubKey := &recPvt.PublicKey

	senderKW := &ECDHESConcatKDFSenderKW{
		recipientPublicKey: recPubKey,
		cek:                random.GetRandomBytes(uint32(keySize)),
	}

	wrappedKey, err := senderKW.wrapKey(A256KWAlg, keySize)
	require.NoError(t, err)
	require.NotEmpty(t, wrappedKey)
	require.EqualValues(t, A256KWAlg, wrappedKey.Alg)

	recipientKW := &ECDHESConcatKDFRecipientKW{
		recipientPrivateKey: recPvt,
	}

	cek, err := recipientKW.unwrapKey(wrappedKey, keySize)
	require.NoError(t, err)
	require.EqualValues(t, senderKW.cek, cek)

	// error test cases
	_, err = recipientKW.unwrapKey(nil, keySize)
	require.Error(t, err)
}
