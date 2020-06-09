/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"testing"

	hybrid "github.com/google/tink/go/hybrid/subtle"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	"github.com/google/tink/go/subtle/random"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	compositepb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/common_composite_go_proto"
)

func TestWrap(t *testing.T) {
	keySize := 32
	curve, err := hybrid.GetCurve(commonpb.EllipticCurveType_NIST_P256.String())
	require.NoError(t, err)

	recPvt, err := hybrid.GenerateECDHKeyPair(curve)
	require.NoError(t, err)

	recPubKey := &composite.PublicKey{
		Type:  compositepb.KeyType_EC.String(),
		Curve: recPvt.PublicKey.Curve.Params().Name,
		X:     recPvt.PublicKey.Point.X.Bytes(),
		Y:     recPvt.PublicKey.Point.Y.Bytes(),
	}

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
