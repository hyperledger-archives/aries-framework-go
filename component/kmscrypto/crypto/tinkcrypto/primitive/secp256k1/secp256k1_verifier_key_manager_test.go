/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package secp256k1_test

import (
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	"github.com/google/tink/go/testutil"
	"github.com/stretchr/testify/require"

	secp256k1pb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/secp256k1_go_proto"
)

const secp256k1VerifierTypeURL = "type.googleapis.com/google.crypto.tink.secp256k1PublicKey"

func TestSecp256K1VerifyGetPrimitiveBasic(t *testing.T) {
	testParams := genValidSecp256k1Params()
	km, err := registry.GetKeyManager(secp256k1VerifierTypeURL)
	require.NoError(t, err, "cannot obtain secp256K1Verifier key manager")

	for i := 0; i < len(testParams); i++ {
		serializedKey, e := proto.Marshal(NewRandomSecp256K1PublicKey(testParams[i].hashType, testParams[i].curve))
		require.NoError(t, e)

		_, err = km.Primitive(serializedKey)
		require.NoErrorf(t, err, "unexpect error in test case %d ", i)
	}
}

func TestECDSAVerifyGetPrimitiveWithInvalidInput(t *testing.T) {
	testParams := genInvalidSecp256k1Params()
	km, err := registry.GetKeyManager(secp256k1VerifierTypeURL)
	require.NoError(t, err)

	for i := 0; i < len(testParams); i++ {
		serializedKey, e := proto.Marshal(NewRandomSecp256K1PrivateKey(testParams[i].hashType, testParams[i].curve))
		if testParams[i].curve != secp256k1pb.BitcoinCurveType_INVALID_BITCOIN_CURVE {
			require.NoError(t, e)
		}

		_, err = km.Primitive(serializedKey)
		require.Errorf(t, err, "expect an error in test case %d", i)
	}

	// invalid version
	key := NewRandomSecp256K1PublicKey(commonpb.HashType_SHA256, secp256k1pb.BitcoinCurveType_SECP256K1)
	key.Version = testutil.ECDSAVerifierKeyVersion + 1

	serializedKey, e := proto.Marshal(key)
	require.NoError(t, e)

	_, err = km.Primitive(serializedKey)
	require.Error(t, err, "expect an error when version is invalid")

	// nil input
	_, err = km.Primitive(nil)
	require.Error(t, err, "expect an error when input is nil")

	_, err = km.Primitive([]byte{})
	require.Error(t, err, "expect an error when input is empty slice")
}

// NewRandomSecp256K1PublicKey creates an Secp256K1PublicKey with randomly generated key material.
func NewRandomSecp256K1PublicKey(hashType commonpb.HashType,
	curve secp256k1pb.BitcoinCurveType) *secp256k1pb.Secp256K1PublicKey {
	return NewRandomSecp256K1PrivateKey(hashType, curve).PublicKey
}
