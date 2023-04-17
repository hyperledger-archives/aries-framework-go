/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package secp256k1_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/google/tink/go/core/registry"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/subtle/random"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	secp256k1pb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/secp256k1_go_proto"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/secp256k1/subtle"
)

const (
	secp256k1SignerKeyVersion = uint32(0)
	secp256k1SignerTypeURL    = "type.googleapis.com/google.crypto.tink.secp256k1PrivateKey"
)

type secp256k1Params struct {
	hashType commonpb.HashType
	curve    secp256k1pb.BitcoinCurveType
}

func TestSecp256k1SignerGetPrimitiveBasic(t *testing.T) {
	testParams := genValidSecp256k1Params()
	km, err := registry.GetKeyManager(secp256k1SignerTypeURL)
	require.NoError(t, err)

	for i := 0; i < len(testParams); i++ {
		serializedKey, e := proto.Marshal(NewRandomSecp256K1PrivateKey(testParams[i].hashType, testParams[i].curve))
		require.NoError(t, e)

		_, err = km.Primitive(serializedKey)
		require.NoErrorf(t, err, "unexpect error in test case %d ", i)
	}
}

func TestECDSASecp256K1SignGetPrimitiveWithInvalidInput(t *testing.T) {
	// invalid params
	testParams := genInvalidSecp256k1Params()
	km, err := registry.GetKeyManager(secp256k1SignerTypeURL)
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
	key := NewRandomSecp256K1PrivateKey(commonpb.HashType_SHA256,
		secp256k1pb.BitcoinCurveType_SECP256K1)
	key.Version = secp256k1SignerKeyVersion + 1
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

func TestECDSASecp256K1SignNewKeyBasic(t *testing.T) {
	testParams := genValidSecp256k1Params()

	km, err := registry.GetKeyManager(secp256k1SignerTypeURL)
	require.NoError(t, err)

	for i := 0; i < len(testParams); i++ {
		params := NewSecp256K1Params(testParams[i].hashType, testParams[i].curve,
			secp256k1pb.Secp256K1SignatureEncoding_Bitcoin_DER)

		serializedFormat, e := proto.Marshal(newSecp256K1KeyFormat(params))
		require.NoError(t, e)

		tmp, e := km.NewKey(serializedFormat)
		require.NoError(t, e)

		key, ok := tmp.(*secp256k1pb.Secp256K1PrivateKey)
		require.True(t, ok)

		err = validateECDSASecp256K1PrivateKey(t, key, params)
		require.NoErrorf(t, err, "invalid private key in test case %d", i)
	}
}

func TestECDSASecp256K1SignNewKeyWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager(secp256k1SignerTypeURL)
	require.NoError(t, err)

	// invalid hash and curve type
	testParams := genInvalidSecp256k1Params()
	for i := 0; i < len(testParams); i++ {
		params := NewSecp256K1Params(testParams[i].hashType, testParams[i].curve,
			secp256k1pb.Secp256K1SignatureEncoding_Bitcoin_DER)

		serializedFormat, e := proto.Marshal(newSecp256K1KeyFormat(params))
		require.NoError(t, e)

		_, err = km.NewKey(serializedFormat)
		require.Errorf(t, err, "expect an error in test case %d", i)
	}

	// invalid encoding
	testParams = genValidSecp256k1Params()
	for i := 0; i < len(testParams); i++ {
		params := NewSecp256K1Params(testParams[i].hashType, testParams[i].curve,
			secp256k1pb.Secp256K1SignatureEncoding_UNKNOWN_BITCOIN_ENCODING)

		serializedFormat, e := proto.Marshal(newSecp256K1KeyFormat(params))
		require.NoError(t, e)

		_, err = km.NewKey(serializedFormat)
		require.Errorf(t, err, "expect an error in test case %d", i)
	}

	// nil input
	_, err = km.NewKey(nil)
	require.Error(t, err, "expect an error when input is nil")

	_, err = km.NewKey([]byte{})
	require.Error(t, err, "expect an error when input is empty slice")
}

func TestECDSASecp256K1SignNewKeyMultipleTimes(t *testing.T) {
	km, err := registry.GetKeyManager(secp256k1SignerTypeURL)
	require.NoError(t, err)

	testParams := genValidSecp256k1Params()

	nTest := 27

	for i := 0; i < len(testParams); i++ {
		keys := make(map[string]bool)
		params := NewSecp256K1Params(testParams[i].hashType, testParams[i].curve,
			secp256k1pb.Secp256K1SignatureEncoding_Bitcoin_DER)
		format := newSecp256K1KeyFormat(params)

		serializedFormat, e := proto.Marshal(format)
		require.NoError(t, e)

		for j := 0; j < nTest; j++ {
			key, e := km.NewKey(serializedFormat)
			require.NoError(t, e)

			serializedKey, e := proto.Marshal(key)
			require.NoError(t, e)

			keys[string(serializedKey)] = true

			keyData, e := km.NewKeyData(serializedFormat)
			require.NoError(t, e)

			serializedKey = keyData.Value
			keys[string(serializedKey)] = true
		}

		require.Equalf(t, len(keys), nTest*2, "key is repeated with params: %s", params)
	}
}

func TestECDSASecp256K1SignNewKeyDataBasic(t *testing.T) {
	km, err := registry.GetKeyManager(secp256k1SignerTypeURL)
	require.NoError(t, err)

	testParams := genValidSecp256k1Params()
	for i := 0; i < len(testParams); i++ {
		params := NewSecp256K1Params(testParams[i].hashType, testParams[i].curve,
			secp256k1pb.Secp256K1SignatureEncoding_Bitcoin_DER)
		serializedFormat, e := proto.Marshal(newSecp256K1KeyFormat(params))
		require.NoError(t, e)

		keyData, e := km.NewKeyData(serializedFormat)
		require.NoErrorf(t, e, "unexpected error in test case  %d", i)

		require.Equalf(t, keyData.TypeUrl, secp256k1SignerTypeURL,
			"incorrect type url in test case  %d: expect %s, got %s",
			i, secp256k1SignerTypeURL, keyData.TypeUrl)

		require.Equalf(t, keyData.KeyMaterialType, tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			"incorrect key material type in test case  %d: expect %s, got %s",
			i, tinkpb.KeyData_ASYMMETRIC_PRIVATE, keyData.KeyMaterialType)

		key := new(secp256k1pb.Secp256K1PrivateKey)
		err = proto.Unmarshal(keyData.Value, key)
		require.NoErrorf(t, err, "unexpect error in test case %d", i)

		err = validateECDSASecp256K1PrivateKey(t, key, params)
		require.NoErrorf(t, err, "invalid private key in test case %d", i)
	}
}

func TestECDSASecp256K1SignNewKeyDataWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager(secp256k1SignerTypeURL)
	require.NoError(t, err)

	testParams := genInvalidSecp256k1Params()
	for i := 0; i < len(testParams); i++ {
		params := NewSecp256K1Params(testParams[i].hashType, testParams[i].curve,
			secp256k1pb.Secp256K1SignatureEncoding_Bitcoin_DER)
		format := newSecp256K1KeyFormat(params)

		serializedFormat, e := proto.Marshal(format)
		require.NoError(t, e)

		_, err = km.NewKeyData(serializedFormat)
		require.Errorf(t, err, "expect an error in test case  %d", i)
	}

	// nil input
	_, err = km.NewKeyData(nil)
	require.Errorf(t, err, "expect an error when input is nil")
}

func TestPublicKeyDataBasic(t *testing.T) {
	testParams := genValidSecp256k1Params()

	km, err := registry.GetKeyManager(secp256k1SignerTypeURL)
	require.NoError(t, err)

	pkm, ok := km.(registry.PrivateKeyManager)
	require.True(t, ok, "cannot obtain private key manager")

	for i := 0; i < len(testParams); i++ {
		key := NewRandomSecp256K1PrivateKey(testParams[i].hashType, testParams[i].curve)
		serializedKey, e := proto.Marshal(key)
		require.NoError(t, e)

		pubKeyData, e := pkm.PublicKeyData(serializedKey)
		require.NoErrorf(t, e, "unexpect error in test case %d", i)

		require.Equalf(t, pubKeyData.TypeUrl, secp256k1VerifierTypeURL, "incorrect type url: %s", pubKeyData.TypeUrl)

		require.Equalf(t, pubKeyData.KeyMaterialType, tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			"incorrect key material type: %d", pubKeyData.KeyMaterialType)

		pubKey := new(secp256k1pb.Secp256K1PublicKey)
		err = proto.Unmarshal(pubKeyData.Value, pubKey)
		require.NoError(t, err)
	}
}

func TestPublicKeyDataWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager(secp256k1SignerTypeURL)
	require.NoError(t, err)

	pkm, ok := km.(registry.PrivateKeyManager)
	require.True(t, ok, "cannot obtain private key manager")

	// modified key
	key := NewRandomSecp256K1PrivateKey(commonpb.HashType_SHA256, secp256k1pb.BitcoinCurveType_SECP256K1)
	serializedKey, err := proto.Marshal(key)
	require.NoError(t, err)

	serializedKey[0] = 0

	_, err = pkm.PublicKeyData(serializedKey)
	require.Error(t, err, "expect an error when input is a modified serialized key")
}

var errSmallKey = fmt.Errorf("private key doesn't have adequate size")

func validateECDSASecp256K1PrivateKey(t *testing.T, key *secp256k1pb.Secp256K1PrivateKey,
	params *secp256k1pb.Secp256K1Params) error {
	require.Equalf(t, key.Version, secp256k1SignerKeyVersion, "incorrect private key's version: expect %d, got %d",
		secp256k1SignerKeyVersion, key.Version)

	publicKey := key.PublicKey
	require.Equalf(t, publicKey.Version, secp256k1SignerKeyVersion, "incorrect public key's version: expect %d, got %d",
		secp256k1SignerKeyVersion, key.Version)

	if params.HashType != publicKey.Params.HashType ||
		params.Curve != publicKey.Params.Curve ||
		params.Encoding != publicKey.Params.Encoding {
		return fmt.Errorf("incorrect params: expect %s, got %s", params, publicKey.Params)
	}

	if len(publicKey.X) == 0 || len(publicKey.Y) == 0 {
		return fmt.Errorf("public points are not initialized")
	}

	// check private key's size
	d := new(big.Int).SetBytes(key.KeyValue)
	keySize := len(d.Bytes())

	if params.Curve == secp256k1pb.BitcoinCurveType_SECP256K1 {
		if keySize < 256/8-8 || keySize > 256/8+1 {
			return errSmallKey
		}
	}

	// try to sign and verify with the key
	hash, curve, encoding := getSecp256K1ParamNames(publicKey.Params)
	signer, err := subtle.NewSecp256K1Signer(hash, curve, encoding, key.KeyValue)
	require.NoError(t, err, "unexpected error when creating Secp256K1Sign")

	verifier, err := subtle.NewSecp256K1Verifier(hash, curve, encoding, publicKey.X, publicKey.Y)
	require.NoError(t, err, "unexpected error when creating Secp256K1Verify")

	data := random.GetRandomBytes(1281)

	signature, err := signer.Sign(data)
	require.NoError(t, err, "unexpected error when signing")

	err = verifier.Verify(signature, data)
	require.NoError(t, err, "unexpected error when verifying signature")

	return nil
}

func genValidSecp256k1Params() []secp256k1Params {
	return []secp256k1Params{
		{
			hashType: commonpb.HashType_SHA256,
			curve:    secp256k1pb.BitcoinCurveType_SECP256K1,
		},
	}
}

func genInvalidSecp256k1Params() []secp256k1Params {
	return []secp256k1Params{
		{
			hashType: commonpb.HashType_SHA1,
			curve:    secp256k1pb.BitcoinCurveType_SECP256K1,
		},
		{
			hashType: commonpb.HashType_SHA1,
			curve:    secp256k1pb.BitcoinCurveType_INVALID_BITCOIN_CURVE,
		},
	}
}

// NewRandomSecp256K1PrivateKey creates an ECDSAPrivateKey with randomly generated key material.
func NewRandomSecp256K1PrivateKey(hashType commonpb.HashType,
	curve secp256k1pb.BitcoinCurveType) *secp256k1pb.Secp256K1PrivateKey {
	curveName := secp256k1pb.BitcoinCurveType_name[int32(curve)]
	if curveName == secp256k1pb.BitcoinCurveType_INVALID_BITCOIN_CURVE.String() {
		return nil
	}

	priv, e := ecdsa.GenerateKey(subtle.GetCurve(curveName), rand.Reader)
	if e != nil {
		return nil
	}

	params := NewSecp256K1Params(hashType, curve, secp256k1pb.Secp256K1SignatureEncoding_Bitcoin_DER)
	publicKey := newSecp256K1PublicKey(secp256k1SignerKeyVersion, params, priv.X.Bytes(), priv.Y.Bytes())

	return newSecp256K1APrivateKey(secp256k1SignerKeyVersion, publicKey, priv.D.Bytes())
}

// NewSecp256K1Params creates a ECDSAParams with the specified parameters.
func NewSecp256K1Params(hashType commonpb.HashType,
	curve secp256k1pb.BitcoinCurveType,
	encoding secp256k1pb.Secp256K1SignatureEncoding) *secp256k1pb.Secp256K1Params {
	return &secp256k1pb.Secp256K1Params{
		HashType: hashType,
		Curve:    curve,
		Encoding: encoding,
	}
}

// newSecp256K1KeyFormat creates a ECDSAKeyFormat with the specified parameters.
func newSecp256K1KeyFormat(params *secp256k1pb.Secp256K1Params) *secp256k1pb.Secp256K1KeyFormat {
	return &secp256k1pb.Secp256K1KeyFormat{Params: params}
}

// newSecp256K1APrivateKey creates a ECDSAPrivateKey with the specified parameters.
func newSecp256K1APrivateKey(version uint32, publicKey *secp256k1pb.Secp256K1PublicKey,
	keyValue []byte) *secp256k1pb.Secp256K1PrivateKey {
	return &secp256k1pb.Secp256K1PrivateKey{
		Version:   version,
		PublicKey: publicKey,
		KeyValue:  keyValue,
	}
}

// newSecp256K1PublicKey creates a ECDSAPublicKey with the specified parameters.
func newSecp256K1PublicKey(version uint32, params *secp256k1pb.Secp256K1Params,
	x []byte, y []byte) *secp256k1pb.Secp256K1PublicKey {
	return &secp256k1pb.Secp256K1PublicKey{
		Version: version,
		Params:  params,
		X:       x,
		Y:       y,
	}
}

// getSecp256K1ParamNames returns the string representations of each parameter in
// the given Secp256K1Params.
func getSecp256K1ParamNames(params *secp256k1pb.Secp256K1Params) (string, string, string) {
	hashName := commonpb.HashType_name[int32(params.HashType)]
	curveName := secp256k1pb.BitcoinCurveType_name[int32(params.Curve)]
	encodingName := secp256k1pb.Secp256K1SignatureEncoding_name[int32(params.Encoding)]

	return hashName, curveName, encodingName
}
