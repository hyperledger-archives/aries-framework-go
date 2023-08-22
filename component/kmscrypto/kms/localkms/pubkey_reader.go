/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	ecdsapb "github.com/google/tink/go/proto/ecdsa_go_proto"
	ed25519pb "github.com/google/tink/go/proto/ed25519_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/subtle"

	"github.com/hyperledger/aries-framework-go/spi/kms"

	bbspb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/bbs_go_proto"
	clpb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/cl_go_proto"
	secp256k1pb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/secp256k1_go_proto"
	secp256k1subtle "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/secp256k1/subtle"
)

// PublicKeyBytesToHandle will create and return a key handle for pubKey of type kt
// it returns an error if it failed creating the key handle
// Note: The key handle created is not stored in the KMS, it's only useful to execute the crypto primitive
// associated with it.
func PublicKeyBytesToHandle(pubKey []byte, kt kms.KeyType, opts ...kms.KeyOpts) (*keyset.Handle, error) {
	if len(pubKey) == 0 {
		return nil, fmt.Errorf("pubKey is empty")
	}

	marshalledKey, tURL, err := getMarshalledProtoKeyAndKeyURL(pubKey, kt, opts...)
	if err != nil {
		return nil, fmt.Errorf("error getting marshalled proto key: %w", err)
	}

	ks := newKeySet(tURL, marshalledKey, tinkpb.KeyData_ASYMMETRIC_PUBLIC)

	memReader := &keyset.MemReaderWriter{Keyset: ks}

	parsedHandle, err := insecurecleartextkeyset.Read(memReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create key handle: %w", err)
	}

	return parsedHandle, nil
}

func newKeySet(tURL string, marshalledKey []byte, keyMaterialType tinkpb.KeyData_KeyMaterialType) *tinkpb.Keyset {
	keyData := &tinkpb.KeyData{
		TypeUrl:         tURL,
		Value:           marshalledKey,
		KeyMaterialType: keyMaterialType,
	}

	return &tinkpb.Keyset{
		Key: []*tinkpb.Keyset_Key{
			{
				KeyData: keyData,
				Status:  tinkpb.KeyStatusType_ENABLED,
				KeyId:   1,
				// since we're building the key from raw key bytes, then must use raw key prefix type
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
		PrimaryKeyId: 1,
	}
}

//nolint:funlen,gocyclo
func getMarshalledProtoKeyAndKeyURL(pubKey []byte, kt kms.KeyType,
	opts ...kms.KeyOpts) ([]byte, string, error) {
	var (
		tURL     string
		keyValue []byte
		err      error
	)

	switch kt {
	case kms.ECDSAP256TypeDER:
		tURL = ecdsaVerifierTypeURL

		keyValue, err = getMarshalledECDSADERKey(
			pubKey,
			"NIST_P256",
			commonpb.EllipticCurveType_NIST_P256,
			commonpb.HashType_SHA256)
		if err != nil {
			return nil, "", err
		}
	case kms.ECDSAP384TypeDER:
		tURL = ecdsaVerifierTypeURL

		keyValue, err = getMarshalledECDSADERKey(
			pubKey,
			"NIST_P384",
			commonpb.EllipticCurveType_NIST_P384,
			commonpb.HashType_SHA384)
		if err != nil {
			return nil, "", err
		}
	case kms.ECDSAP521TypeDER:
		tURL = ecdsaVerifierTypeURL

		keyValue, err = getMarshalledECDSADERKey(
			pubKey,
			"NIST_P521",
			commonpb.EllipticCurveType_NIST_P521,
			commonpb.HashType_SHA512)
		if err != nil {
			return nil, "", err
		}
	case kms.ECDSAP256TypeIEEEP1363:
		tURL = ecdsaVerifierTypeURL

		keyValue, err = getMarshalledECDSAIEEEP1363Key(
			pubKey,
			"NIST_P256",
			commonpb.EllipticCurveType_NIST_P256,
			commonpb.HashType_SHA256)
		if err != nil {
			return nil, "", err
		}
	case kms.ECDSAP384TypeIEEEP1363:
		tURL = ecdsaVerifierTypeURL

		keyValue, err = getMarshalledECDSAIEEEP1363Key(
			pubKey,
			"NIST_P384",
			commonpb.EllipticCurveType_NIST_P384,
			commonpb.HashType_SHA384)
		if err != nil {
			return nil, "", err
		}
	case kms.ECDSAP521TypeIEEEP1363:
		tURL = ecdsaVerifierTypeURL

		keyValue, err = getMarshalledECDSAIEEEP1363Key(
			pubKey,
			"NIST_P521",
			commonpb.EllipticCurveType_NIST_P521,
			commonpb.HashType_SHA512)
		if err != nil {
			return nil, "", err
		}
	case kms.ED25519Type:
		tURL = ed25519VerifierTypeURL
		pubKeyProto := new(ed25519pb.Ed25519PublicKey)
		pubKeyProto.Version = 0
		pubKeyProto.KeyValue = make([]byte, len(pubKey))
		copy(pubKeyProto.KeyValue, pubKey)

		keyValue, err = proto.Marshal(pubKeyProto)
		if err != nil {
			return nil, "", err
		}
	case kms.BLS12381G2Type:
		tURL = bbsVerifierKeyTypeURL
		pubKeyProto := new(bbspb.BBSPublicKey)
		pubKeyProto.Version = 0
		pubKeyProto.Params = buidBBSParams(kt)
		pubKeyProto.KeyValue = make([]byte, len(pubKey))
		copy(pubKeyProto.KeyValue, pubKey)

		keyValue, err = proto.Marshal(pubKeyProto)
		if err != nil {
			return nil, "", err
		}
	case kms.CLCredDefType:
		tURL = clCredDefKeyTypeURL
		pubKeyProto := new(clpb.CLCredDefPublicKey)
		pubKeyProto.Version = 0
		pubKeyProto.Params = buidCLCredDefParams(kt, opts...)
		pubKeyProto.KeyValue = make([]byte, len(pubKey))
		copy(pubKeyProto.KeyValue, pubKey)

		keyValue, err = proto.Marshal(pubKeyProto)
		if err != nil {
			return nil, "", err
		}
	case kms.ECDSASecp256k1DER:
		tURL = secp256k1VerifierTypeURL

		keyValue, err = getMarshalledECDSASecp256K1DERKey(
			pubKey,
			"SECP256K1",
			secp256k1pb.BitcoinCurveType_SECP256K1,
			commonpb.HashType_SHA256)
		if err != nil {
			return nil, "", err
		}
	case kms.ECDSASecp256k1IEEEP1363:
		tURL = secp256k1VerifierTypeURL

		keyValue, err = getMarshalledECDSASecp256K1IEEEP1363Key(
			pubKey,
			"SECP256K1",
			secp256k1pb.BitcoinCurveType_SECP256K1,
			commonpb.HashType_SHA256)
		if err != nil {
			return nil, "", err
		}
	default:
		return nil, "", fmt.Errorf("invalid key type")
	}

	return keyValue, tURL, nil
}

func getMarshalledECDSADERKey(marshaledPubKey []byte, curveName string, c commonpb.EllipticCurveType,
	h commonpb.HashType) ([]byte, error) {
	curve := subtle.GetCurve(curveName)
	if curve == nil {
		return nil, fmt.Errorf("undefined curve")
	}

	pubKey, err := x509.ParsePKIXPublicKey(marshaledPubKey)
	if err != nil {
		return nil, err
	}

	ecPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key reader: not an ecdsa public key")
	}

	params := &ecdsapb.EcdsaParams{
		Curve:    c,
		Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
		HashType: h,
	}

	return getMarshalledECDSAKey(ecPubKey, params)
}

func getMarshalledECDSASecp256K1DERKey(marshaledPubKey []byte, curveName string, c secp256k1pb.BitcoinCurveType,
	h commonpb.HashType) ([]byte, error) {
	curve := secp256k1subtle.GetCurve(curveName)
	if curve == nil {
		return nil, fmt.Errorf("undefined curve")
	}

	pubKey, err := x509.ParsePKIXPublicKey(marshaledPubKey)
	if err != nil {
		return nil, err
	}

	ecPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key reader: not an ecdsa public key")
	}

	params := &secp256k1pb.Secp256K1Params{
		Curve:    c,
		Encoding: secp256k1pb.Secp256K1SignatureEncoding_Bitcoin_DER,
		HashType: h,
	}

	return getMarshalledSecp256Key(ecPubKey, params)
}

func getMarshalledECDSAIEEEP1363Key(marshaledPubKey []byte, curveName string, c commonpb.EllipticCurveType,
	h commonpb.HashType) ([]byte, error) {
	curve := subtle.GetCurve(curveName)
	if curve == nil {
		return nil, fmt.Errorf("undefined curve")
	}

	x, y := elliptic.Unmarshal(curve, marshaledPubKey)

	if x == nil || y == nil {
		return nil, fmt.Errorf("failed to unamrshal public ecdsa key")
	}

	params := &ecdsapb.EcdsaParams{
		Curve:    c,
		Encoding: ecdsapb.EcdsaSignatureEncoding_IEEE_P1363,
		HashType: h,
	}

	return getMarshalledECDSAKey(&ecdsa.PublicKey{X: x, Y: y, Curve: curve}, params)
}

func getMarshalledECDSASecp256K1IEEEP1363Key(marshaledPubKey []byte, curveName string, c secp256k1pb.BitcoinCurveType,
	h commonpb.HashType) ([]byte, error) {
	curve := secp256k1subtle.GetCurve(curveName)
	if curve == nil {
		return nil, fmt.Errorf("undefined curve")
	}

	x, y := elliptic.Unmarshal(curve, marshaledPubKey)

	if x == nil || y == nil {
		return nil, fmt.Errorf("failed to unamrshal public ecdsa key")
	}

	params := &secp256k1pb.Secp256K1Params{
		Curve:    c,
		Encoding: secp256k1pb.Secp256K1SignatureEncoding_Bitcoin_IEEE_P1363,
		HashType: h,
	}

	return getMarshalledSecp256Key(&ecdsa.PublicKey{X: x, Y: y, Curve: curve}, params)
}

func getMarshalledECDSAKey(ecPubKey *ecdsa.PublicKey, params *ecdsapb.EcdsaParams) ([]byte, error) {
	return proto.Marshal(newProtoECDSAPublicKey(ecPubKey, params))
}

func getMarshalledSecp256Key(ecPubKey *ecdsa.PublicKey, params *secp256k1pb.Secp256K1Params) ([]byte, error) {
	return proto.Marshal(newProtoSecp256K1PublicKey(ecPubKey, params))
}

func newProtoECDSAPublicKey(ecPubKey *ecdsa.PublicKey, params *ecdsapb.EcdsaParams) *ecdsapb.EcdsaPublicKey {
	return &ecdsapb.EcdsaPublicKey{
		Version: 0,
		X:       ecPubKey.X.Bytes(),
		Y:       ecPubKey.Y.Bytes(),
		Params:  params,
	}
}

func newProtoSecp256K1PublicKey(ecPubKey *ecdsa.PublicKey,
	params *secp256k1pb.Secp256K1Params) *secp256k1pb.Secp256K1PublicKey {
	return &secp256k1pb.Secp256K1PublicKey{
		Version: 0,
		X:       ecPubKey.X.Bytes(),
		Y:       ecPubKey.Y.Bytes(),
		Params:  params,
	}
}
