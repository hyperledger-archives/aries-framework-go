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

	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

func publicKeyBytesToHandle(pubKey []byte, kt kms.KeyType) (*keyset.Handle, error) {
	if len(pubKey) == 0 {
		return nil, fmt.Errorf("pubKey is empty")
	}

	marshalledKey, tURL, err := getMarshalledProtoKeyAndKeyURL(pubKey, kt)
	if err != nil {
		return nil, fmt.Errorf("error getting marshalled proto key: %w", err)
	}

	keyData := &tinkpb.KeyData{
		TypeUrl:         tURL,
		Value:           marshalledKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}

	ks := &tinkpb.Keyset{
		Key: []*tinkpb.Keyset_Key{
			{
				KeyData: keyData,
				Status:  tinkpb.KeyStatusType_ENABLED,
				KeyId:   1,
				// since we're building the key from raw key bytes, then must use raw key prefix type
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			}},
		PrimaryKeyId: 1,
	}

	memReader := &keyset.MemReaderWriter{Keyset: ks}

	parsedHandle, err := insecurecleartextkeyset.Read(memReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create key handle: %w", err)
	}

	return parsedHandle, nil
}

func getMarshalledProtoKeyAndKeyURL(pubKey []byte, kt kms.KeyType) ([]byte, string, error) { //nolint:funlen,gocyclo
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
			commonpb.HashType_SHA512)
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
	case kms.ECDSAP256TypeIEEE1363:
		tURL = ecdsaVerifierTypeURL

		keyValue, err = getMarshalledECDSAIEEE1363Key(
			pubKey,
			"NIST_P256",
			commonpb.EllipticCurveType_NIST_P256,
			commonpb.HashType_SHA256)
		if err != nil {
			return nil, "", err
		}
	case kms.ECDSAP384TypeIEEE1363:
		tURL = ecdsaVerifierTypeURL

		keyValue, err = getMarshalledECDSAIEEE1363Key(
			pubKey,
			"NIST_P384",
			commonpb.EllipticCurveType_NIST_P384,
			commonpb.HashType_SHA512)
		if err != nil {
			return nil, "", err
		}
	case kms.ECDSAP521TypeIEEE1363:
		tURL = ecdsaVerifierTypeURL

		keyValue, err = getMarshalledECDSAIEEE1363Key(
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

	return getMarshalledECDSAKey(ecPubKey, c, h, ecdsapb.EcdsaSignatureEncoding_DER)
}

func getMarshalledECDSAIEEE1363Key(marshaledPubKey []byte, curveName string, c commonpb.EllipticCurveType,
	h commonpb.HashType) ([]byte, error) {
	curve := subtle.GetCurve(curveName)
	if curve == nil {
		return nil, fmt.Errorf("undefined curve")
	}

	x, y := elliptic.Unmarshal(curve, marshaledPubKey)

	if x == nil || y == nil {
		return nil, fmt.Errorf("failed to unamrshal public ecdsa key")
	}

	return getMarshalledECDSAKey(&ecdsa.PublicKey{X: x, Y: y, Curve: curve}, c, h,
		ecdsapb.EcdsaSignatureEncoding_IEEE_P1363)
}

func getMarshalledECDSAKey(ecPubKey *ecdsa.PublicKey, c commonpb.EllipticCurveType,
	h commonpb.HashType, enc ecdsapb.EcdsaSignatureEncoding) ([]byte, error) {
	pubKeyProto := new(ecdsapb.EcdsaPublicKey)

	pubKeyProto.X = ecPubKey.X.Bytes()
	pubKeyProto.Y = ecPubKey.Y.Bytes()
	pubKeyProto.Version = 0
	pubKeyProto.Params = &ecdsapb.EcdsaParams{
		Curve:    c,
		Encoding: enc,
		HashType: h,
	}

	return proto.Marshal(pubKeyProto)
}
