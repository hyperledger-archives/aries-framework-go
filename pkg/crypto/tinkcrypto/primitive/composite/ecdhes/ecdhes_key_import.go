/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdhes

import (
	"encoding/json"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"

	ecdhessubtle "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdhes/subtle"
	ecdhespb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdhes_aead_go_proto"
)

// publicKeyBytesToHandle for reading pubKey and get keyset.Handle of kt key type
func publicKeyBytesToHandle(pubKey []byte) (*keyset.Handle, error) {
	if len(pubKey) == 0 {
		return nil, fmt.Errorf("pubKey is empty")
	}

	marshalledKey, tURL, err := getMarshalledProtoKeyAndKeyURL(pubKey)
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
				KeyData:          keyData,
				Status:           tinkpb.KeyStatusType_ENABLED,
				KeyId:            1,
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

func getMarshalledProtoKeyAndKeyURL(pubKey []byte) ([]byte, string, error) {
	var (
		tURL     string
		keyValue []byte
		err      error
	)

	tURL = ecdhesPublicKeyTypeURL

	keyValue, err = getMarshalledECDHESKey(pubKey)
	if err != nil {
		return nil, "", err
	}

	return keyValue, tURL, nil
}

func getMarshalledECDHESKey(pubKey []byte) ([]byte, error) {
	ecPubKey := new(ecdhessubtle.ECPublicKey)

	err := json.Unmarshal(pubKey, ecPubKey)
	if err != nil {
		return nil, err
	}

	switch ecPubKey.Curve {
	case "secp256r1", "NIST_P256", "P-256", "EllipticCurveType_NIST_P256":
	default:
		return nil, fmt.Errorf("ECDHES supports keys with NIST_P256 EC curve only")
	}

	if ecPubKey.X == nil || ecPubKey.Y == nil {
		return nil, fmt.Errorf("invalid key")
	}

	curveType, err := GetCurveType(ecPubKey.Curve)
	if err != nil {
		return nil, fmt.Errorf("undefined curve type %w", err)
	}

	aeadEnc := aead.AES256GCMKeyTemplate()
	pubKeyProto := new(ecdhespb.EcdhesAeadPublicKey)

	pubKeyProto.X = ecPubKey.X
	pubKeyProto.Y = ecPubKey.Y
	pubKeyProto.Version = 0
	pubKeyProto.Params = &ecdhespb.EcdhesAeadParams{
		EncParams: &ecdhespb.EcdhesAeadEncParams{
			AeadEnc: aeadEnc,
		},
		KwParams: &ecdhespb.EcdhesKwParams{
			CurveType: curveType,
		},
		EcPointFormat: commonpb.EcPointFormat_UNCOMPRESSED,
	}

	return proto.Marshal(pubKeyProto)
}
