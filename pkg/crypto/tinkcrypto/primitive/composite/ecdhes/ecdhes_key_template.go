/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdhes

import (
	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	compositepb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/common_composite_go_proto"
	ecdhespb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdhes_aead_go_proto"
)

// ECDHES256KWAES256GCMKeyTemplate is a KeyTemplate that generates an ECDH-ES P-256 key wrapping and AES256-GCM CEK. It
// is used to represent a recipient key to execute the CompositeDecrypt primitive with the following parameters:
//  - Key Wrapping: ECDH-ES over A256KW as per https://tools.ietf.org/html/rfc7518#appendix-A.2
//  - Content Encryption: AES256-GCM
//  - KDF: Concat KDF as per https://tools.ietf.org/html/rfc7518#section-4.6
// Keys from this template represent a valid recipient public/private key pairs and can be stored in the KMS
func ECDHES256KWAES256GCMKeyTemplate() *tinkpb.KeyTemplate {
	return createKeyTemplate(commonpb.EllipticCurveType_NIST_P256, commonpb.EcPointFormat_UNCOMPRESSED,
		aead.AES256GCMKeyTemplate(), tinkpb.OutputPrefixType_RAW, nil, compositepb.KeyType_EC)
}

// ECDHES256KWAES256GCMKeyTemplateWithRecipients is similar to ECDHES256KWAES256GCMKeyTemplate but adding recipients
// keys to execute the CompositeEncrypt primitive for encrypting a message targeted to one ore more recipients.
// Keys from this template offer valid CompositeEncrypt primitive execution only and should not be stored in the KMS
func ECDHES256KWAES256GCMKeyTemplateWithRecipients(recPublicKeys []composite.PublicKey) (*tinkpb.KeyTemplate, error) {
	ecdhesRecipientKeys, err := createECDHESPublicKeys(recPublicKeys)
	if err != nil {
		return nil, err
	}

	return createKeyTemplate(commonpb.EllipticCurveType_NIST_P256, commonpb.EcPointFormat_UNCOMPRESSED,
		aead.AES256GCMKeyTemplate(), tinkpb.OutputPrefixType_RAW, ecdhesRecipientKeys, compositepb.KeyType_EC), nil
}

func createECDHESPublicKeys(recRawPublicKeys []composite.PublicKey) ([]*ecdhespb.EcdhesAeadRecipientPublicKey, error) {
	var recKeys []*ecdhespb.EcdhesAeadRecipientPublicKey

	for _, key := range recRawPublicKeys {
		curveType, err := composite.GetCurveType(key.Curve)
		if err != nil {
			return nil, err
		}

		keyType, err := composite.GetKeyType(key.Type)
		if err != nil {
			return nil, err
		}

		rKey := &ecdhespb.EcdhesAeadRecipientPublicKey{
			Version:   0,
			KID:       key.KID,
			CurveType: curveType,
			X:         key.X,
			Y:         key.Y,
			KeyType:   keyType,
		}

		recKeys = append(recKeys, rKey)
	}

	return recKeys, nil
}

// TODO add chacha key templates as well https://github.com/hyperledger/aries-framework-go/issues/1637

// createKeyTemplate creates a new ECDHES-AEAD key template with the given key
// size in bytes.
func createKeyTemplate(c commonpb.EllipticCurveType, epf commonpb.EcPointFormat, contentEncKeyT *tinkpb.KeyTemplate,
	prefixType tinkpb.OutputPrefixType, recipients []*ecdhespb.EcdhesAeadRecipientPublicKey,
	keyType compositepb.KeyType) *tinkpb.KeyTemplate {
	format := &ecdhespb.EcdhesAeadKeyFormat{
		Params: &ecdhespb.EcdhesAeadParams{
			KwParams: &ecdhespb.EcdhesKwParams{
				CurveType:  c,
				KeyType:    keyType,
				Recipients: recipients,
			},
			EncParams: &ecdhespb.EcdhesAeadEncParams{
				AeadEnc: contentEncKeyT,
			},
			EcPointFormat: epf,
		},
	}

	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		panic("failed to marshal EcdhesAeadKeyFormat proto")
	}

	return &tinkpb.KeyTemplate{
		TypeUrl:          ecdhesAESPrivateKeyTypeURL,
		Value:            serializedFormat,
		OutputPrefixType: prefixType,
	}
}
