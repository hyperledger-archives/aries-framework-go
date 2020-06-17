/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdh1pu

import (
	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	compositepb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/common_composite_go_proto"
	ecdh1pupb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdh1pu_aead_go_proto"
)

// ECDH1PU256KWAES256GCMKeyTemplate is a KeyTemplate that generates an ECDH-1PU P-256 key wrapping and AES256-GCM CEK.
// It is used to represent a recipient key to execute the CompositeDecrypt primitive with the following parameters:
//  - Key Wrapping: ECDH-1PU over A256KW as per https://tools.ietf.org/html/draft-madden-jose-ecdh-1pu-03#section-2
//  - Content Encryption: AES256-GCM
//  - KDF: One-Step KDF as per https://tools.ietf.org/html/draft-madden-jose-ecdh-1pu-03#section-2.2
// Keys from this template represent a valid recipient public/private key pairs and can be stored in the KMS
func ECDH1PU256KWAES256GCMKeyTemplate() *tinkpb.KeyTemplate {
	return createKeyTemplate(commonpb.EllipticCurveType_NIST_P256, nil)
}

// ECDH1PU384KWAES256GCMKeyTemplate is a KeyTemplate that generates an ECDH-1PU P-384 key wrapping and AES256-GCM CEK.
// It is used to represent a recipient key to execute the CompositeDecrypt primitive with the following parameters:
//  - Key Wrapping: ECDH-1PU over A384KW as per https://tools.ietf.org/html/draft-madden-jose-ecdh-1pu-03#section-2
//  - Content Encryption: AES256-GCM
//  - KDF: One-Step KDF as per https://tools.ietf.org/html/draft-madden-jose-ecdh-1pu-03#section-2.2
// Keys from this template represent a valid recipient public/private key pairs and can be stored in the KMS
func ECDH1PU384KWAES256GCMKeyTemplate() *tinkpb.KeyTemplate {
	return createKeyTemplate(commonpb.EllipticCurveType_NIST_P384, nil)
}

// ECDH1PU521KWAES256GCMKeyTemplate is a KeyTemplate that generates an ECDH-1PU P-521 key wrapping and AES256-GCM CEK.
// It is used to represent a recipient key to execute the CompositeDecrypt primitive with the following parameters:
//  - Key Wrapping: ECDH-1PU over A521KW as per https://tools.ietf.org/html/draft-madden-jose-ecdh-1pu-03#section-2
//  - Content Encryption: AES256-GCM
//  - KDF: One-Step KDF as per https://tools.ietf.org/html/draft-madden-jose-ecdh-1pu-03#section-2.2
// Keys from this template represent a valid recipient public/private key pairs and can be stored in the KMS
func ECDH1PU521KWAES256GCMKeyTemplate() *tinkpb.KeyTemplate {
	return createKeyTemplate(commonpb.EllipticCurveType_NIST_P521, nil)
}

// ECDH1PU256KWAES256GCMKeyTemplateWithRecipients is similar to ECDH1PU256KWAES256GCMKeyTemplate but adding recipients
// keys to execute the CompositeEncrypt primitive for encrypting a message targeted to one ore more recipients.
// Keys from this template offer valid CompositeEncrypt primitive execution only and should not be stored in the KMS
func ECDH1PU256KWAES256GCMKeyTemplateWithRecipients(recPublicKeys []composite.PublicKey) (*tinkpb.KeyTemplate, error) {
	ecdhesRecipientKeys, err := createECDH1PUPublicKeys(recPublicKeys)
	if err != nil {
		return nil, err
	}

	return createKeyTemplate(commonpb.EllipticCurveType_NIST_P256, ecdhesRecipientKeys), nil
}

// ECDH1PU384KWAES256GCMKeyTemplateWithRecipients is similar to ECDH1PU384KWAES256GCMKeyTemplate but adding recipients
// keys to execute the CompositeEncrypt primitive for encrypting a message targeted to one ore more recipients.
// Keys from this template offer valid CompositeEncrypt primitive execution only and should not be stored in the KMS
func ECDH1PU384KWAES256GCMKeyTemplateWithRecipients(recPublicKeys []composite.PublicKey) (*tinkpb.KeyTemplate, error) {
	ecdhesRecipientKeys, err := createECDH1PUPublicKeys(recPublicKeys)
	if err != nil {
		return nil, err
	}

	return createKeyTemplate(commonpb.EllipticCurveType_NIST_P384, ecdhesRecipientKeys), nil
}

// ECDH1PU521KWAES256GCMKeyTemplateWithRecipients is similar to ECDH1PU521KWAES256GCMKeyTemplate but adding recipients
// keys to execute the CompositeEncrypt primitive for encrypting a message targeted to one ore more recipients.
// Keys from this template offer valid CompositeEncrypt primitive execution only and should not be stored in the KMS
func ECDH1PU521KWAES256GCMKeyTemplateWithRecipients(recPublicKeys []composite.PublicKey) (*tinkpb.KeyTemplate, error) {
	ecdhesRecipientKeys, err := createECDH1PUPublicKeys(recPublicKeys)
	if err != nil {
		return nil, err
	}

	return createKeyTemplate(commonpb.EllipticCurveType_NIST_P521, ecdhesRecipientKeys), nil
}

func createECDH1PUPublicKeys(rRawPublicKeys []composite.PublicKey) ([]*ecdh1pupb.Ecdh1PuAeadRecipientPublicKey, error) {
	var recKeys []*ecdh1pupb.Ecdh1PuAeadRecipientPublicKey

	for _, key := range rRawPublicKeys {
		curveType, err := composite.GetCurveType(key.Curve)
		if err != nil {
			return nil, err
		}

		keyType, err := composite.GetKeyType(key.Type)
		if err != nil {
			return nil, err
		}

		rKey := &ecdh1pupb.Ecdh1PuAeadRecipientPublicKey{
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

// createKeyTemplate creates a new ECDH1PU-AEAD key template with the given key
// size in bytes.
func createKeyTemplate(c commonpb.EllipticCurveType, r []*ecdh1pupb.Ecdh1PuAeadRecipientPublicKey) *tinkpb.KeyTemplate {
	format := &ecdh1pupb.Ecdh1PuAeadKeyFormat{
		Params: &ecdh1pupb.Ecdh1PuAeadParams{
			KwParams: &ecdh1pupb.Ecdh1PuKwParams{
				CurveType:  c,
				KeyType:    compositepb.KeyType_EC,
				Recipients: r,
			},
			EncParams: &ecdh1pupb.Ecdh1PuAeadEncParams{
				AeadEnc: aead.AES256GCMKeyTemplate(),
			},
			EcPointFormat: commonpb.EcPointFormat_UNCOMPRESSED,
		},
	}

	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		panic("failed to marshal Ecdh1PuAeadKeyFormat proto")
	}

	return &tinkpb.KeyTemplate{
		TypeUrl:          ecdh1puAESPrivateKeyTypeURL,
		Value:            serializedFormat,
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
	}
}
