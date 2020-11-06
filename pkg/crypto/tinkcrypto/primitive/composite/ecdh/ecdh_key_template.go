/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdh

import (
	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"

	ecdhpb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
)

// ECDH256KWAES256GCMKeyTemplate is a KeyTemplate that generates a key that accepts a CEK for AES256-GCM encryption. CEK
// wrapping is done outside of this Tink key (in the tinkcrypto service). It
// is used to represent a key to execute the CompositeDecrypt primitive with the following parameters:
//  - Content Encryption: AES256-GCM
// Keys from this template represent a valid recipient public/private key pairs and can be stored in the KMS. The
// recipient key represented in this key template uses NIST curve P-256.
func ECDH256KWAES256GCMKeyTemplate() *tinkpb.KeyTemplate {
	return createKeyTemplate(commonpb.EllipticCurveType_NIST_P256, nil)
}

// ECDH384KWAES256GCMKeyTemplate is a KeyTemplate that generates a key that accepts a CEK for AES256-GCM encryption. CEK
// wrapping is done outside of this Tink key (in the tinkcrypto service). It
// is used to represent a key to execute the CompositeDecrypt primitive with the following parameters:
//  - Content Encryption: AES256-GCM
// Keys from this template represent a valid recipient public/private key pairs and can be stored in the KMS. The
// recipient key represented in this key template uses NIST curve P-384.
func ECDH384KWAES256GCMKeyTemplate() *tinkpb.KeyTemplate {
	return createKeyTemplate(commonpb.EllipticCurveType_NIST_P384, nil)
}

// ECDH521KWAES256GCMKeyTemplate is a KeyTemplate that generates a key that accepts a CEK for AES256-GCM encryption. CEK
// wrapping is done outside of this Tink key (in the tinkcrypto service). It
// is used to represent a key to execute the CompositeDecrypt primitive with the following parameters:
//  - Content Encryption: AES256-GCM
// Keys from this template represent a valid recipient public/private key pairs and can be stored in the KMS. The
// recipient key represented in this key template uses NIST curve P-521.
func ECDH521KWAES256GCMKeyTemplate() *tinkpb.KeyTemplate {
	return createKeyTemplate(commonpb.EllipticCurveType_NIST_P521, nil)
}

// AES256GCMKeyTemplateWithCEK is similar to ECDHAES256GCMKeyTemplate but adding the cek to execute the
// CompositeEncrypt primitive for encrypting a message targeted to one ore more recipients.
// Keys from this template offer valid CompositeEncrypt primitive execution only and should not be stored in the KMS.
// The key created from this template has no recipient key info linked to it. It is use exclusively used for primitive
// execution.
func AES256GCMKeyTemplateWithCEK(cek []byte) *tinkpb.KeyTemplate {
	// the curve passed in the template below is ignored when executing the primitive, it's hardcoded to pass key
	// key format validation only.
	return createKeyTemplate(0, cek)
}

// TODO add chacha key templates as well https://github.com/hyperledger/aries-framework-go/issues/1637

// createKeyTemplate creates a new ECDH-AEAD key template with the set cek for primitive execution.
func createKeyTemplate(c commonpb.EllipticCurveType, cek []byte) *tinkpb.KeyTemplate {
	format := &ecdhpb.EcdhAeadKeyFormat{
		Params: &ecdhpb.EcdhAeadParams{
			KwParams: &ecdhpb.EcdhKwParams{
				CurveType: c,
				KeyType:   ecdhpb.KeyType_EC,
			},
			EncParams: &ecdhpb.EcdhAeadEncParams{
				AeadEnc: aead.AES256GCMKeyTemplate(),
				CEK:     cek,
			},
			EcPointFormat: commonpb.EcPointFormat_UNCOMPRESSED,
		},
	}

	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		panic("failed to marshal EcdhAeadKeyFormat proto")
	}

	return &tinkpb.KeyTemplate{
		TypeUrl:          ecdhAESPrivateKeyTypeURL,
		Value:            serializedFormat,
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
	}
}
