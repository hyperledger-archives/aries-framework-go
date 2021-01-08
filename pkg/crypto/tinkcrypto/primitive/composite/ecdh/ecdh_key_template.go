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

// ECDH256KWAES256GCMKeyTemplate is a KeyTemplate that generates a key that accepts a CEK for AES256-GCM content
// encryption. CEK wrapping is done outside of this Tink key (in the tinkcrypto service). It is used to represent a key
// to execute the CompositeDecrypt primitive with the following parameters:
//  - Content Encryption: AES256-GCM
// Keys from this template represent a valid recipient public/private key pairs and can be stored in the KMS. The
// recipient key represented in this key template uses the following key wrapping curve:
//  - NIST curve P-256.
func ECDH256KWAES256GCMKeyTemplate() *tinkpb.KeyTemplate {
	return createKeyTemplate(true, true, commonpb.EllipticCurveType_NIST_P256, nil)
}

// ECDH384KWAES256GCMKeyTemplate is a KeyTemplate that generates a key that accepts a CEK for AES256-GCM content
// encryption. CEK wrapping is done outside of this Tink key (in the tinkcrypto service). It is used to represent a key
// to execute the CompositeDecrypt primitive with the following parameters:
//  - Content Encryption: AES256-GCM
// Keys from this template represent a valid recipient public/private key pairs and can be stored in the KMS. The
// recipient key represented in this key template uses the following key wrapping curve:
//  - NIST curve P-384
func ECDH384KWAES256GCMKeyTemplate() *tinkpb.KeyTemplate {
	return createKeyTemplate(true, true, commonpb.EllipticCurveType_NIST_P384, nil)
}

// ECDH521KWAES256GCMKeyTemplate is a KeyTemplate that generates a key that accepts a CEK for AES256-GCM content
// encryption. CEK wrapping is done outside of this Tink key (in the tinkcrypto service). It is used to represent a key
// to execute the CompositeDecrypt primitive with the following parameters:
//  - Content Encryption: AES256-GCM
// Keys from this template represent a valid recipient public/private key pairs and can be stored in the KMS. The
// recipient key represented in this key template uses the following key wrapping curve:
//  - NIST curve P-521
func ECDH521KWAES256GCMKeyTemplate() *tinkpb.KeyTemplate {
	return createKeyTemplate(true, true, commonpb.EllipticCurveType_NIST_P521, nil)
}

// ECDH256KWXChachaKeyTemplate is a KeyTemplate that generates a key that accepts a CEK for XChacha20Poly1305 content
// encryption. CEK wrapping is done outside of this Tink key (in the tinkcrypto service). It is used to represent
// a key to execute the CompositeDecrypt primitive with the following parameters:
//  - Content Encryption: XChacha20Poly1305
// Keys from this template represent a valid recipient public/private key pairs and can be stored in the KMS. The
// recipient key represented in this key template uses the following key wrapping curve:
//  - NIST curve P-256.
func ECDH256KWXChachaKeyTemplate() *tinkpb.KeyTemplate {
	return createKeyTemplate(true, false, commonpb.EllipticCurveType_NIST_P256, nil)
}

// ECDH384KWXChachaKeyTemplate is a KeyTemplate that generates a key that accepts a CEK for XChacha20Poly1305 content
// encryption. CEK wrapping is done outside of this Tink key (in the tinkcrypto service). It is used to represent
// a key to execute the CompositeDecrypt primitive with the following parameters:
//  - Content Encryption: XChacha20Poly1305
// Keys from this template represent a valid recipient public/private key pairs and can be stored in the KMS. The
// recipient key represented in this key template uses the following key wrapping curve:
//  - NIST curve P-384
func ECDH384KWXChachaKeyTemplate() *tinkpb.KeyTemplate {
	return createKeyTemplate(true, false, commonpb.EllipticCurveType_NIST_P384, nil)
}

// ECDH521KWXChachaKeyTemplate is a KeyTemplate that generates a key that accepts a CEK for XChacha20Poly1305 content
// encryption. CEK wrapping is done outside of this Tink key (in the tinkcrypto service). It is used to represent
// a key to execute the CompositeDecrypt primitive with the following parameters:
//  - Content Encryption: XChacha20Poly1305
// Keys from this template represent a valid recipient public/private key pairs and can be stored in the KMS. The
// recipient key represented in this key template uses the following key wrapping curve:
//  - NIST curve P-521
func ECDH521KWXChachaKeyTemplate() *tinkpb.KeyTemplate {
	return createKeyTemplate(true, false, commonpb.EllipticCurveType_NIST_P521, nil)
}

// X25519XChachaECDHKeyTemplate is a KeyTemplate that generates a key that accepts a CEK for XChacha20Poly1305 content
// encryption. CEK wrapping is done outside of this Tink key (in the tinkcrypto service). It is used to represent a key
// to execute the CompositeDecrypt primitive with the following parameters:
//  - Content Encryption: XChaha20Poly1305
// Keys from this template represent a valid recipient public/private key pairs and can be stored in the KMS.The
// recipient key represented in this key template uses the following key wrapping curve:
//  - Curve25519
func X25519XChachaECDHKeyTemplate() *tinkpb.KeyTemplate {
	return createKeyTemplate(false, false, commonpb.EllipticCurveType_CURVE25519, nil)
}

// X25519AES256GCMECDHKeyTemplate is a KeyTemplate that generates a key that accepts a CEK for AES256-GCM content
// encryption. CEK wrapping is done outside of this Tink key (in the tinkcrypto service). It is used to represent a key
// to execute the CompositeDecrypt primitive with the following parameters:
//  - Content Encryption: AES256-GCM
// Keys from this template represent a valid recipient public/private key pairs and can be stored in the KMS.The
// recipient key represented in this key template uses the following key wrapping curve:
//  - Curve25519
func X25519AES256GCMECDHKeyTemplate() *tinkpb.KeyTemplate {
	return createKeyTemplate(false, true, commonpb.EllipticCurveType_CURVE25519, nil)
}

// AES256GCMKeyTemplateWithCEK is similar to ECDH256KWAES256GCMKeyTemplate but adding the cek to execute the
// CompositeEncrypt primitive for encrypting a message targeted to one ore more recipients. KW is not executed by this
// template, so it is ignored and set to NIST P Curved key by default.
// Keys from this template offer valid CompositeEncrypt primitive execution only and should not be stored in the KMS.
// The key created from this template has no recipient key info linked to it. It is exclusively used for primitive
// execution.
func AES256GCMKeyTemplateWithCEK(cek []byte) *tinkpb.KeyTemplate {
	// the curve passed in the template below is ignored when executing the primitive, it's hardcoded to pass key
	// key format validation only.
	return createKeyTemplate(true, true, 0, cek)
}

// XChachaKeyTemplateWithCEK is similar to X25519XChachaECDHKeyTemplate but adding the cek to execute the
// CompositeEncrypt primitive for encrypting a message targeted to one ore more recipients.
// Keys from this template offer valid CompositeEncrypt primitive execution only and should not be stored in the KMS.
// The key created from this template has no recipient key info linked to it. It is exclusively used for primitive
// execution.
func XChachaKeyTemplateWithCEK(cek []byte) *tinkpb.KeyTemplate {
	return createKeyTemplate(false, false, 0, cek)
}

// createKeyTemplate creates a new ECDH-AEAD key template with the set cek for primitive execution. Boolean flags used:
//  - nistpKW flag to state if kw is either NIST P curves (true) or Curve25519 (false)
//  - aesEnc flag to state if content encryption is either AES256-GCM (true) or XChacha20Poly1305 (false)
func createKeyTemplate(nistpKW, aesEnc bool, c commonpb.EllipticCurveType, cek []byte) *tinkpb.KeyTemplate {
	var encTemplate *tinkpb.KeyTemplate

	typeURL, keyType := getTypeParams(nistpKW, aesEnc)

	if aesEnc {
		encTemplate = aead.AES256GCMKeyTemplate()
	} else {
		encTemplate = aead.XChaCha20Poly1305KeyTemplate()
	}

	format := &ecdhpb.EcdhAeadKeyFormat{
		Params: &ecdhpb.EcdhAeadParams{
			KwParams: &ecdhpb.EcdhKwParams{
				CurveType: c,
				KeyType:   keyType,
			},
			EncParams: &ecdhpb.EcdhAeadEncParams{
				AeadEnc: encTemplate,
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
		TypeUrl:          typeURL,
		Value:            serializedFormat,
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
	}
}

func getTypeParams(nispKW, aesEnc bool) (string, ecdhpb.KeyType) {
	if nispKW {
		if aesEnc {
			return ecdhNISTPAESPrivateKeyTypeURL, ecdhpb.KeyType_EC
		}

		return ecdhNISTPXChachaPrivateKeyTypeURL, ecdhpb.KeyType_EC
	}

	if aesEnc {
		return ecdhX25519AESPrivateKeyTypeURL, ecdhpb.KeyType_OKP
	}

	return ecdhX25519XChachaPrivateKeyTypeURL, ecdhpb.KeyType_OKP
}
