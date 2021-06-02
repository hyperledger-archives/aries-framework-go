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

	cbcaead "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/aead"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/aead/subtle"
	ecdhpb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
)

type aeadAlg int

const (
	aesGCM = iota
	xc20p
	aesCBC
)

// NISTP256ECDHKWKeyTemplate is a KeyTemplate that generates a key that accepts a CEK for JWE content
// encryption. CEK wrapping is done outside of this Tink key (in the tinkcrypto service).
// Keys from this template represent a valid recipient public/private key pairs and can be stored in the KMS. The
// recipient key represented in this key template uses the following key wrapping curve:
//  - NIST curve P-256.
// Keys created with this template are mainly used for key wrapping of a cek. They are independent of the AEAD content
// encryption algorithm.
func NISTP256ECDHKWKeyTemplate() *tinkpb.KeyTemplate {
	// aesGCM is set to pass key generation in the key manager, it's irrelevant to the key or its intended use.
	return createKeyTemplate(true, aesGCM, commonpb.EllipticCurveType_NIST_P256, nil)
}

// NISTP384ECDHKWKeyTemplate is a KeyTemplate that generates a key that accepts a CEK for JWE content
// encryption. CEK wrapping is done outside of this Tink key (in the tinkcrypto service).
// Keys from this template represent a valid recipient public/private key pairs and can be stored in the KMS. The
// recipient key represented in this key template uses the following key wrapping curve:
//  - NIST curve P-384
// Keys created with this template are mainly used for key wrapping of a cek. They are independent of the AEAD content
// encryption algorithm.
func NISTP384ECDHKWKeyTemplate() *tinkpb.KeyTemplate {
	// aesGCM is set to pass key generation in the key manager, it's irrelevant to the key or its intended use.
	return createKeyTemplate(true, aesGCM, commonpb.EllipticCurveType_NIST_P384, nil)
}

// NISTP521ECDHKWKeyTemplate is a KeyTemplate that generates a key that accepts a CEK for JWE content
// encryption. CEK wrapping is done outside of this Tink key (in the tinkcrypto service).
// Keys from this template represent a valid recipient public/private key pairs and can be stored in the KMS. The
// recipient key represented in this key template uses the following key wrapping curve:
//  - NIST curve P-521
// Keys created with this template are mainly used for key wrapping of a cek. They are independent of the AEAD content
// encryption algorithm.
func NISTP521ECDHKWKeyTemplate() *tinkpb.KeyTemplate {
	// aesGCM is set to pass key generation in the key manager, it's irrelevant to the key or its intended use.
	return createKeyTemplate(true, aesGCM, commonpb.EllipticCurveType_NIST_P521, nil)
}

// X25519ECDHKWKeyTemplate is a KeyTemplate that generates a key that accepts a CEK for JWE content
// encryption. CEK wrapping is done outside of this Tink key (in the tinkcrypto service).
// Keys from this template represent a valid recipient public/private key pairs and can be stored in the KMS.The
// recipient key represented in this key template uses the following key wrapping curve:
//  - Curve25519
// Keys created with this template are mainly used for key wrapping of a cek. They are independent of the AEAD content
// encryption algorithm.
func X25519ECDHKWKeyTemplate() *tinkpb.KeyTemplate {
	// xc20p is set to pass key generation in the key manager, it's irrelevant to the key or its intended use.
	return createKeyTemplate(false, xc20p, commonpb.EllipticCurveType_CURVE25519, nil)
}

// NISTPECDHAES256GCMKeyTemplateWithCEK is similar to NISTP256ECDHKWKeyTemplate but adding the cek to execute the
// CompositeEncrypt primitive for encrypting a message targeted to one ore more recipients. KW is not executed by this
// template, so it is ignored and set to NIST P Curved key by default.
// Keys from this template offer valid CompositeEncrypt primitive execution only and should not be stored in the KMS.
// The key created from this template has no recipient key info linked to it. It is exclusively used for primitive
// execution using content encryption algorithm:
//  - AES256-GCM
func NISTPECDHAES256GCMKeyTemplateWithCEK(cek []byte) *tinkpb.KeyTemplate {
	// the curve passed in the template below is ignored when executing the primitive, it's hardcoded to pass key
	// key format validation only.
	return createKeyTemplate(true, aesGCM, 0, cek)
}

// X25519ECDHXChachaKeyTemplateWithCEK is similar to X25519ECDHKWKeyTemplate but adding the cek to execute the
// CompositeEncrypt primitive for encrypting a message targeted to one ore more recipients.
// Keys from this template offer valid CompositeEncrypt primitive execution only and should not be stored in the KMS.
// The key created from this template has no recipient key info linked to it. It is exclusively used for primitive
// execution using content encryption algorithm:
//  - XChacha20Poly1305
func X25519ECDHXChachaKeyTemplateWithCEK(cek []byte) *tinkpb.KeyTemplate {
	return createKeyTemplate(false, xc20p, 0, cek)
}

// NISTPECDHAESCBCHMACKeyTemplateWithCEK is similar to NISTPECDHAES256GCMKeyTemplateWithCEK but using AES_CBC+HMAC aead.
// KW is not executed by this template, so it is ignored and set to NIST P Curved key by default.
// Keys from this template offer valid CompositeEncrypt primitive execution only and should not be stored in the KMS.
// The key created from this template has no recipient key info linked to it. It is exclusively used for primitive
// execution using content encryption algorithm:
//  - CBC+HMAC aead
//  - cek size determines the cipher block and HMAC function to use, with valid size:
// 		* 32: AES_CBC 16 bytes key size (128 bits) and SHA128 HMAC
//		* 48: AES_CBC 24 bytes key size (192 bits) and SHA192 HMAC
//		* 64: AES_CBC 32 bytes key size (256 bits) and SHA256 HMAC
//		* and other size of cek will return a template with an empty AEAD embedded template which will fail encryption.
func NISTPECDHAESCBCHMACKeyTemplateWithCEK(cek []byte) *tinkpb.KeyTemplate {
	// the curve passed in the template below is ignored when executing the primitive, it's hardcoded to pass key
	// key format validation only.
	return createKeyTemplate(true, aesCBC, 0, cek)
}

// X25519ECDHAESCBCHMACKeyTemplateWithCEK is similar to X25519ECDHXChachaKeyTemplateWithCEK but using AES_CBC+HMAC aead.
// KW is not executed by this template, so it is ignored and set to NIST P Curved key by default.
// Keys from this template offer valid CompositeEncrypt primitive execution only and should not be stored in the KMS.
// The key created from this template has no recipient key info linked to it. It is exclusively used for primitive
// execution using content encryption algorithm:
//  - CBC+HMAC aead
//  - cek size determines the cipher block and HMAC function to use, with valid size:
// 		* 32: AES_CBC 16 bytes key size (128 bits) and SHA128 HMAC
//		* 48: AES_CBC 24 bytes key size (192 bits) and SHA192 HMAC
//		* 64: AES_CBC 32 bytes key size (256 bits) and SHA256 HMAC
//		* and other size of cek will return a template with an empty AEAD embedded template which will fail encryption.
func X25519ECDHAESCBCHMACKeyTemplateWithCEK(cek []byte) *tinkpb.KeyTemplate {
	// the curve passed in the template below is ignored when executing the primitive, it's hardcoded to pass key
	// key format validation only.
	return createKeyTemplate(false, aesCBC, 0, cek)
}

// createKeyTemplate creates a new ECDH-AEAD key template with the set cek for primitive execution. Boolean flag used:
//  - nistpKW flag to state if kw is either NIST P curves (true) or Curve25519 (false)
//  - encAlg + cek to determine the the nested AEAD key template to use
func createKeyTemplate(nistpKW bool, encAlg aeadAlg, c commonpb.EllipticCurveType, cek []byte) *tinkpb.KeyTemplate {
	typeURL, keyType, encTemplate := getTypeParams(nistpKW, encAlg, cek)

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

func getTypeParams(nistpKW bool, encAlg aeadAlg, cek []byte) (string, ecdhpb.KeyType, *tinkpb.KeyTemplate) {
	var (
		keyTemplate *tinkpb.KeyTemplate
		twoKeys     = 2
	)

	switch encAlg {
	case aesGCM:
		keyTemplate = aead.AES256GCMKeyTemplate()
	case aesCBC:
		switch len(cek) {
		case subtle.AES128Size * twoKeys:
			keyTemplate = cbcaead.AES128CBCHMACSHA256KeyTemplate()
		case subtle.AES192Size * twoKeys:
			keyTemplate = cbcaead.AES192CBCHMACSHA384KeyTemplate()
		case subtle.AES256Size * twoKeys:
			keyTemplate = cbcaead.AES256CBCHMACSHA512KeyTemplate()
		}
	case xc20p:
		keyTemplate = aead.XChaCha20Poly1305KeyTemplate()
	}

	if nistpKW {
		return nistpECDHKWPrivateKeyTypeURL, ecdhpb.KeyType_EC, keyTemplate
	}

	return x25519ECDHKWPrivateKeyTypeURL, ecdhpb.KeyType_OKP, keyTemplate
}
