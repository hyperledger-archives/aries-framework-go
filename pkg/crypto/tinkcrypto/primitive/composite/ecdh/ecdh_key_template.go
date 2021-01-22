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

// NISTP256ECDHKWKeyTemplate is a KeyTemplate that generates a key that accepts a CEK for JWE content
// encryption. CEK wrapping is done outside of this Tink key (in the tinkcrypto service).
// Keys from this template represent a valid recipient public/private key pairs and can be stored in the KMS. The
// recipient key represented in this key template uses the following key wrapping curve:
//  - NIST curve P-256.
func NISTP256ECDHKWKeyTemplate() *tinkpb.KeyTemplate {
	return createKeyTemplate(true, commonpb.EllipticCurveType_NIST_P256, nil)
}

// NISTP384ECDHKWKeyTemplate is a KeyTemplate that generates a key that accepts a CEK for JWE content
// encryption. CEK wrapping is done outside of this Tink key (in the tinkcrypto service).
// Keys from this template represent a valid recipient public/private key pairs and can be stored in the KMS. The
// recipient key represented in this key template uses the following key wrapping curve:
//  - NIST curve P-384
func NISTP384ECDHKWKeyTemplate() *tinkpb.KeyTemplate {
	return createKeyTemplate(true, commonpb.EllipticCurveType_NIST_P384, nil)
}

// NISTP521ECDHKWKeyTemplate is a KeyTemplate that generates a key that accepts a CEK for JWE content
// encryption. CEK wrapping is done outside of this Tink key (in the tinkcrypto service).
// Keys from this template represent a valid recipient public/private key pairs and can be stored in the KMS. The
// recipient key represented in this key template uses the following key wrapping curve:
//  - NIST curve P-521
func NISTP521ECDHKWKeyTemplate() *tinkpb.KeyTemplate {
	return createKeyTemplate(true, commonpb.EllipticCurveType_NIST_P521, nil)
}

// X25519ECDHKWKeyTemplate is a KeyTemplate that generates a key that accepts a CEK for JWE content
// encryption. CEK wrapping is done outside of this Tink key (in the tinkcrypto service).
// Keys from this template represent a valid recipient public/private key pairs and can be stored in the KMS.The
// recipient key represented in this key template uses the following key wrapping curve:
//  - Curve25519
func X25519ECDHKWKeyTemplate() *tinkpb.KeyTemplate {
	return createKeyTemplate(false, commonpb.EllipticCurveType_CURVE25519, nil)
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
	return createKeyTemplate(true, 0, cek)
}

// X25519ECDHXChachaKeyTemplateWithCEK is similar to X25519ECDHKWKeyTemplate but adding the cek to execute the
// CompositeEncrypt primitive for encrypting a message targeted to one ore more recipients.
// Keys from this template offer valid CompositeEncrypt primitive execution only and should not be stored in the KMS.
// The key created from this template has no recipient key info linked to it. It is exclusively used for primitive
// execution using content encryption algorithm:
//  - XChacha20Poly1305
func X25519ECDHXChachaKeyTemplateWithCEK(cek []byte) *tinkpb.KeyTemplate {
	return createKeyTemplate(false, 0, cek)
}

// createKeyTemplate creates a new ECDH-AEAD key template with the set cek for primitive execution. Boolean flag used:
//  - nistpKW flag to state if kw is either NIST P curves (true) or Curve25519 (false)
func createKeyTemplate(nistpKW bool, c commonpb.EllipticCurveType, cek []byte) *tinkpb.KeyTemplate {
	typeURL, keyType, encTemplate := getTypeParams(nistpKW)

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

func getTypeParams(nispKW bool) (string, ecdhpb.KeyType, *tinkpb.KeyTemplate) {
	if nispKW {
		return nistpECDHKWPrivateKeyTypeURL, ecdhpb.KeyType_EC, aead.AES256GCMKeyTemplate()
	}

	return x25519ECDHKWPrivateKeyTypeURL, ecdhpb.KeyType_OKP, aead.XChaCha20Poly1305KeyTemplate()
}
