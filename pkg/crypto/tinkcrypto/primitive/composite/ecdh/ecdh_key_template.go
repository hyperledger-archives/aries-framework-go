/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdh

import (
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/ecdh"
)

// AEADAlg represents the AEAD implementation algorithm used by ECDH.
type AEADAlg = ecdh.AEADAlg

const (
	// AES256GCM AEAD.
	AES256GCM = iota + 1
	// XC20P AEAD.
	XC20P
	// AES128CBCHMACSHA256 AEAD.
	AES128CBCHMACSHA256
	// AES192CBCHMACSHA384 AEAD.
	AES192CBCHMACSHA384
	// AES256CBCHMACSHA384 AEAD.
	AES256CBCHMACSHA384
	// AES256CBCHMACSHA512 AEAD.
	AES256CBCHMACSHA512
)

// EncryptionAlgLabel maps AEADAlg to its label.
var EncryptionAlgLabel = ecdh.EncryptionAlgLabel // nolint: gochecknoglobals

// NISTP256ECDHKWKeyTemplate is a KeyTemplate that generates a key that accepts a CEK for JWE content
// encryption. CEK wrapping is done outside of this Tink key (in the tinkcrypto service).
// Keys from this template represent a valid recipient public/private key pairs and can be stored in the KMS. The
// recipient key represented in this key template uses the following key wrapping curve:
//   - NIST curve P-256.
//
// Keys created with this template are mainly used for key wrapping of a cek. They are independent of the AEAD content
// encryption algorithm.
func NISTP256ECDHKWKeyTemplate() *tinkpb.KeyTemplate {
	// aesGCM is set to pass key generation in the key manager, it's irrelevant to the key or its intended use.
	return ecdh.NISTP256ECDHKWKeyTemplate()
}

// NISTP384ECDHKWKeyTemplate is a KeyTemplate that generates a key that accepts a CEK for JWE content
// encryption. CEK wrapping is done outside of this Tink key (in the tinkcrypto service).
// Keys from this template represent a valid recipient public/private key pairs and can be stored in the KMS. The
// recipient key represented in this key template uses the following key wrapping curve:
//   - NIST curve P-384
//
// Keys created with this template are mainly used for key wrapping of a cek. They are independent of the AEAD content
// encryption algorithm.
func NISTP384ECDHKWKeyTemplate() *tinkpb.KeyTemplate {
	// aesGCM is set to pass key generation in the key manager, it's irrelevant to the key or its intended use.
	return ecdh.NISTP384ECDHKWKeyTemplate()
}

// NISTP521ECDHKWKeyTemplate is a KeyTemplate that generates a key that accepts a CEK for JWE content
// encryption. CEK wrapping is done outside of this Tink key (in the tinkcrypto service).
// Keys from this template represent a valid recipient public/private key pairs and can be stored in the KMS. The
// recipient key represented in this key template uses the following key wrapping curve:
//   - NIST curve P-521
//
// Keys created with this template are mainly used for key wrapping of a cek. They are independent of the AEAD content
// encryption algorithm.
func NISTP521ECDHKWKeyTemplate() *tinkpb.KeyTemplate {
	// aesGCM is set to pass key generation in the key manager, it's irrelevant to the key or its intended use.
	return ecdh.NISTP521ECDHKWKeyTemplate()
}

// X25519ECDHKWKeyTemplate is a KeyTemplate that generates a key that accepts a CEK for JWE content
// encryption. CEK wrapping is done outside of this Tink key (in the tinkcrypto service).
// Keys from this template represent a valid recipient public/private key pairs and can be stored in the KMS.The
// recipient key represented in this key template uses the following key wrapping curve:
//   - Curve25519
//
// Keys created with this template are mainly used for key wrapping of a cek. They are independent of the AEAD content
// encryption algorithm.
func X25519ECDHKWKeyTemplate() *tinkpb.KeyTemplate {
	// xc20p is set to pass key generation in the key manager, it's irrelevant to the key or its intended use.
	return ecdh.X25519ECDHKWKeyTemplate()
}

// KeyTemplateForECDHPrimitiveWithCEK is similar to NISTP256ECDHKWKeyTemplate but adding the cek to execute the
// CompositeEncrypt primitive for encrypting a message targeted to one ore more recipients. KW is not executed by this
// template, so it is ignored and set to NIST P Curved key by default.
// Keys from this template offer valid CompositeEncrypt primitive execution only and should not be stored in the KMS.
// The key created from this template has no recipient key info linked to it. It is exclusively used for primitive
// execution using content encryption. Available content encryption algorithms:
//   - AES256GCM, XChacaha20Poly1305, AES128CBC+HMAC256, AES192CBC+HMAC384, AES256CBC+HMAC384, AES256CBC+HMAC512
//
// It works with both key wrapping modes (executed outside of the key primitive created by this template):
// NIST P kw or XC20P kw
// cek should be of size:
// - 32 bytes for AES256GCM, XChacaha20Poly1305, AES128CBC+HMAC256.
// - 48 bytes for AES192CBC+HMAC384.
// - 56 bytes for AES256CBC+HMAC384.
// - 64 bytes for AES256CBC+HMAC512.
func KeyTemplateForECDHPrimitiveWithCEK(cek []byte, nistpKW bool, encAlg AEADAlg) *tinkpb.KeyTemplate {
	// the curve passed in the template below is ignored when executing the primitive, it's hardcoded to pass key
	// key format validation only.
	return ecdh.KeyTemplateForECDHPrimitiveWithCEK(cek, nistpKW, encAlg)
}
