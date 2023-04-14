/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aead

import (
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead"
)

// This file contains pre-generated KeyTemplates for AEAD keys. One can use these templates to generate new Keysets.
// These templates are based on the CBC-HMAC parameters defined at:
// https://datatracker.ietf.org/doc/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05#section-2.8.

// AES128CBCHMACSHA256KeyTemplate is a KeyTemplate that generates an AES-CBC-HMAC-AEAD key with the following
// parameters:
//   - AES key size: 16 bytes
//   - HMAC key size: 16 bytes
//   - HMAC tag size: 16 bytes
//   - HMAC hash function: SHA256
func AES128CBCHMACSHA256KeyTemplate() *tinkpb.KeyTemplate {
	return aead.AES128CBCHMACSHA256KeyTemplate()
}

// AES192CBCHMACSHA384KeyTemplate is a KeyTemplate that generates an AES-CBC-HMAC-AEAD key with the following
// parameters:
//   - AES key size: 24 bytes
//   - HMAC key size: 24 bytes
//   - HMAC tag size: 24 bytes
//   - HMAC hash function: SHA384
func AES192CBCHMACSHA384KeyTemplate() *tinkpb.KeyTemplate {
	return aead.AES192CBCHMACSHA384KeyTemplate()
}

// AES256CBCHMACSHA384KeyTemplate is a KeyTemplate that generates an AES-CBC-HMAC-AEAD key with the following
// parameters:
//   - AES key size: 32 bytes
//   - HMAC key size: 24 bytes
//   - HMAC tag size: 24 bytes
//   - HMAC hash function: SHA384
func AES256CBCHMACSHA384KeyTemplate() *tinkpb.KeyTemplate {
	return aead.AES256CBCHMACSHA384KeyTemplate()
}

// AES256CBCHMACSHA512KeyTemplate is a KeyTemplate that generates an AES-CBC-HMAC-AEAD key with the following
// parameters:
//   - AES key size: 32 bytes
//   - HMAC key size: 32 bytes
//   - HMAC tag size: 32 bytes
//   - HMAC hash function: SHA512
func AES256CBCHMACSHA512KeyTemplate() *tinkpb.KeyTemplate {
	return aead.AES256CBCHMACSHA512KeyTemplate()
}
