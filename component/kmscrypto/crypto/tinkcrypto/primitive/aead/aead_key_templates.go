/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aead

import (
	"github.com/golang/protobuf/proto"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	hmacpb "github.com/google/tink/go/proto/hmac_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead/subtle"
	aescbcpb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/aes_cbc_go_proto"
	aeadpb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/aes_cbc_hmac_aead_go_proto"
)

// This file contains pre-generated KeyTemplates for AEAD keys. One can use these templates to generate new Keysets.
// These templates are based on the CBC-HMAC parameters defined at:
// https://datatracker.ietf.org/doc/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05#section-2.8.

// AES128CBCHMACSHA256KeyTemplate is a KeyTemplate that generates an AES-CBC-HMAC-AEAD key with the following
// parameters:
//  - AES key size: 16 bytes
//  - HMAC key size: 16 bytes
//  - HMAC tag size: 16 bytes
//  - HMAC hash function: SHA256
func AES128CBCHMACSHA256KeyTemplate() *tinkpb.KeyTemplate {
	return createAESCBCHMACAEADKeyTemplate(subtle.AES128Size, subtle.AES128Size, subtle.AES128Size,
		commonpb.HashType_SHA256)
}

// AES192CBCHMACSHA384KeyTemplate is a KeyTemplate that generates an AES-CBC-HMAC-AEAD key with the following
// parameters:
//  - AES key size: 24 bytes
//  - HMAC key size: 24 bytes
//  - HMAC tag size: 24 bytes
//  - HMAC hash function: SHA384
func AES192CBCHMACSHA384KeyTemplate() *tinkpb.KeyTemplate {
	return createAESCBCHMACAEADKeyTemplate(subtle.AES192Size, subtle.AES192Size, subtle.AES192Size,
		commonpb.HashType_SHA384)
}

// AES256CBCHMACSHA384KeyTemplate is a KeyTemplate that generates an AES-CBC-HMAC-AEAD key with the following
// parameters:
//  - AES key size: 32 bytes
//  - HMAC key size: 24 bytes
//  - HMAC tag size: 24 bytes
//  - HMAC hash function: SHA384
func AES256CBCHMACSHA384KeyTemplate() *tinkpb.KeyTemplate {
	return createAESCBCHMACAEADKeyTemplate(subtle.AES256Size, subtle.AES192Size, subtle.AES192Size,
		commonpb.HashType_SHA384)
}

// AES256CBCHMACSHA512KeyTemplate is a KeyTemplate that generates an AES-CBC-HMAC-AEAD key with the following
// parameters:
//  - AES key size: 32 bytes
//  - HMAC key size: 32 bytes
//  - HMAC tag size: 32 bytes
//  - HMAC hash function: SHA512
func AES256CBCHMACSHA512KeyTemplate() *tinkpb.KeyTemplate {
	return createAESCBCHMACAEADKeyTemplate(subtle.AES256Size, subtle.AES256Size, subtle.AES256Size,
		commonpb.HashType_SHA512)
}

func createAESCBCHMACAEADKeyTemplate(aesKeySize, hmacKeySize, tagSize uint32,
	hashType commonpb.HashType) *tinkpb.KeyTemplate {
	format := &aeadpb.AesCbcHmacAeadKeyFormat{
		AesCbcKeyFormat: &aescbcpb.AesCbcKeyFormat{
			KeySize: aesKeySize,
		},
		HmacKeyFormat: &hmacpb.HmacKeyFormat{
			Params:  &hmacpb.HmacParams{Hash: hashType, TagSize: tagSize},
			KeySize: hmacKeySize,
		},
	}

	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		panic("failed to marshal CBC+HMAC AEAD key format proto")
	}

	return &tinkpb.KeyTemplate{
		Value:            serializedFormat,
		TypeUrl:          aesCBCHMACAEADTypeURL,
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
	}
}
