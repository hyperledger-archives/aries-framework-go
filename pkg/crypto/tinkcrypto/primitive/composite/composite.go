/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package composite provides the core crypto composite primitives such as ECDH-ES and ECDH-1PU to be used by JWE crypto
package composite

import (
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite"
)

// EncryptedData represents the Encryption's output data as a result of ECDHEncrypt.Encrypt(pt, aad) call
// The user of the primitive must unmarshal the result and build their own ECDH-ES/1PU compliant message (ie JWE msg).
type EncryptedData = composite.EncryptedData

// EncrypterHelper is a helper for Content Encryption of composite ECDH (ES/1PU) key wrapping + AEAD content encryption
// This interface is used internally by the composite primitives.
type EncrypterHelper = composite.EncrypterHelper

const (
	// AESCBCHMACAEADTypeURL for AESCBC+HMAC AEAD content encryption URL.
	AESCBCHMACAEADTypeURL = composite.AESCBCHMACAEADTypeURL
	// AESGCMTypeURL for AESGCM content encryption URL identifier.
	AESGCMTypeURL = composite.AESGCMTypeURL
	// ChaCha20Poly1305TypeURL for Chacha20Poly1305 content encryption URL identifier.
	ChaCha20Poly1305TypeURL = composite.ChaCha20Poly1305TypeURL
	// XChaCha20Poly1305TypeURL for XChachaPoly1305 content encryption URL identifier.
	XChaCha20Poly1305TypeURL = composite.XChaCha20Poly1305TypeURL
)

// RegisterCompositeAEADEncHelper registers a content encryption helper.
type RegisterCompositeAEADEncHelper = composite.RegisterCompositeAEADEncHelper

// NewRegisterCompositeAEADEncHelper initializes and returns a RegisterCompositeAEADEncHelper.
//
//nolint:gocyclo
func NewRegisterCompositeAEADEncHelper(k *tinkpb.KeyTemplate) (*RegisterCompositeAEADEncHelper, error) {
	return composite.NewRegisterCompositeAEADEncHelper(k)
}
