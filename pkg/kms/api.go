/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// KeyManager manages keys and their storage for the aries framework
type KeyManager interface {
	// Create a new key/keyset/key handle for the type kt
	Create(kt KeyType) (string, interface{}, error)
	// Get key handle for the given keyID
	Get(keyID string) (interface{}, error)
	// Rotate a key referenced by keyID and return a new handle of a keyset including old key and
	// new key with type kt. It also returns the updated keyID as the first return value
	Rotate(kt KeyType, keyID string) (string, interface{}, error)
}

// Provider for KeyManager builder/constructor
type Provider interface {
	StorageProvider() storage.Provider
	SecretLock() secretlock.Service
}

// Creator method to create new key management service
type Creator func(provider Provider) (KeyManager, error)

const (
	// AES128GCM key type value
	AES128GCM = "AES128GCM"
	// AES256GCMNoPrefix key type value
	AES256GCMNoPrefix = "AES256GCMNoPrefix"
	// AES256GCM key type value
	AES256GCM = "AES256GCM"
	// ChaCha20Poly1305 key type value
	ChaCha20Poly1305 = "ChaCha20Poly1305"
	// XChaCha20Poly1305 key type value
	XChaCha20Poly1305 = "XChaCha20Poly1305"
	// ECDSAP256 key type value
	ECDSAP256 = "ECDSAP256"
	// ECDSAP384 key type value
	ECDSAP384 = "ECDSAP384"
	// ECDSAP521 key type value
	ECDSAP521 = "ECDSAP521"
	// ED25519 key type value
	ED25519 = "ED25519"
	// RSA key type value
	RSA = "RSA"
	// HMACSHA256Tag256 key type value
	HMACSHA256Tag256 = "HMACSHA256Tag256"
	// ECDHES256AES256GCM key type value
	ECDHES256AES256GCM = "ECDHES256AES256GCM"
)

// KeyType represents a key type supported by the KMS
type KeyType string

const (
	// AES128GCMType key type value
	AES128GCMType = KeyType(AES128GCM)
	// AES256GCMNoPrefixType key type value
	AES256GCMNoPrefixType = KeyType(AES256GCMNoPrefix)
	// AES256GCMType key type value
	AES256GCMType = KeyType(AES256GCM)
	// ChaCha20Poly1305Type key type value
	ChaCha20Poly1305Type = KeyType(ChaCha20Poly1305)
	// XChaCha20Poly1305Type key type value
	XChaCha20Poly1305Type = KeyType(XChaCha20Poly1305)
	// ECDSAP256Type key type value
	ECDSAP256Type = KeyType(ECDSAP256)
	// ECDSAP384Type key type value
	ECDSAP384Type = KeyType(ECDSAP384)
	// ECDSAP521Type key type value
	ECDSAP521Type = KeyType(ECDSAP521)
	// ED25519Type key type value
	ED25519Type = KeyType(ED25519)
	// RSAType key type value
	RSAType = KeyType(RSA)
	// HMACSHA256Tag256Type key type value
	HMACSHA256Tag256Type = KeyType(HMACSHA256Tag256)
	// ECDHES256AES256GCMType key type value
	ECDHES256AES256GCMType = KeyType(ECDHES256AES256GCM)
)
