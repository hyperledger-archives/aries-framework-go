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

// KeyType represents a key type supported by the KMS
type KeyType string

const (
	// AES128GCMType key type value
	AES128GCMType = KeyType("AES128GCM")
	// AES256GCMNoPrefixType key type value
	AES256GCMNoPrefixType = KeyType("AES256GCMNoPrefix")
	// AES256GCMType key type value
	AES256GCMType = KeyType("AES256GCM")
	// ChaCha20Poly1305Type key type value
	ChaCha20Poly1305Type = KeyType("ChaCha20Poly1305")
	// XChaCha20Poly1305Type key type value
	XChaCha20Poly1305Type = KeyType("XChaCha20Poly1305")
	// ECDSAP256Type key type value
	ECDSAP256Type = KeyType("ECDSAP256")
	// ECDSAP384Type key type value
	ECDSAP384Type = KeyType("ECDSAP384")
	// ECDSAP521Type key type value
	ECDSAP521Type = KeyType("ECDSAP521")
	// Ed25519Type key type values
	Ed25519Type = KeyType("ED25519")
)
