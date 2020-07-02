/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// package kms provides the KMS interface of the framework. This includes the provider interface necessary for building
// KMS instances and the list of key types supported by the service.

// KeyManager manages keys and their storage for the aries framework
type KeyManager interface {
	// Create a new key/keyset/key handle for the type kt
	// Returns:
	//  - keyID of the handle
	//  - handle instance (to private key)
	//  - error if failure
	Create(kt KeyType) (string, interface{}, error)
	// Get key handle for the given keyID
	// Returns:
	//  - handle instance (to private key)
	//  - error if failure
	Get(keyID string) (interface{}, error)
	// Rotate a key referenced by keyID and return a new handle of a keyset including old key and
	// new key with type kt. It also returns the updated keyID as the first return value
	// Returns:
	//  - new KeyID // TODO remove creation of new keyID from Rotate() - #1837
	//  - handle instance (to private key)
	//  - error if failure
	Rotate(kt KeyType, keyID string) (string, interface{}, error)
	// ExportPubKeyBytes will fetch a key referenced by id then gets its public key in raw bytes and returns it.
	// The key must be an asymmetric key.
	// Returns:
	//  - marshalled public key []byte
	//  - error if it fails to export the public key bytes
	ExportPubKeyBytes(keyID string) ([]byte, error)
	// PubKeyBytesToHandle transforms pubKey raw bytes into a key handle of keyType. This function is only a utility to
	// provide a public key handle for Tink/Crypto primitive execution, it does not persist the key handle.
	// Returns:
	//  - handle instance to the public key of type keyType
	//  - error if keyType is not supported, the key does not match keyType or unmarshal fails
	PubKeyBytesToHandle(pubKey []byte, kt KeyType) (interface{}, error)
	// ImportPrivateKey will import privKey into the KMS storage for the given keyType then returns the new key id and
	// the newly persisted Handle.
	// 'privKey' possible types are: *ecdsa.PrivateKey and ed25519.PrivateKey
	// 'kt' possible types are signing key types only (ECDSA keys or Ed25519)
	// 'opts' allows setting the keysetID of the imported key using WithKeyID() option. If the ID is already used,
	// then an error is returned.
	// Returns:
	//  - keyID of the handle
	//  - handle instance (to private key)
	//  - error if import failure (key empty, invalid, doesn't match keyType, unsupported keyType or storing key failed)
	ImportPrivateKey(privKey interface{}, kt KeyType, opts ...PrivateKeyOpts) (string, interface{}, error)
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
	// ECDSAP256DER key type value
	ECDSAP256DER = "ECDSAP256DER"
	// ECDSAP384DER key type value
	ECDSAP384DER = "ECDSAP384DER"
	// ECDSAP521DER key type value
	ECDSAP521DER = "ECDSAP521DER"
	// ECDSAP256IEEEP1363 key type value
	ECDSAP256IEEEP1363 = "ECDSAP256IEEEP1363"
	// ECDSAP384IEEEP1363 key type value
	ECDSAP384IEEEP1363 = "ECDSAP384IEEEP1363"
	// ECDSAP521IEEEP1363 key type value
	ECDSAP521IEEEP1363 = "ECDSAP521IEEEP1363"
	// ECDSASecp256k1IEEEP1363 key type value
	ECDSASecp256k1IEEEP1363 = "ECDSASecp256k1IEEEP1363"
	// ED25519 key type value
	ED25519 = "ED25519"
	// RSARS256 key type value
	RSARS256 = "RSARS256"
	// RSAPS256 key type value
	RSAPS256 = "RSAPS256"
	// HMACSHA256Tag256 key type value
	HMACSHA256Tag256 = "HMACSHA256Tag256"
	// ECDHES256AES256GCM key type value
	ECDHES256AES256GCM = "ECDHES256AES256GCM"
	// ECDHES384AES256GCM key type value
	ECDHES384AES256GCM = "ECDHES384AES256GCM"
	// ECDHES521AES256GCM key type value
	ECDHES521AES256GCM = "ECDHES521AES256GCM"
	// ECDH1PU256AES256GCM key type value
	ECDH1PU256AES256GCM = "ECDH1PU256AES256GCM"
	// ECDH1PU384AES256GCM key type value
	ECDH1PU384AES256GCM = "ECDH1PU384AES256GCM"
	// ECDH1PU521AES256GCM key type value
	ECDH1PU521AES256GCM = "ECDH1PU521AES256GCM"
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
	// ECDSAP256TypeDER key type value
	ECDSAP256TypeDER = KeyType(ECDSAP256DER)
	// ECDSAP384TypeDER key type value
	ECDSAP384TypeDER = KeyType(ECDSAP384DER)
	// ECDSAP521TypeDER key type value
	ECDSAP521TypeDER = KeyType(ECDSAP521DER)
	// ECDSAP256TypeIEEEP1363 key type value
	ECDSAP256TypeIEEEP1363 = KeyType(ECDSAP256IEEEP1363)
	// ECDSAP384TypeIEEEP1363 key type value
	ECDSAP384TypeIEEEP1363 = KeyType(ECDSAP384IEEEP1363)
	// ECDSAP521TypeIEEEP1363 key type value
	ECDSAP521TypeIEEEP1363 = KeyType(ECDSAP521IEEEP1363)
	// ECDSASecp256k1TypeIEEEP1363 key type value
	ECDSASecp256k1TypeIEEEP1363 = KeyType(ECDSASecp256k1IEEEP1363)
	// ED25519Type key type value
	ED25519Type = KeyType(ED25519)
	// RSARS256Type key type value
	RSARS256Type = KeyType(RSARS256)
	// RSAPS256Type key type value
	RSAPS256Type = KeyType(RSAPS256)
	// HMACSHA256Tag256Type key type value
	HMACSHA256Tag256Type = KeyType(HMACSHA256Tag256)
	// ECDHES256AES256GCMType key type value
	ECDHES256AES256GCMType = KeyType(ECDHES256AES256GCM)
	// ECDHES384AES256GCMType key type value
	ECDHES384AES256GCMType = KeyType(ECDHES384AES256GCM)
	// ECDHES521AES256GCMType key type value
	ECDHES521AES256GCMType = KeyType(ECDHES521AES256GCM)
	// ECDH1PU256AES256GCMType key type value
	ECDH1PU256AES256GCMType = KeyType(ECDH1PU256AES256GCM)
	// ECDH1PU384AES256GCMType key type value
	ECDH1PU384AES256GCMType = KeyType(ECDH1PU384AES256GCM)
	// ECDH1PU521AES256GCMType key type value
	ECDH1PU521AES256GCMType = KeyType(ECDH1PU521AES256GCM)
)
