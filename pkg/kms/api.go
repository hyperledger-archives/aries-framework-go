/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/pkg/kms"
)

// package kms provides the KMS interface of the framework. This includes the provider interface necessary for building
// KMS instances and the list of key types supported by the service.

// KeyManager manages keys and their storage for the aries framework.
type KeyManager = kms.KeyManager

// ErrKeyNotFound is an error type that a KMS expects from the Store.Get method if no key stored under the given
// key ID could be found.
var ErrKeyNotFound = kms.ErrKeyNotFound

// Store defines the storage capability required by a KeyManager Provider.
type Store = kms.Store

// Provider for KeyManager builder/constructor.
type Provider = kms.Provider

// Creator method to create new key management service.
type Creator func(provider Provider) (KeyManager, error)

const (
	// AES128GCM key type value.
	AES128GCM = kms.AES128GCM
	// AES256GCMNoPrefix key type value.
	AES256GCMNoPrefix = kms.AES256GCMNoPrefix
	// AES256GCM key type value.
	AES256GCM = kms.AES256GCM
	// ChaCha20Poly1305 key type value.
	ChaCha20Poly1305 = kms.ChaCha20Poly1305
	// XChaCha20Poly1305 key type value.
	XChaCha20Poly1305 = kms.XChaCha20Poly1305
	// ECDSAP256DER key type value.
	ECDSAP256DER = kms.ECDSAP256DER
	// ECDSAP384DER key type value.
	ECDSAP384DER = kms.ECDSAP384DER
	// ECDSAP521DER key type value.
	ECDSAP521DER = kms.ECDSAP521DER
	// ECDSASecp256k1DER key type value.
	ECDSASecp256k1DER = kms.ECDSASecp256k1DER
	// ECDSAP256IEEEP1363 key type value.
	ECDSAP256IEEEP1363 = kms.ECDSAP256IEEEP1363
	// ECDSAP384IEEEP1363 key type value.
	ECDSAP384IEEEP1363 = kms.ECDSAP384IEEEP1363
	// ECDSAP521IEEEP1363 key type value.
	ECDSAP521IEEEP1363 = kms.ECDSAP521IEEEP1363
	// ECDSASecp256k1IEEEP1363 key type value.
	ECDSASecp256k1IEEEP1363 = kms.ECDSASecp256k1IEEEP1363
	// ED25519 key type value.
	ED25519 = kms.ED25519
	// RSARS256 key type value.
	RSARS256 = kms.RSARS256
	// RSAPS256 key type value.
	RSAPS256 = kms.RSAPS256
	// HMACSHA256Tag256 key type value.
	HMACSHA256Tag256 = kms.HMACSHA256Tag256
	// NISTP256ECDHKW key type value.
	NISTP256ECDHKW = kms.NISTP256ECDHKW
	// NISTP384ECDHKW key type value.
	NISTP384ECDHKW = kms.NISTP384ECDHKW
	// NISTP521ECDHKW key type value.
	NISTP521ECDHKW = kms.NISTP521ECDHKW
	// X25519ECDHKW key type value.
	X25519ECDHKW = kms.X25519ECDHKW
	// BLS12381G2 BBS+ key type value.
	BLS12381G2 = kms.BLS12381G2
	// CLCredDef key type value.
	CLCredDef = kms.CLCredDef
	// CLMasterSecret key type value.
	CLMasterSecret = kms.CLMasterSecret
)

// KeyType represents a key type supported by the KMS.
type KeyType = kms.KeyType

const (
	// AES128GCMType key type value.
	AES128GCMType = kms.AES128GCMType
	// AES256GCMNoPrefixType key type value.
	AES256GCMNoPrefixType = kms.AES256GCMNoPrefixType
	// AES256GCMType key type value.
	AES256GCMType = kms.AES256GCMType
	// ChaCha20Poly1305Type key type value.
	ChaCha20Poly1305Type = kms.ChaCha20Poly1305Type
	// XChaCha20Poly1305Type key type value.
	XChaCha20Poly1305Type = kms.XChaCha20Poly1305Type
	// ECDSAP256TypeDER key type value.
	ECDSAP256TypeDER = kms.ECDSAP256TypeDER
	// ECDSASecp256k1TypeDER key type value.
	ECDSASecp256k1TypeDER = kms.ECDSASecp256k1TypeDER
	// ECDSAP384TypeDER key type value.
	ECDSAP384TypeDER = kms.ECDSAP384TypeDER
	// ECDSAP521TypeDER key type value.
	ECDSAP521TypeDER = kms.ECDSAP521TypeDER
	// ECDSAP256TypeIEEEP1363 key type value.
	ECDSAP256TypeIEEEP1363 = kms.ECDSAP256TypeIEEEP1363
	// ECDSAP384TypeIEEEP1363 key type value.
	ECDSAP384TypeIEEEP1363 = kms.ECDSAP384TypeIEEEP1363
	// ECDSAP521TypeIEEEP1363 key type value.
	ECDSAP521TypeIEEEP1363 = kms.ECDSAP521TypeIEEEP1363
	// ECDSASecp256k1TypeIEEEP1363 key type value.
	ECDSASecp256k1TypeIEEEP1363 = KeyType(ECDSASecp256k1IEEEP1363)
	// ED25519Type key type value.
	ED25519Type = kms.ED25519Type
	// RSARS256Type key type value.
	RSARS256Type = kms.RSARS256Type
	// RSAPS256Type key type value.
	RSAPS256Type = kms.RSAPS256Type
	// HMACSHA256Tag256Type key type value.
	HMACSHA256Tag256Type = kms.HMACSHA256Tag256Type
	// NISTP256ECDHKWType key type value.
	NISTP256ECDHKWType = kms.NISTP256ECDHKWType
	// NISTP384ECDHKWType key type value.
	NISTP384ECDHKWType = kms.NISTP384ECDHKWType
	// NISTP521ECDHKWType key type value.
	NISTP521ECDHKWType = kms.NISTP521ECDHKWType
	// X25519ECDHKWType key type value.
	X25519ECDHKWType = kms.X25519ECDHKWType
	// BLS12381G2Type BBS+ key type value.
	BLS12381G2Type = kms.BLS12381G2Type
	// CLCredDefType type value.
	CLCredDefType = kms.CLCredDefType
	// CLMasterSecretType key type value.
	CLMasterSecretType = kms.CLMasterSecretType
)

// CryptoBox is a libsodium crypto service used by legacy authcrypt packer.
// TODO remove this service when legacy packer is retired from the framework.
type CryptoBox = kms.CryptoBox

// PrivateKeyOpts are the import private key option.
type PrivateKeyOpts = kms.PrivateKeyOpts

// WithKeyID option is for importing a private key with a specified KeyID.
func WithKeyID(keyID string) PrivateKeyOpts {
	return kms.WithKeyID(keyID)
}

// KeyOpts are the create key option.
type KeyOpts = kms.KeyOpts

// WithAttrs option is for creating a key that requires extra attributes.
func WithAttrs(attrs []string) kms.KeyOpts {
	return kms.WithAttrs(attrs)
}
