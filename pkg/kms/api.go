/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/kms"
	kmsapi "github.com/hyperledger/aries-framework-go/spi/kms"
)

// package kms provides the KMS interface of the framework. This includes the provider interface necessary for building
// KMS instances and the list of key types supported by the service.

// KeyManager manages keys and their storage for the aries framework.
type KeyManager = kmsapi.KeyManager

// ErrKeyNotFound is an error type that a KMS expects from the Store.Get method if no key stored under the given
// key ID could be found.
var ErrKeyNotFound = kms.ErrKeyNotFound

// Store defines the storage capability required by a KeyManager Provider.
type Store = kmsapi.Store

// Provider for KeyManager builder/constructor.
type Provider = kmsapi.Provider

// Creator method to create new key management service.
type Creator func(provider Provider) (KeyManager, error)

const (
	// AES128GCM key type value.
	AES128GCM = kmsapi.AES128GCM
	// AES256GCMNoPrefix key type value.
	AES256GCMNoPrefix = kmsapi.AES256GCMNoPrefix
	// AES256GCM key type value.
	AES256GCM = kmsapi.AES256GCM
	// ChaCha20Poly1305 key type value.
	ChaCha20Poly1305 = kmsapi.ChaCha20Poly1305
	// XChaCha20Poly1305 key type value.
	XChaCha20Poly1305 = kmsapi.XChaCha20Poly1305
	// ECDSAP256DER key type value.
	ECDSAP256DER = kmsapi.ECDSAP256DER
	// ECDSAP384DER key type value.
	ECDSAP384DER = kmsapi.ECDSAP384DER
	// ECDSAP521DER key type value.
	ECDSAP521DER = kmsapi.ECDSAP521DER
	// ECDSASecp256k1DER key type value.
	ECDSASecp256k1DER = kmsapi.ECDSASecp256k1DER
	// ECDSAP256IEEEP1363 key type value.
	ECDSAP256IEEEP1363 = kmsapi.ECDSAP256IEEEP1363
	// ECDSAP384IEEEP1363 key type value.
	ECDSAP384IEEEP1363 = kmsapi.ECDSAP384IEEEP1363
	// ECDSAP521IEEEP1363 key type value.
	ECDSAP521IEEEP1363 = kmsapi.ECDSAP521IEEEP1363
	// ECDSASecp256k1IEEEP1363 key type value.
	ECDSASecp256k1IEEEP1363 = kmsapi.ECDSASecp256k1IEEEP1363
	// ED25519 key type value.
	ED25519 = kmsapi.ED25519
	// RSARS256 key type value.
	RSARS256 = kmsapi.RSARS256
	// RSAPS256 key type value.
	RSAPS256 = kmsapi.RSAPS256
	// HMACSHA256Tag256 key type value.
	HMACSHA256Tag256 = kmsapi.HMACSHA256Tag256
	// NISTP256ECDHKW key type value.
	NISTP256ECDHKW = kmsapi.NISTP256ECDHKW
	// NISTP384ECDHKW key type value.
	NISTP384ECDHKW = kmsapi.NISTP384ECDHKW
	// NISTP521ECDHKW key type value.
	NISTP521ECDHKW = kmsapi.NISTP521ECDHKW
	// X25519ECDHKW key type value.
	X25519ECDHKW = kmsapi.X25519ECDHKW
	// BLS12381G2 BBS+ key type value.
	BLS12381G2 = kmsapi.BLS12381G2
	// CLCredDef key type value.
	CLCredDef = kmsapi.CLCredDef
	// CLMasterSecret key type value.
	CLMasterSecret = kmsapi.CLMasterSecret
)

// KeyType represents a key type supported by the KMS.
type KeyType = kmsapi.KeyType

const (
	// AES128GCMType key type value.
	AES128GCMType = kmsapi.AES128GCMType
	// AES256GCMNoPrefixType key type value.
	AES256GCMNoPrefixType = kmsapi.AES256GCMNoPrefixType
	// AES256GCMType key type value.
	AES256GCMType = kmsapi.AES256GCMType
	// ChaCha20Poly1305Type key type value.
	ChaCha20Poly1305Type = kmsapi.ChaCha20Poly1305Type
	// XChaCha20Poly1305Type key type value.
	XChaCha20Poly1305Type = kmsapi.XChaCha20Poly1305Type
	// ECDSAP256TypeDER key type value.
	ECDSAP256TypeDER = kmsapi.ECDSAP256TypeDER
	// ECDSASecp256k1TypeDER key type value.
	ECDSASecp256k1TypeDER = kmsapi.ECDSASecp256k1TypeDER
	// ECDSAP384TypeDER key type value.
	ECDSAP384TypeDER = kmsapi.ECDSAP384TypeDER
	// ECDSAP521TypeDER key type value.
	ECDSAP521TypeDER = kmsapi.ECDSAP521TypeDER
	// ECDSAP256TypeIEEEP1363 key type value.
	ECDSAP256TypeIEEEP1363 = kmsapi.ECDSAP256TypeIEEEP1363
	// ECDSAP384TypeIEEEP1363 key type value.
	ECDSAP384TypeIEEEP1363 = kmsapi.ECDSAP384TypeIEEEP1363
	// ECDSAP521TypeIEEEP1363 key type value.
	ECDSAP521TypeIEEEP1363 = kmsapi.ECDSAP521TypeIEEEP1363
	// ECDSASecp256k1TypeIEEEP1363 key type value.
	ECDSASecp256k1TypeIEEEP1363 = kmsapi.ECDSASecp256k1TypeIEEEP1363
	// ED25519Type key type value.
	ED25519Type = kmsapi.ED25519Type
	// RSARS256Type key type value.
	RSARS256Type = kmsapi.RSARS256Type
	// RSAPS256Type key type value.
	RSAPS256Type = kmsapi.RSAPS256Type
	// HMACSHA256Tag256Type key type value.
	HMACSHA256Tag256Type = kmsapi.HMACSHA256Tag256Type
	// NISTP256ECDHKWType key type value.
	NISTP256ECDHKWType = kmsapi.NISTP256ECDHKWType
	// NISTP384ECDHKWType key type value.
	NISTP384ECDHKWType = kmsapi.NISTP384ECDHKWType
	// NISTP521ECDHKWType key type value.
	NISTP521ECDHKWType = kmsapi.NISTP521ECDHKWType
	// X25519ECDHKWType key type value.
	X25519ECDHKWType = kmsapi.X25519ECDHKWType
	// BLS12381G2Type BBS+ key type value.
	BLS12381G2Type = kmsapi.BLS12381G2Type
	// CLCredDefType type value.
	CLCredDefType = kmsapi.CLCredDefType
	// CLMasterSecretType key type value.
	CLMasterSecretType = kmsapi.CLMasterSecretType
)

// CryptoBox is a libsodium crypto service used by legacy authcrypt packer.
// TODO remove this service when legacy packer is retired from the framework.
type CryptoBox = kms.CryptoBox

// PrivateKeyOpts are the import private key option.
type PrivateKeyOpts = kmsapi.PrivateKeyOpts

// WithKeyID option is for importing a private key with a specified KeyID.
func WithKeyID(keyID string) PrivateKeyOpts {
	return kmsapi.WithKeyID(keyID)
}

// KeyOpts are the create key option.
type KeyOpts = kmsapi.KeyOpts

// WithAttrs option is for creating a key that requires extra attributes.
func WithAttrs(attrs []string) kmsapi.KeyOpts {
	return kmsapi.WithAttrs(attrs)
}
