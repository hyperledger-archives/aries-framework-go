/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

// Package kms provides the KMS interface of the framework. This includes the provider interface necessary for building
// KMS instances and the list of key types supported by the service.
package kms

import (
	"github.com/trustbloc/kms-go/spi/kms"
)

// KeyManager manages keys and their storage for the aries framework.
type KeyManager = kms.KeyManager

// Store defines the storage capability required by a KeyManager Provider.
type Store = kms.Store

// Provider for KeyManager builder/constructor.
type Provider = kms.Provider

// Creator method to create new key management service.
type Creator func(provider Provider) (KeyManager, error)

const (
	// AES128GCM key type value.
	AES128GCM = "AES128GCM"
	// AES256GCMNoPrefix key type value.
	AES256GCMNoPrefix = "AES256GCMNoPrefix"
	// AES256GCM key type value.
	AES256GCM = "AES256GCM"
	// ChaCha20Poly1305 key type value.
	ChaCha20Poly1305 = "ChaCha20Poly1305"
	// XChaCha20Poly1305 key type value.
	XChaCha20Poly1305 = "XChaCha20Poly1305"
	// ECDSAP256DER key type value.
	ECDSAP256DER = "ECDSAP256DER"
	// ECDSAP384DER key type value.
	ECDSAP384DER = "ECDSAP384DER"
	// ECDSAP521DER key type value.
	ECDSAP521DER = "ECDSAP521DER"
	// ECDSASecp256k1DER key type value.
	ECDSASecp256k1DER = "ECDSASecp256k1DER"
	// ECDSAP256IEEEP1363 key type value.
	ECDSAP256IEEEP1363 = "ECDSAP256IEEEP1363"
	// ECDSAP384IEEEP1363 key type value.
	ECDSAP384IEEEP1363 = "ECDSAP384IEEEP1363"
	// ECDSAP521IEEEP1363 key type value.
	ECDSAP521IEEEP1363 = "ECDSAP521IEEEP1363"
	// ECDSASecp256k1IEEEP1363 key type value.
	ECDSASecp256k1IEEEP1363 = "ECDSASecp256k1IEEEP1363"
	// ED25519 key type value.
	ED25519 = "ED25519"
	// RSARS256 key type value.
	RSARS256 = "RSARS256"
	// RSAPS256 key type value.
	RSAPS256 = "RSAPS256"
	// HMACSHA256Tag256 key type value.
	HMACSHA256Tag256 = "HMACSHA256Tag256"
	// NISTP256ECDHKW key type value.
	NISTP256ECDHKW = "NISTP256ECDHKW"
	// NISTP384ECDHKW key type value.
	NISTP384ECDHKW = "NISTP384ECDHKW"
	// NISTP521ECDHKW key type value.
	NISTP521ECDHKW = "NISTP521ECDHKW"
	// X25519ECDHKW key type value.
	X25519ECDHKW = "X25519ECDHKW"
	// BLS12381G2 BBS+ key type value.
	BLS12381G2 = "BLS12381G2"
	// CLCredDef key type value.
	CLCredDef = "CLCredDef"
	// CLMasterSecret key type value.
	CLMasterSecret = "CLMasterSecret"
)

// KeyType represents a key type supported by the KMS.
type KeyType = kms.KeyType

const (
	// AES128GCMType key type value.
	AES128GCMType = KeyType(AES128GCM)
	// AES256GCMNoPrefixType key type value.
	AES256GCMNoPrefixType = KeyType(AES256GCMNoPrefix)
	// AES256GCMType key type value.
	AES256GCMType = KeyType(AES256GCM)
	// ChaCha20Poly1305Type key type value.
	ChaCha20Poly1305Type = KeyType(ChaCha20Poly1305)
	// XChaCha20Poly1305Type key type value.
	XChaCha20Poly1305Type = KeyType(XChaCha20Poly1305)
	// ECDSAP256TypeDER key type value.
	ECDSAP256TypeDER = KeyType(ECDSAP256DER)
	// ECDSASecp256k1TypeDER key type value.
	ECDSASecp256k1TypeDER = KeyType(ECDSASecp256k1DER)
	// ECDSAP384TypeDER key type value.
	ECDSAP384TypeDER = KeyType(ECDSAP384DER)
	// ECDSAP521TypeDER key type value.
	ECDSAP521TypeDER = KeyType(ECDSAP521DER)
	// ECDSAP256TypeIEEEP1363 key type value.
	ECDSAP256TypeIEEEP1363 = KeyType(ECDSAP256IEEEP1363)
	// ECDSAP384TypeIEEEP1363 key type value.
	ECDSAP384TypeIEEEP1363 = KeyType(ECDSAP384IEEEP1363)
	// ECDSAP521TypeIEEEP1363 key type value.
	ECDSAP521TypeIEEEP1363 = KeyType(ECDSAP521IEEEP1363)
	// ECDSASecp256k1TypeIEEEP1363 key type value.
	ECDSASecp256k1TypeIEEEP1363 = KeyType(ECDSASecp256k1IEEEP1363)
	// ED25519Type key type value.
	ED25519Type = KeyType(ED25519)
	// RSARS256Type key type value.
	RSARS256Type = KeyType(RSARS256)
	// RSAPS256Type key type value.
	RSAPS256Type = KeyType(RSAPS256)
	// HMACSHA256Tag256Type key type value.
	HMACSHA256Tag256Type = KeyType(HMACSHA256Tag256)
	// NISTP256ECDHKWType key type value.
	NISTP256ECDHKWType = KeyType(NISTP256ECDHKW)
	// NISTP384ECDHKWType key type value.
	NISTP384ECDHKWType = KeyType(NISTP384ECDHKW)
	// NISTP521ECDHKWType key type value.
	NISTP521ECDHKWType = KeyType(NISTP521ECDHKW)
	// X25519ECDHKWType key type value.
	X25519ECDHKWType = KeyType(X25519ECDHKW)
	// BLS12381G2Type BBS+ key type value.
	BLS12381G2Type = KeyType(BLS12381G2)
	// CLCredDefType type value.
	CLCredDefType = KeyType(CLCredDef)
	// CLMasterSecretType key type value.
	CLMasterSecretType = KeyType(CLMasterSecret)
)
