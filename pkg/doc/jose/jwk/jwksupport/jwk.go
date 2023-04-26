/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwksupport

import (
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk/jwksupport"
	"github.com/hyperledger/aries-framework-go/spi/crypto"
	"github.com/hyperledger/aries-framework-go/spi/kms"
)

// JWKFromKey creates a JWK from an opaque key struct.
// It's e.g. *ecdsa.PublicKey, *ecdsa.PrivateKey, ed25519.VerificationMethod, *bbs12381g2pub.PrivateKey or
// *bbs12381g2pub.PublicKey.
func JWKFromKey(opaqueKey interface{}) (*jwk.JWK, error) {
	return jwksupport.JWKFromKey(opaqueKey)
}

// JWKFromX25519Key is similar to JWKFromKey but is specific to X25519 keys when using a public key as raw []byte.
// This builder function presets the curve and key type in the JWK.
// Using JWKFromKey for X25519 raw keys will not have these fields set and will not provide the right JWK output.
func JWKFromX25519Key(pubKey []byte) (*jwk.JWK, error) {
	return jwksupport.JWKFromX25519Key(pubKey)
}

// PubKeyBytesToJWK converts marshalled bytes of keyType into JWK.
func PubKeyBytesToJWK(bytes []byte, keyType kms.KeyType) (*jwk.JWK, error) { // nolint:gocyclo
	return jwksupport.PubKeyBytesToJWK(bytes, keyType)
}

// PublicKeyFromJWK builds a crypto.PublicKey from jwkKey.
func PublicKeyFromJWK(jwkKey *jwk.JWK) (*crypto.PublicKey, error) {
	return jwksupport.PublicKeyFromJWK(jwkKey)
}
