/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cryptoutil

import (
	chacha "golang.org/x/crypto/chacha20poly1305"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/util/cryptoutil"
)

// DeriveECDHX25519 does X25519 ECDH using fromPrivKey and toPubKey.
func DeriveECDHX25519(fromPrivKey, toPubKey *[chacha.KeySize]byte) ([]byte, error) {
	return cryptoutil.DeriveECDHX25519(fromPrivKey, toPubKey)
}

// LengthPrefix array with a bigEndian uint32 value of array's length.
func LengthPrefix(array []byte) []byte {
	return cryptoutil.LengthPrefix(array)
}

// Curve25519KeySize number of bytes in a Curve25519 public or private key.
const Curve25519KeySize = cryptoutil.Curve25519KeySize

// NonceSize size of a nonce used by Box encryption (Xchacha20Poly1305).
const NonceSize = cryptoutil.NonceSize

// PublicEd25519toCurve25519 takes an Ed25519 public key and provides the corresponding Curve25519 public key
// This function wraps PublicKeyToCurve25519 from Adam Langley's ed25519 repo: https://github.com/agl/ed25519 now
// moved to https://github.com/teserakt-io/golang-ed25519
func PublicEd25519toCurve25519(pub []byte) ([]byte, error) {
	return cryptoutil.PublicEd25519toCurve25519(pub)
}

// SecretEd25519toCurve25519 converts a secret key from Ed25519 to curve25519 format
// This function wraps PrivateKeyToCurve25519 from Adam Langley's ed25519 repo: https://github.com/agl/ed25519 now
// moved to https://github.com/teserakt-io/golang-ed25519
func SecretEd25519toCurve25519(priv []byte) ([]byte, error) {
	return cryptoutil.SecretEd25519toCurve25519(priv)
}
