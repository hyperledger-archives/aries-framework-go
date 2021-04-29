/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cryptoutil

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/teserakt-io/golang-ed25519/extra25519"
	chacha "golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// DeriveECDHX25519 does X25519 ECDH using fromPrivKey and toPubKey.
func DeriveECDHX25519(fromPrivKey, toPubKey *[chacha.KeySize]byte) ([]byte, error) {
	if fromPrivKey == nil || toPubKey == nil {
		return nil, errors.New("deriveECDHX25519: invalid key")
	}

	// do ScalarMult of the sender's private key with the recipient key to get a derived Z point (ECDH)
	z, err := curve25519.X25519(fromPrivKey[:], toPubKey[:])
	if err != nil {
		return nil, fmt.Errorf("deriveECDHX25519: %w", err)
	}

	return z, nil
}

// LengthPrefix array with a bigEndian uint32 value of array's length.
func LengthPrefix(array []byte) []byte {
	const prefixLen = 4

	arrInfo := make([]byte, prefixLen+len(array))
	binary.BigEndian.PutUint32(arrInfo, uint32(len(array)))
	copy(arrInfo[prefixLen:], array)

	return arrInfo
}

// Curve25519KeySize number of bytes in a Curve25519 public or private key.
const Curve25519KeySize = 32

// NonceSize size of a nonce used by Box encryption (Xchacha20Poly1305).
const NonceSize = 24

// PublicEd25519toCurve25519 takes an Ed25519 public key and provides the corresponding Curve25519 public key
// This function wraps PublicKeyToCurve25519 from Adam Langley's ed25519 repo: https://github.com/agl/ed25519 now
// moved to https://github.com/teserakt-io/golang-ed25519
func PublicEd25519toCurve25519(pub []byte) ([]byte, error) {
	if len(pub) == 0 {
		return nil, errors.New("public key is nil")
	}

	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%d-byte key size is invalid", len(pub))
	}

	pkOut := new([Curve25519KeySize]byte)
	pKIn := new([Curve25519KeySize]byte)
	copy(pKIn[:], pub)

	success := extra25519.PublicKeyToCurve25519(pkOut, pKIn)
	if !success {
		return nil, errors.New("error converting public key")
	}

	return pkOut[:], nil
}

// SecretEd25519toCurve25519 converts a secret key from Ed25519 to curve25519 format
// This function wraps PrivateKeyToCurve25519 from Adam Langley's ed25519 repo: https://github.com/agl/ed25519 now
// moved to https://github.com/teserakt-io/golang-ed25519
func SecretEd25519toCurve25519(priv []byte) ([]byte, error) {
	if len(priv) == 0 {
		return nil, errors.New("private key is nil")
	}

	sKIn := new([ed25519.PrivateKeySize]byte)
	copy(sKIn[:], priv)

	sKOut := new([Curve25519KeySize]byte)
	extra25519.PrivateKeyToCurve25519(sKOut, sKIn)

	return sKOut[:], nil
}
