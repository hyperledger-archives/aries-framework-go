/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cryptoutil

import (
	"crypto"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"

	josecipher "github.com/square/go-jose/v3/cipher"
	"github.com/teserakt-io/golang-ed25519/extra25519"
	chacha "golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// Derive25519KEK is a utility function that will derive an ephemeral
// symmetric key (kek) using fromPrivKey and toPubKey.
func Derive25519KEK(alg, apu, apv []byte, fromPrivKey, toPubKey *[chacha.KeySize]byte) ([]byte, error) {
	if fromPrivKey == nil || toPubKey == nil {
		return nil, errors.New("invalid key")
	}

	const (
		numBitsPerByte = 8
		supPubInfoLen  = 4
	)

	// do ScalarMult of the sender's private key with the recipient key to get a derived Z point
	// ( equivalent to derive an EC key )
	z, err := curve25519.X25519(fromPrivKey[:], toPubKey[:])
	if err != nil {
		return nil, err
	}

	// inspired by: github.com/square/go-jose/v3@v3.0.0-20190722231519-723929d55157/cipher/ecdh_es.go
	// -> DeriveECDHES() call
	// suppPubInfo is the encoded length of the recipient shared key output size in bits
	supPubInfo := make([]byte, supPubInfoLen)
	// since we're using chacha20poly1305 keys, keySize is known
	binary.BigEndian.PutUint32(supPubInfo, uint32(chacha.KeySize)*numBitsPerByte)

	// as per https://tools.ietf.org/html/rfc7518#section-4.6.2
	// concatKDF requires info data to be length prefixed with BigEndian 32 bits type
	// length prefix alg
	algInfo := LengthPrefix(alg)

	// length prefix apu
	apuInfo := LengthPrefix(apu)

	// length prefix apv
	apvInfo := LengthPrefix(apv)

	// get a Concat KDF stream for z, encryption algorithm, api, supPubInfo and empty supPrivInfo using sha256
	reader := josecipher.NewConcatKDF(crypto.SHA256, z, algInfo, apuInfo, apvInfo, supPubInfo, []byte{})

	// kek is the recipient specific encryption key used to encrypt the sharedSymKey
	kek := make([]byte, chacha.KeySize)

	// Read on the KDF will never fail
	_, err = reader.Read(kek)
	if err != nil {
		return nil, err
	}

	return kek, nil
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
