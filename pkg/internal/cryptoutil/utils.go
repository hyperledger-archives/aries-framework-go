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

// errEmptyRecipients is used when recipients list is empty.
var errEmptyRecipients = errors.New("empty recipients")

// errInvalidKeypair is used when a keypair is invalid.
var errInvalidKeypair = errors.New("invalid keypair")

// SignatureAlgorithm represents a signature algorithm.
type SignatureAlgorithm string

// EncryptionAlgorithm represents a content encryption algorithm.
type EncryptionAlgorithm string

const (
	// encryption key types.

	// Curve25519 encryption key type.
	Curve25519 = EncryptionAlgorithm("Curve25519")

	// signing key types.

	// EdDSA signature key type.
	EdDSA = SignatureAlgorithm("EdDSA")
)

// VerifyKeys is a utility function that verifies if sender key pair and recipients keys are valid (not empty).
func VerifyKeys(sender KeyPair, recipients [][]byte) error {
	if len(recipients) == 0 {
		return errEmptyRecipients
	}

	if !isKeyPairValid(sender) {
		return errInvalidKeypair
	}

	if !IsChachaKeyValid(sender.Priv) || !IsChachaKeyValid(sender.Pub) {
		return ErrInvalidKey
	}

	return nil
}

// IsChachaKeyValid will return true if key size is the same as chacha20poly1305.keySize
// false otherwise.
func IsChachaKeyValid(key []byte) bool {
	return len(key) == chacha.KeySize
}

// KeyPair represents a private/public key pair.
type KeyPair struct {
	// Priv is a private key
	Priv []byte `json:"priv,omitempty"`
	// Pub is a public key
	Pub []byte `json:"pub,omitempty"`
}

// EncKeyPair represents a private/public encryption key pair.
type EncKeyPair struct {
	KeyPair `json:"keypair,omitempty"`
	// Alg is the encryption algorithm of keys enclosed in this key pair
	Alg EncryptionAlgorithm `json:"alg,omitempty"`
}

// SigKeyPair represents a private/public signature (verification) key pair.
type SigKeyPair struct {
	KeyPair `json:"keypair,omitempty"`
	// Alg is the signature algorithm of keys enclosed in this key pair
	Alg SignatureAlgorithm `json:"alg,omitempty"`
}

// MessagingKeys represents a pair of key pairs, one for encryption and one for signature
// usually stored in a KMS, it helps prevent converting signing keys into encryption ones
// TODO refactor this structure and all KeyPair handling as per issue #596.
type MessagingKeys struct {
	*EncKeyPair `json:"enckeypair,omitempty"`
	*SigKeyPair `json:"sigkeypair,omitempty"`
}

// isKeyPairValid is a utility function that validates a KeyPair.
func isKeyPairValid(kp KeyPair) bool {
	if kp.Priv == nil || kp.Pub == nil {
		return false
	}

	return true
}

// IsEncKeyPairValid is a utility function that validates an EncKeyPair.
func IsEncKeyPairValid(kp *EncKeyPair) bool {
	if !isKeyPairValid(kp.KeyPair) {
		return false
	}

	switch kp.Alg {
	case Curve25519:
		return true
	default:
		return false
	}
}

// IsSigKeyPairValid is a utility function that validates an EncKeyPair.
func IsSigKeyPairValid(kp *SigKeyPair) bool {
	if !isKeyPairValid(kp.KeyPair) {
		return false
	}

	switch kp.Alg {
	case EdDSA:
		return true
	default:
		return false
	}
}

// IsMessagingKeysValid is a utility function that validates a KeyPair.
func IsMessagingKeysValid(kpb *MessagingKeys) bool {
	if !IsSigKeyPairValid(kpb.SigKeyPair) || !IsEncKeyPairValid(kpb.EncKeyPair) {
		return false
	}

	return true
}

// Derive25519KEK is a utility function that will derive an ephemeral
// symmetric key (kek) using fromPrivKey and toPubKey.
func Derive25519KEK(alg, apu []byte, fromPrivKey, toPubKey *[chacha.KeySize]byte) ([]byte, error) {
	if fromPrivKey == nil || toPubKey == nil {
		return nil, ErrInvalidKey
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

	// length prefix apv (empty)
	apvInfo := LengthPrefix(nil)

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

// ErrKeyNotFound is returned when key not found.
var ErrKeyNotFound = errors.New("key not found")

// ErrInvalidKey is used when a key is invalid.
var ErrInvalidKey = errors.New("invalid key")
