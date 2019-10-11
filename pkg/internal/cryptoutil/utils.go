/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cryptoutil

import (
	"crypto"
	"encoding/binary"
	"errors"

	josecipher "github.com/square/go-jose/v3/cipher"
	chacha "golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// errEmptyRecipients is used when recipients list is empty
var errEmptyRecipients = errors.New("empty recipients")

// errInvalidKeypair is used when a keypair is invalid
var errInvalidKeypair = errors.New("invalid keypair")

// VerifyKeys is a utility function that verifies if sender key pair and recipients keys are valid (not empty)
func VerifyKeys(sender KeyPair, recipients [][]byte) error {
	if len(recipients) == 0 {
		return errEmptyRecipients
	}

	if !IsKeyPairValid(sender) {
		return errInvalidKeypair
	}

	if !IsChachaKeyValid(sender.Priv) || !IsChachaKeyValid(sender.Pub) {
		return ErrInvalidKey
	}
	return nil
}

// IsChachaKeyValid will return true if key size is the same as chacha20poly1305.keySize
// false otherwise
func IsChachaKeyValid(key []byte) bool {
	return len(key) == chacha.KeySize
}

// KeyPair represents a private/public key pair
type KeyPair struct {
	// Priv is a private key
	Priv []byte
	// Pub is a public key
	Pub []byte
}

// IsKeyPairValid is a utility function that validates a KeyPair
func IsKeyPairValid(kp KeyPair) bool {
	if kp.Priv == nil || kp.Pub == nil {
		return false
	}

	return true
}

// Derive25519KEK is a utility function that will derive an ephemeral symmetric key (kek) using fromPrivKey and toPubKey
func Derive25519KEK(alg, apu []byte, fromPrivKey, toPubKey *[chacha.KeySize]byte) ([]byte, error) { // nolint:lll
	if fromPrivKey == nil || toPubKey == nil {
		return nil, ErrInvalidKey
	}

	// generating Z is inspired by sodium_crypto_scalarmult()
	// https://github.com/gamringer/php-authcrypt/blob/master/src/Crypt.php#L80

	// with z being a basePoint of a curve25519
	z := new([chacha.KeySize]byte)
	// do ScalarMult of the sender's private key with the recipient key to get a derived Z point
	// ( equivalent to derive an EC key )
	curve25519.ScalarMult(z, fromPrivKey, toPubKey)

	// inspired by: github.com/square/go-jose/v3@v3.0.0-20190722231519-723929d55157/cipher/ecdh_es.go
	// -> DeriveECDHES() call
	// suppPubInfo is the encoded length of the recipient shared key output size in bits
	supPubInfo := make([]byte, 4)
	// since we're using chacha20poly1305 keys, keySize is known
	binary.BigEndian.PutUint32(supPubInfo, uint32(chacha.KeySize)*8)

	// as per https://tools.ietf.org/html/rfc7518#section-4.6.2
	// concatKDF requires info data to be length prefixed with BigEndian 32 bits type
	// length prefix alg
	algInfo := lengthPrefix(alg)

	// length prefix apu
	apuInfo := lengthPrefix(apu)

	// length prefix apv (empty)
	apvInfo := lengthPrefix(nil)

	// get a Concat KDF stream for z, encryption algorithm, api, supPubInfo and empty supPrivInfo using sha256
	reader := josecipher.NewConcatKDF(crypto.SHA256, z[:], algInfo, apuInfo, apvInfo, supPubInfo, []byte{})

	// kek is the recipient specific encryption key used to encrypt the sharedSymKey
	kek := make([]byte, chacha.KeySize)

	// Read on the KDF will never fail
	_, err := reader.Read(kek)
	if err != nil {
		return nil, err
	}

	return kek, nil
}

// lengthPrefix array with a bigEndian uint32 value of array's length
func lengthPrefix(array []byte) []byte {
	arrInfo := make([]byte, 4+len(array))
	binary.BigEndian.PutUint32(arrInfo, uint32(len(array)))
	copy(arrInfo[4:], array)
	return arrInfo
}

// ErrKeyNotFound is returned when key not found
var ErrKeyNotFound = errors.New("key not found")

// ErrInvalidKey is used when a key is invalid
var ErrInvalidKey = errors.New("invalid key")
