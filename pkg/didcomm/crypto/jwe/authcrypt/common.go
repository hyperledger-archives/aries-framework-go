/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package authcrypt

import (
	"crypto"
	"crypto/cipher"
	"encoding/binary"
	"errors"

	josecipher "github.com/square/go-jose/v3/cipher"
	chacha "golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// createCipher will create and return a new Chacha20Poly1035 cipher for the given nonceSize and symmetric key
func createCipher(nonceSize int, symKey []byte) (cipher.AEAD, error) {
	switch nonceSize {
	case chacha.NonceSize:
		return chacha.New(symKey)
	case chacha.NonceSizeX:
		return chacha.NewX(symKey)
	default:
		return nil, errors.New("cipher cannot be created with bad nonce size and shared symmetric Key combo")
	}
}

// lengthPrefix array with a bigEndian uint32 value of array's length
func lengthPrefix(array []byte) []byte {
	arrInfo := make([]byte, 4+len(array))
	binary.BigEndian.PutUint32(arrInfo, uint32(len(array)))
	copy(arrInfo[4:], array)
	return arrInfo
}

// generateKEK will generate an ephemeral symmetric key (kek) for the privKey/pubKey set to
// be used for encrypting a cek.
// it will return this new key along with the corresponding APU or an error if it fails.
func (c *Crypter) generateKEK(apu []byte, privKey, pubKey *[chacha.KeySize]byte) ([]byte, error) {
	// generating Z is inspired by sodium_crypto_scalarmult()
	// https://github.com/gamringer/php-authcrypt/blob/master/src/Crypt.php#L80

	// with z being a basePoint of a curve25519
	z := new([chacha.KeySize]byte)
	// do ScalarMult of the sender's private key with the recipient key to get a derived Z point
	// ( equivalent to derive an EC key )
	curve25519.ScalarMult(z, privKey, pubKey)

	// inspired by: github.com/square/go-jose/v3@v3.0.0-20190722231519-723929d55157/cipher/ecdh_es.go
	// -> DeriveECDHES() call
	// suppPubInfo is the encoded length of the recipient shared key output size in bits
	supPubInfo := make([]byte, 4)
	// since we're using chacha20poly1035 keys, keySize is known
	binary.BigEndian.PutUint32(supPubInfo, uint32(chacha.KeySize)*8)

	// as per https://tools.ietf.org/html/rfc7518#section-4.6.2
	// concatKDF requires info data to be length prefixed with BigEndian 32 bits type
	// length prefix alg
	algInfo := lengthPrefix([]byte(c.alg))

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
