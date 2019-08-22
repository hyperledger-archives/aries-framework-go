/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package authcrypt

import (
	"encoding/json"
	"errors"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/nacl/box"
)

// Decrypt will JWE decode the envelope argument for the sender and recipients
// Using (X)Chacha20 encryption algorithm and Poly1035 authenticator
func (c *Crypter) Decrypt(envelope []byte, recipientPrivKey *[chacha20poly1305.KeySize]byte) ([]byte, error) {
	// TODO implement decryption and call decryptOID for the recipient's OID
	jwe := &Envelope{}
	err := json.Unmarshal(envelope, jwe)
	if err != nil {
		return nil, err
	}
	var oid []byte
	for _, recipient := range jwe.Recipients {

		oid, err = decryptOID(recipientPrivKey, c.sender.pub, []byte(recipient.Header.OID))
		if oid != nil {
			break
		}
	}

	return oid, err
}

// decryptOID will decrypt a recipient's encrypted OID (in the case of this package, it is represented as
// ephemeral key concatenated with the sender's public key) using the recipient's privKey/pubKey keypair,
// this is equivalent to libsodium's C function: crypto_box_seal()
// https://libsodium.gitbook.io/doc/public-key_cryptography/sealed_boxes#usage
func decryptOID(privKey, pubKey *[chacha20poly1305.KeySize]byte, encrypted []byte) ([]byte, error) {
	var epk [32]byte
	var nonce [24]byte
	copy(epk[:], encrypted[:chacha20poly1305.KeySize])

	nonceWriter, err := blake2b.New(24, nil)
	if err != nil {
		return nil, err
	}
	nonceSlice := nonceWriter.Sum(append(epk[:], pubKey[:]...))
	copy(nonce[:], nonceSlice)

	decrypted, ok := box.Open(nil, encrypted[32:], &nonce, &epk, privKey)
	if !ok {
		return nil, errors.New("decryption error")
	}
	return decrypted, nil
}
