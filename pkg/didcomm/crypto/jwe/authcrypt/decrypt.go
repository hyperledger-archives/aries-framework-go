/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package authcrypt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/btcsuite/btcutil/base58"
	chacha "golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/nacl/box"

	jwecrypto "github.com/hyperledger/aries-framework-go/pkg/didcomm/crypto"
)

// Decrypt will JWE decode the envelope argument for the recipientPrivKey and validates
// the envelope's recipients has a match for recipientKeyPair.Pub key.
// Using (X)Chacha20 cipher and Poly1035 authenticator for the encrypted payload and
// encrypted CEK
// And Using (x)Salsa20 cipher with 25519 keys (libsodium equivalent) for decrypting
// the sender's public key in the current recipient's header.
// The current recipient is the one with the sender's encrypted key that successfully
// decrypts with recipientKeyPair.Priv Key.
func (c *Crypter) Decrypt(envelope []byte, recipientKeyPair jwecrypto.KeyPair) ([]byte, error) { //nolint:lll,funlen
	if !jwecrypto.IsKeyPairValid(recipientKeyPair) {
		return nil, errInvalidKeypair
	}

	jwe := &Envelope{}
	err := json.Unmarshal(envelope, jwe)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt message: %w", err)
	}
	pubK := new([chacha.KeySize]byte)
	copy(pubK[:], recipientKeyPair.Pub)
	recipient, err := c.findRecipient(jwe.Recipients, pubK)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt message: %w", err)
	}
	var oid []byte

	// TODO replace oid with JWK wrapped in spk recipient header
	cryptedOID, err := base64.RawURLEncoding.DecodeString(recipient.Header.OID)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt message: %w", err)
	}
	recPubKey := base58.Decode(recipient.Header.KID)
	var recipientPubKey [chacha.KeySize]byte
	copy(recipientPubKey[:], recPubKey)

	privK := new([chacha.KeySize]byte)
	copy(privK[:], recipientKeyPair.Priv)
	oid, err = decryptOID(privK, &recipientPubKey, cryptedOID)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt sender key: %w", err)
	}
	// if oid is found, it means decrypting the sender's public key with this recipient is successful
	// proceed with decrypting the recipient's shared key and use it to decrypt the JWE's real payload
	if oid != nil {
		senderKey := base58.Decode(string(oid))
		var senderPubKey [chacha.KeySize]byte
		copy(senderPubKey[:], senderKey)

		sharedKey, er := c.decryptSharedKey(jwecrypto.KeyPair{Priv: recipientKeyPair.Priv, Pub: recPubKey},
			&senderPubKey, recipient)
		if er != nil {
			return nil, fmt.Errorf("failed to decrypt shared key: %w", er)
		}

		symOutput, er := c.decryptPayload(sharedKey, jwe)
		if er != nil {
			return nil, fmt.Errorf("failed to decrypt message: %w", er)
		}

		return symOutput, nil
	}

	return nil, errors.New("failed to decrypt message - invalid sender key in envelope")
}

func (c *Crypter) decryptPayload(cek []byte, jwe *Envelope) ([]byte, error) {
	aad := retrieveAAD(jwe.Recipients)
	aadEncoded := base64.RawURLEncoding.EncodeToString(aad)
	if jwe.AAD != aadEncoded {
		return nil, errors.New("failed to decrypt message - invalid AAD in envelope")
	}

	crypter, er := createCipher(c.nonceSize, cek)
	if er != nil {
		return nil, er
	}

	pldAAD := jwe.Protected + "." + aadEncoded
	payload, er := base64.RawURLEncoding.DecodeString(jwe.CipherText)
	if er != nil {
		return nil, er
	}
	tag, er := base64.RawURLEncoding.DecodeString(jwe.Tag)
	if er != nil {
		return nil, er
	}
	nonce, er := base64.RawURLEncoding.DecodeString(jwe.IV)
	if er != nil {
		return nil, er
	}
	payload = append(payload, tag...)
	return crypter.Open(nil, nonce, payload, []byte(pldAAD))
}

func retrieveAAD(recipients []Recipient) []byte {
	var keys []string
	for _, rec := range recipients {
		keys = append(keys, rec.Header.KID)
	}
	return hashAAD(keys)
}

// findRecipient will loop through jweRecipients and returns the first matching key from recipients
func (c *Crypter) findRecipient(jweRecipients []Recipient, recipientPubKey *[chacha.KeySize]byte) (*Recipient, error) {
	for _, recipient := range jweRecipients {
		recipient := recipient // pin!
		if bytes.Equal(recipientPubKey[:], base58.Decode(recipient.Header.KID)) {
			return &recipient, nil
		}
	}
	return nil, errRecipientNotFound
}

func (c *Crypter) decryptSharedKey(recipientKp jwecrypto.KeyPair, senderPubKey *[chacha.KeySize]byte, recipient *Recipient) ([]byte, error) { //nolint:lll
	apu, err := base64.RawURLEncoding.DecodeString(recipient.Header.APU)
	if err != nil {
		return nil, err
	}

	nonce, err := base64.RawURLEncoding.DecodeString(recipient.Header.IV)
	if err != nil {
		return nil, err
	}
	if len(nonce) != c.nonceSize {
		return nil, errors.New("bad nonce size")
	}

	tag, err := base64.RawURLEncoding.DecodeString(recipient.Header.Tag)
	if err != nil {
		return nil, err
	}

	sharedEncryptedKey, err := base64.RawURLEncoding.DecodeString(recipient.EncryptedKey)
	if err != nil {
		return nil, err
	}

	privK := new([chacha.KeySize]byte)
	copy(privK[:], recipientKp.Priv)

	// create a new ephemeral key for the recipient and return its APU
	kek, err := c.generateRecipientCEK(apu, privK, senderPubKey)
	if err != nil {
		return nil, err
	}

	// create a new (chacha20poly1035) cipher with this new key to encrypt the shared key (cek)
	cipher, err := createCipher(c.nonceSize, kek)
	if err != nil {
		return nil, err
	}

	cipherText := sharedEncryptedKey
	cipherText = append(cipherText, tag...)

	return cipher.Open(nil, nonce, cipherText, nil)
}

// decryptOID will decrypt a recipient's encrypted OID (in the case of this package, it is represented as
// ephemeral key concatenated with the sender's public key) using the recipient's privKey/pubKey keypair,
// this is equivalent to libsodium's C function: crypto_box_seal_open()
// https://libsodium.gitbook.io/doc/public-key_cryptography/sealed_boxes#usage
// the returned decrypted value is the sender's public key base58 encoded
// TODO replace 'OID' to 'SPK' recipient header which should represent the key in JWK encoded in a compact JWE format
func decryptOID(recipientPrivKey, recipientPubKey *[chacha.KeySize]byte, encrypted []byte) ([]byte, error) {
	var epk [chacha.KeySize]byte
	copy(epk[:], encrypted[:chacha.KeySize])

	// generate an equivalent nonce to libsodium's (see link above)
	nonce, err := generateLibsodiumNonce(epk[:], recipientPubKey[:])
	if err != nil {
		return nil, err
	}

	decrypted, ok := box.Open(nil, encrypted[chacha.KeySize:], nonce, &epk, recipientPrivKey)
	if !ok {
		return nil, errors.New("sender public key decryption error")
	}
	return decrypted, nil
}
