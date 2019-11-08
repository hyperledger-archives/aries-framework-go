/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package authcrypt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/btcsuite/btcutil/base58"
	chacha "golang.org/x/crypto/chacha20poly1305"
)

// Unpack will JWE decode the envelope argument for the recipientPrivKey and validates
// the envelope's recipients has a match for recipientKeyPair.Pub key.
// Using (X)Chacha20 cipher and Poly1305 authenticator for the encrypted payload and
// encrypted CEK.
// The current recipient is the one with the sender's encrypted key that successfully
// decrypts with recipientKeyPair.Priv Key.
func (p *Packer) Unpack(envelope []byte) ([]byte, error) {
	jwe := &Envelope{}

	err := json.Unmarshal(envelope, jwe)
	if err != nil {
		return nil, fmt.Errorf("unpack: %w", err)
	}

	recipientPubKey, recipient, err := p.findRecipient(jwe.Recipients)
	if err != nil {
		return nil, fmt.Errorf("unpack: %w", err)
	}

	senderKey, err := p.decryptSPK(recipientPubKey, recipient.Header.SPK)
	if err != nil {
		return nil, fmt.Errorf("unpack: sender key: %w", err)
	}

	// senderKey must not be empty to proceed
	if senderKey != nil {
		senderPubKey := new([chacha.KeySize]byte)
		copy(senderPubKey[:], senderKey)

		sharedKey, er := p.decryptCEK(recipientPubKey, senderPubKey, recipient)
		if er != nil {
			return nil, fmt.Errorf("unpack: decrypt shared key: %w", er)
		}

		symOutput, er := p.decryptPayload(sharedKey, jwe)
		if er != nil {
			return nil, fmt.Errorf("unpack: %w", er)
		}

		return symOutput, nil
	}

	return nil, errors.New("unpack: invalid sender key in envelope")
}

func (p *Packer) decryptPayload(cek []byte, jwe *Envelope) ([]byte, error) {
	cipher, err := createCipher(p.nonceSize, cek)
	if err != nil {
		return nil, err
	}

	pldAAD := jwe.Protected + "." + jwe.AAD

	payload, err := base64.RawURLEncoding.DecodeString(jwe.CipherText)
	if err != nil {
		return nil, err
	}

	tag, err := base64.RawURLEncoding.DecodeString(jwe.Tag)
	if err != nil {
		return nil, err
	}

	nonce, err := base64.RawURLEncoding.DecodeString(jwe.IV)
	if err != nil {
		return nil, err
	}

	payload = append(payload, tag...)

	return cipher.Open(nil, nonce, payload, []byte(pldAAD))
}

// findRecipient will loop through jweRecipients and returns the first matching key from the kms
func (p *Packer) findRecipient(jweRecipients []Recipient) (*[chacha.KeySize]byte, *Recipient, error) {
	var recipientsKeys []string
	for _, recipient := range jweRecipients {
		recipientsKeys = append(recipientsKeys, recipient.Header.KID)
	}

	i, err := p.kms.FindVerKey(recipientsKeys)
	if err != nil {
		return nil, nil, err
	}

	pubK := new([chacha.KeySize]byte)
	copy(pubK[:], base58.Decode(recipientsKeys[i]))

	return pubK, &jweRecipients[i], nil
}

// decryptCEK will decrypt the CEK found in recipient using recipientKp's private key and senderPubKey
func (p *Packer) decryptCEK(recipientPubKey, senderPubKey *[chacha.KeySize]byte, recipient *Recipient) ([]byte, error) { //nolint:lll
	apu, err := base64.RawURLEncoding.DecodeString(recipient.Header.APU)
	if err != nil {
		return nil, err
	}

	nonce, err := base64.RawURLEncoding.DecodeString(recipient.Header.IV)
	if err != nil {
		return nil, err
	}

	if len(nonce) != p.nonceSize {
		return nil, errors.New("bad nonce size")
	}

	tag, err := base64.RawURLEncoding.DecodeString(recipient.Header.Tag)
	if err != nil {
		return nil, err
	}

	encryptedCEK, err := base64.RawURLEncoding.DecodeString(recipient.EncryptedKey)
	if err != nil {
		return nil, err
	}

	// derive an ephemeral key for the recipient
	kek, err := p.kms.DeriveKEK([]byte(p.alg), apu, recipientPubKey[:], senderPubKey[:])
	if err != nil {
		return nil, err
	}

	// create a new (chacha20poly1305) cipher with this new key to decrypt the cek
	cipher, err := createCipher(p.nonceSize, kek)
	if err != nil {
		return nil, err
	}

	cipherText := encryptedCEK
	cipherText = append(cipherText, tag...)

	return cipher.Open(nil, nonce, cipherText, nil)
}
