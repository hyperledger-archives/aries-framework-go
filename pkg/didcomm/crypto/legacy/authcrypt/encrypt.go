/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package authcrypt

import (
	"encoding/base64"
	"encoding/json"

	"github.com/btcsuite/btcutil/base58"
	chacha "golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/poly1305"
)

// Encrypt will encode the payload argument
// Using the protocol defined by Aries RFC 0019
func (c *Crypter) Encrypt(payload []byte) ([]byte, error) {
	var err error

	nonce := make([]byte, chacha.NonceSize)
	_, err = c.randSource.Read(nonce)
	if err != nil {
		return nil, err
	}

	// cek (content encryption key) is a symmetric key, for chacha20, a symmetric cipher
	_, cek, err := box.GenerateKey(c.randSource)
	if err != nil {
		return nil, err
	}

	chachaCipher, err := chacha.New(cek[:])
	if err != nil {
		return nil, err
	}

	var recipients []recipient

	recipients, err = c.buildRecipients(cek)
	if err != nil {
		return nil, err
	}

	protectedBytes, err := c.buildProtected(recipients)
	if err != nil {
		return nil, err
	}

	AAD := base64.URLEncoding.EncodeToString(protectedBytes)

	// 	Additional data is b64encode(jsonencode(protected))
	symPld := chachaCipher.Seal(nil, nonce, payload, []byte(AAD))

	// symPld has a length of len(pld) + poly1035.TagSize
	// fetch the tag from the tail
	tag := symPld[len(symPld)-poly1305.TagSize:]
	// fetch the cipherText from the head (0:up to the trailing tag)
	cipherText := symPld[0 : len(symPld)-poly1305.TagSize]

	env := c.buildEnvelope(protectedBytes, nonce, cipherText, tag)
	out, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}

	return out, nil
}

// buildEnvelope builds the Envelope following the legacy format
func (c *Crypter) buildEnvelope(protectedBytes, nonce, cipherText, tag []byte) envelope {
	return envelope{
		Protected:  base64.URLEncoding.EncodeToString(protectedBytes),
		IV:         base64.URLEncoding.EncodeToString(nonce),
		CipherText: base64.URLEncoding.EncodeToString(cipherText),
		Tag:        base64.URLEncoding.EncodeToString(tag),
	}
}

func (c *Crypter) buildProtected(recipients []recipient) ([]byte, error) {
	protectedHeader := protected{
		Enc:        "chacha20poly1305_ietf",
		Typ:        "JWM/1.0",
		Alg:        "Authcrypt",
		Recipients: recipients,
	}

	protectedBytes, err := json.Marshal(protectedHeader)
	if err != nil {
		return nil, err
	}

	return protectedBytes, nil
}

func (c *Crypter) buildRecipients(cek *[chacha.KeySize]byte) ([]recipient, error) {
	var encodedRecipients []recipient

	for _, recKey := range c.recipients {
		recipient, err := c.buildRecipient(cek, recKey)
		if err != nil {
			return nil, err
		}

		encodedRecipients = append(encodedRecipients, *recipient)
	}

	return encodedRecipients, nil
}

// buildRecipient encodes the necessary data for the recipient to decrypt the message
// 	encrypting the CEK and sender pub key
func (c *Crypter) buildRecipient(cek *[chacha.KeySize]byte, recKey *publicEd25519) (*recipient, error) {
	var nonce [24]byte

	_, err := c.randSource.Read(nonce[:])
	if err != nil {
		return nil, err
	}

	senderSKCurve, err := secretEd25519toCurve25519(c.sender.priv)
	if err != nil {
		return nil, err
	}

	recPKCurve, err := publicEd25519toCurve25519(recKey)
	if err != nil {
		return nil, err
	}

	encCEK := box.Seal(nil, cek[:], &nonce, (*[CurveKeySize]byte)(recPKCurve), (*[CurveKeySize]byte)(senderSKCurve))

	var encSender []byte
	encSender, err = sodiumBoxSeal([]byte(base58.Encode(c.sender.pub[:])), recPKCurve, c.randSource)
	if err != nil {
		return nil, err
	}

	return &recipient{
		EncryptedKey: base64.URLEncoding.EncodeToString(encCEK),
		Header: recipientHeader{
			KID:    base58.Encode(recKey[:]), // recKey is the Ed25519 pk
			Sender: base64.URLEncoding.EncodeToString(encSender),
			IV:     base64.URLEncoding.EncodeToString(nonce[:]),
		},
	}, nil
}
