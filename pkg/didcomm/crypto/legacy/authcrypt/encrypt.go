/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package authcrypt

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/btcsuite/btcutil/base58"
	chacha "golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/poly1305"

	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
)

// Encrypt will encode the payload argument
// Using the protocol defined by Aries RFC 0019
func (c *Crypter) Encrypt(payload []byte, sender cryptoutil.KeyPair, recipientPubKeys [][]byte) ([]byte, error) {
	var err error

	if len(recipientPubKeys) == 0 {
		return nil, errors.New("empty recipients keys, must have at least one recipient")
	}

	recipientEdKeys := []*publicEd25519{}
	for _, key := range recipientPubKeys {
		if len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("recipient key has invalid size %d", len(key))
		}
		edKey := new(publicEd25519)
		copy(edKey[:], key)
		recipientEdKeys = append(recipientEdKeys, edKey)
	}

	edSender, err := keyToEdKey(sender)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt, sender %s", err.Error())
	}

	nonce := make([]byte, chacha.NonceSize)
	_, err = c.randSource.Read(nonce)
	if err != nil {
		return nil, err
	}

	// cek (content encryption key) is a symmetric key, for chacha20, a symmetric cipher
	cek := &[chacha.KeySize]byte{}
	_, err = c.randSource.Read(cek[:])
	if err != nil {
		return nil, err
	}

	var recipients []recipient

	recipients, err = c.buildRecipients(cek, edSender, recipientEdKeys)
	if err != nil {
		return nil, err
	}

	p := protected{
		Enc:        "chacha20poly1305_ietf",
		Typ:        "JWM/1.0",
		Alg:        "Authcrypt",
		Recipients: recipients,
	}

	return c.buildEnvelope(nonce, payload, cek[:], &p)
}

func (c *Crypter) buildEnvelope(nonce, payload, cek []byte, protected *protected) ([]byte, error) {
	protectedBytes, err := json.Marshal(protected)
	if err != nil {
		return nil, err
	}

	protectedB64 := base64.URLEncoding.EncodeToString(protectedBytes)

	chachaCipher, err := chacha.New(cek)
	if err != nil {
		return nil, err
	}

	// 	Additional data is b64encode(jsonencode(protected))
	symPld := chachaCipher.Seal(nil, nonce, payload, []byte(protectedB64))

	// symPld has a length of len(pld) + poly1305.TagSize
	// fetch the tag from the tail
	tag := symPld[len(symPld)-poly1305.TagSize:]
	// fetch the cipherText from the head (0:up to the trailing tag)
	cipherText := symPld[0 : len(symPld)-poly1305.TagSize]

	env := legacyEnvelope{
		Protected:  protectedB64,
		IV:         base64.URLEncoding.EncodeToString(nonce),
		CipherText: base64.URLEncoding.EncodeToString(cipherText),
		Tag:        base64.URLEncoding.EncodeToString(tag),
	}
	out, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}

	return out, nil
}

func (c *Crypter) buildRecipients(cek *[chacha.KeySize]byte, senderKey *keyPairEd25519, recPubKeys []*publicEd25519) ([]recipient, error) { // nolint: lll
	var encodedRecipients []recipient

	for _, recKey := range recPubKeys {
		recipient, err := c.buildRecipient(cek, senderKey, recKey)
		if err != nil {
			return nil, err
		}

		encodedRecipients = append(encodedRecipients, *recipient)
	}

	return encodedRecipients, nil
}

// buildRecipient encodes the necessary data for the recipient to decrypt the message
// 	encrypting the CEK and sender Pub key
func (c *Crypter) buildRecipient(cek *[chacha.KeySize]byte, senderKey *keyPairEd25519, recKey *publicEd25519) (*recipient, error) { // nolint: lll
	var nonce [24]byte

	_, err := c.randSource.Read(nonce[:])
	if err != nil {
		return nil, err
	}

	senderSKCurve, err := secretEd25519toCurve25519(senderKey.Priv)
	if err != nil {
		return nil, err
	}

	recPKCurve, err := publicEd25519toCurve25519(recKey)
	if err != nil {
		return nil, err
	}

	encCEK := box.Seal(nil, cek[:], &nonce, (*[CurveKeySize]byte)(recPKCurve), (*[CurveKeySize]byte)(senderSKCurve))

	var encSender []byte
	encSender, err = sodiumBoxSeal([]byte(base58.Encode(senderKey.Pub[:])), recPKCurve, c.randSource)
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
