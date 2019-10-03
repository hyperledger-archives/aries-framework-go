/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package authcrypt

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/crypto"

	"github.com/btcsuite/btcutil/base58"
	chacha "golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/nacl/box"
)

// Decrypt will decode the envelope using the legacy format
// Using (X)Chacha20 encryption algorithm and Poly1035 authenticator
func (c *Crypter) Decrypt(envelope []byte, recipient crypto.KeyPair) ([]byte, error) {
	edRecipient, err := keyToEdKey(recipient)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt, recipient %s", err.Error())
	}

	var envelopeData legacyEnvelope
	err = json.Unmarshal(envelope, &envelopeData)
	if err != nil {
		return nil, err
	}

	protectedBytes, err := base64.URLEncoding.DecodeString(envelopeData.Protected)
	if err != nil {
		return nil, err
	}

	var protectedData protected
	err = json.Unmarshal(protectedBytes, &protectedData)
	if err != nil {
		return nil, err
	}

	if protectedData.Typ != "JWM/1.0" {
		return nil, fmt.Errorf("message type %s not supported", protectedData.Typ)
	}

	if protectedData.Alg != "Authcrypt" {
		// TODO: change this when anoncrypt is introduced
		return nil, fmt.Errorf("message format %s not supported", protectedData.Alg)
	}

	cek, err := getCEK(protectedData.Recipients, edRecipient)
	if err != nil {
		return nil, err
	}

	return c.decodeCipherText(cek, &envelopeData)
}

func getCEK(recipients []recipient, recKey *keyPairEd25519) (*[chacha.KeySize]byte, error) {
	for _, candidate := range recipients {
		header := candidate.Header
		pubKey := base58.Decode(header.KID)

		if !bytes.Equal(pubKey, recKey.Pub[:]) {
			continue
		}

		pk, err := publicEd25519toCurve25519(recKey.Pub)
		if err != nil {
			return nil, err
		}
		sk, err := secretEd25519toCurve25519(recKey.Priv)
		if err != nil {
			return nil, err
		}

		sender, err := decodeSender(header.Sender, pk, sk)
		if err != nil {
			return nil, err
		}

		nonceSlice, err := base64.URLEncoding.DecodeString(header.IV)
		if err != nil {
			return nil, err
		}
		var nonce [24]byte
		copy(nonce[:], nonceSlice)

		encCEK, err := base64.URLEncoding.DecodeString(candidate.EncryptedKey)
		if err != nil {
			return nil, err
		}

		cekSlice, success := box.Open(nil, encCEK, &nonce, (*[CurveKeySize]byte)(sender), (*[CurveKeySize]byte)(sk))
		if !success {
			return nil, errors.New("failed to decrypt CEK")
		}

		var cek [chacha.KeySize]byte
		copy(cek[:], cekSlice)

		return &cek, nil
	}

	return nil, errors.New("no key accessible")
}

func decodeSender(b64Sender string, pk *publicCurve25519, sk *privateCurve25519) (*publicCurve25519, error) {
	encSender, err := base64.URLEncoding.DecodeString(b64Sender)
	if err != nil {
		return nil, err
	}

	senderSlice, err := sodiumBoxSealOpen(encSender, pk, sk)
	if err != nil {
		return nil, err
	}

	senderData := base58.Decode(string(senderSlice))

	var senderEdPub [ed25519.PublicKeySize]byte
	copy(senderEdPub[:], senderData)

	sender, err := publicEd25519toCurve25519((*publicEd25519)(&senderEdPub))
	if err != nil {
		return nil, err
	}

	return sender, nil
}

// decodeCipherText decodes (from base64) and decrypts the ciphertext using chacha20poly1305
func (c *Crypter) decodeCipherText(cek *[chacha.KeySize]byte, envelope *legacyEnvelope) ([]byte, error) {
	var cipherText, nonce, tag, aad, message []byte
	aad = []byte(envelope.Protected)
	cipherText, err := base64.URLEncoding.DecodeString(envelope.CipherText)
	if err != nil {
		return nil, err
	}
	nonce, err = base64.URLEncoding.DecodeString(envelope.IV)
	if err != nil {
		return nil, err
	}
	tag, err = base64.URLEncoding.DecodeString(envelope.Tag)
	if err != nil {
		return nil, err
	}

	chachaCipher, err := chacha.New(cek[:])
	if err != nil {
		return nil, err
	}

	payload := append(cipherText, tag...)

	message, err = chachaCipher.Open(nil, nonce, payload, aad)
	if err != nil {
		return nil, err
	}

	return message, nil
}

// Open a box sealed by sodiumBoxSeal
func sodiumBoxSealOpen(msg []byte, recPub *publicCurve25519, recPriv *privateCurve25519) ([]byte, error) {
	if len(msg) < 32 {
		return nil, errors.New("message too short")
	}
	var epk [32]byte
	copy(epk[:], msg[:32])

	var nonce [24]byte
	nonceSlice, err := makeNonce(epk[:], recPub[:])
	if err != nil {
		return nil, err
	}
	copy(nonce[:], nonceSlice)

	out, success := box.Open(nil, msg[32:], &nonce, &epk, (*[32]byte)(recPriv))
	if !success {
		return nil, errors.New("failed to unpack")
	}

	return out, nil
}
