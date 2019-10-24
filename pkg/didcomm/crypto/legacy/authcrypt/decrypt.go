/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package authcrypt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/btcsuite/btcutil/base58"
	chacha "golang.org/x/crypto/chacha20poly1305"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/operator/box"
	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
)

// Decrypt will decode the envelope using the legacy format
// Using (X)Chacha20 encryption algorithm and Poly1035 authenticator
func (c *Crypter) Decrypt(envelope []byte) ([]byte, error) {
	var envelopeData legacyEnvelope
	err := json.Unmarshal(envelope, &envelopeData)
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

	cek, err := getCEK(protectedData.Recipients, c.wallet)
	if err != nil {
		return nil, err
	}

	return c.decodeCipherText(cek, &envelopeData)
}

func getCEK(recipients []recipient, w legacyWallet) (*[chacha.KeySize]byte, error) {
	var candidateKeys []string

	for _, candidate := range recipients {
		candidateKeys = append(candidateKeys, candidate.Header.KID)
	}

	recKeyIdx, err := w.FindVerKey(candidateKeys)
	if err != nil {
		return nil, fmt.Errorf("no key accessible %w", err)
	}

	recip := recipients[recKeyIdx]
	recKey := recip.Header.KID

	recCurvePub, err := cryptoutil.PublicEd25519toCurve25519(base58.Decode(recKey))
	if err != nil {
		return nil, err
	}

	cryptoBox, err := box.New(w)
	if err != nil {
		return nil, err
	}

	sender, err := decodeSender(recip.Header.Sender, recCurvePub, cryptoBox)
	if err != nil {
		return nil, err
	}

	nonceSlice, err := base64.URLEncoding.DecodeString(recip.Header.IV)
	if err != nil {
		return nil, err
	}

	encCEK, err := base64.URLEncoding.DecodeString(recip.EncryptedKey)
	if err != nil {
		return nil, err
	}

	cekSlice, err := cryptoBox.EasyOpen(encCEK, nonceSlice, sender, recCurvePub)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt CEK: %s", err)
	}

	var cek [chacha.KeySize]byte
	copy(cek[:], cekSlice)

	return &cek, nil
}

func decodeSender(b64Sender string, pk []byte, cryptoBox *box.CryptoBox) ([]byte, error) {
	encSender, err := base64.URLEncoding.DecodeString(b64Sender)
	if err != nil {
		return nil, err
	}

	senderSlice, err := cryptoBox.SealOpen(encSender, pk)
	if err != nil {
		return nil, err
	}

	senderData := base58.Decode(string(senderSlice))

	return cryptoutil.PublicEd25519toCurve25519(senderData)
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
