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

	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

// Unpack will decode the envelope using the legacy format
// Using (X)Chacha20 encryption algorithm and Poly1035 authenticator
func (p *Packer) Unpack(envelope []byte) ([]byte, []byte, error) {
	var envelopeData legacyEnvelope

	err := json.Unmarshal(envelope, &envelopeData)
	if err != nil {
		return nil, nil, err
	}

	protectedBytes, err := base64.URLEncoding.DecodeString(envelopeData.Protected)
	if err != nil {
		return nil, nil, err
	}

	var protectedData protected

	err = json.Unmarshal(protectedBytes, &protectedData)
	if err != nil {
		return nil, nil, err
	}

	if protectedData.Typ != encodingType {
		return nil, nil, fmt.Errorf("message type %s not supported", protectedData.Typ)
	}

	if protectedData.Alg != "Authcrypt" {
		// TODO https://github.com/hyperledger/aries-framework-go/issues/41 change this when anoncrypt is introduced
		return nil, nil, fmt.Errorf("message format %s not supported", protectedData.Alg)
	}

	cek, recKey, err := getCEK(protectedData.Recipients, p.kms)
	if err != nil {
		return nil, nil, err
	}

	data, err := p.decodeCipherText(cek, &envelopeData)

	return data, recKey, err
}

func getCEK(recipients []recipient, km kms.KeyManager) (*[chacha.KeySize]byte, []byte, error) {
	var candidateKeys []string

	for _, candidate := range recipients {
		candidateKeys = append(candidateKeys, candidate.Header.KID)
	}

	recKeyIdx, err := km.FindVerKey(candidateKeys)
	if err != nil {
		return nil, nil, fmt.Errorf("no key accessible %w", err)
	}

	recip := recipients[recKeyIdx]
	recKey := recip.Header.KID

	recCurvePub, err := km.ConvertToEncryptionKey(base58.Decode(recKey))
	if err != nil {
		return nil, nil, err
	}

	senderPub, senderPubCurve, err := decodeSender(recip.Header.Sender, recCurvePub, km)
	if err != nil {
		return nil, nil, err
	}

	nonceSlice, err := base64.URLEncoding.DecodeString(recip.Header.IV)
	if err != nil {
		return nil, nil, err
	}

	encCEK, err := base64.URLEncoding.DecodeString(recip.EncryptedKey)
	if err != nil {
		return nil, nil, err
	}

	b, err := kms.NewCryptoBox(km)
	if err != nil {
		return nil, nil, err
	}

	cekSlice, err := b.EasyOpen(encCEK, nonceSlice, senderPubCurve, recCurvePub)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt CEK: %s", err)
	}

	var cek [chacha.KeySize]byte

	copy(cek[:], cekSlice)

	return &cek, senderPub, nil
}

func decodeSender(b64Sender string, pk []byte, km kms.KeyManager) ([]byte, []byte, error) {
	encSender, err := base64.URLEncoding.DecodeString(b64Sender)
	if err != nil {
		return nil, nil, err
	}

	b, err := kms.NewCryptoBox(km)
	if err != nil {
		return nil, nil, err
	}

	senderPub, err := b.SealOpen(encSender, pk)
	if err != nil {
		return nil, nil, err
	}

	senderData := base58.Decode(string(senderPub))

	senderPubCurve, err := cryptoutil.PublicEd25519toCurve25519(senderData)

	return senderData, senderPubCurve, err
}

// decodeCipherText decodes (from base64) and decrypts the ciphertext using chacha20poly1305
func (p *Packer) decodeCipherText(cek *[chacha.KeySize]byte, envelope *legacyEnvelope) ([]byte, error) {
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
