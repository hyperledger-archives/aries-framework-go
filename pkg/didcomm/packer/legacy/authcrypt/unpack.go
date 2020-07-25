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

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/transport"
	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
)

// Unpack will decode the envelope using the legacy format
// Using (X)Chacha20 encryption algorithm and Poly1035 authenticator.
func (p *Packer) Unpack(envelope []byte) (*transport.Envelope, error) {
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

	if protectedData.Typ != encodingType {
		return nil, fmt.Errorf("message type %s not supported", protectedData.Typ)
	}

	if protectedData.Alg != "Authcrypt" {
		// TODO https://github.com/hyperledger/aries-framework-go/issues/41 change this when anoncrypt is introduced
		return nil, fmt.Errorf("message format %s not supported", protectedData.Alg)
	}

	keys, err := getCEK(protectedData.Recipients, p.legacyKMS)
	if err != nil {
		return nil, err
	}

	cek, senderKey, recKey := keys.cek, keys.theirKey, keys.myKey

	data, err := p.decodeCipherText(cek, &envelopeData)

	return &transport.Envelope{
		Message:    data,
		FromVerKey: senderKey,
		ToVerKey:   recKey,
	}, err
}

type keys struct {
	cek      *[chacha.KeySize]byte
	theirKey []byte
	myKey    []byte
}

func getCEK(recipients []recipient, km legacykms.KeyManager) (*keys, error) {
	var candidateKeys []string

	for _, candidate := range recipients {
		candidateKeys = append(candidateKeys, candidate.Header.KID)
	}

	recKeyIdx, err := km.FindVerKey(candidateKeys)
	if err != nil {
		return nil, fmt.Errorf("no key accessible %w", err)
	}

	recip := recipients[recKeyIdx]
	recKey := base58.Decode(recip.Header.KID)

	recCurvePub, err := km.ConvertToEncryptionKey(recKey)
	if err != nil {
		return nil, err
	}

	senderPub, senderPubCurve, err := decodeSender(recip.Header.Sender, recCurvePub, km)
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

	b, err := legacykms.NewCryptoBox(km)
	if err != nil {
		return nil, err
	}

	cekSlice, err := b.EasyOpen(encCEK, nonceSlice, senderPubCurve, recCurvePub)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt CEK: %s", err)
	}

	var cek [chacha.KeySize]byte

	copy(cek[:], cekSlice)

	return &keys{
		cek:      &cek,
		theirKey: senderPub,
		myKey:    recKey,
	}, nil
}

func decodeSender(b64Sender string, pk []byte, km legacykms.KeyManager) ([]byte, []byte, error) {
	encSender, err := base64.URLEncoding.DecodeString(b64Sender)
	if err != nil {
		return nil, nil, err
	}

	b, err := legacykms.NewCryptoBox(km)
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

// decodeCipherText decodes (from base64) and decrypts the ciphertext using chacha20poly1305.
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
