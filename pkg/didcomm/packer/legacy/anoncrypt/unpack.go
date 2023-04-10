/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anoncryt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/btcsuite/btcutil/base58"
	chacha "golang.org/x/crypto/chacha20poly1305"

	"github.com/hyperledger/aries-framework-go/pkg/doc/util/jwkkid"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
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

	if protectedData.Alg != anonCrypt {
		return nil, fmt.Errorf("message format %s not supported", protectedData.Alg)
	}

	keys, err := getCEK(protectedData.Recipients, p.kms)
	if err != nil {
		return nil, err
	}

	cek, recKey := keys.cek, keys.myKey

	data, err := p.decodeCipherText(cek, &envelopeData)

	return &transport.Envelope{
		Message: data,
		ToKey:   recKey,
	}, err
}

type keys struct {
	cek   *[chacha.KeySize]byte
	myKey []byte
}

func getCEK(recipients []recipient, km kms.KeyManager) (*keys, error) {
	var candidateKeys []string

	for _, candidate := range recipients {
		candidateKeys = append(candidateKeys, candidate.Header.KID)
	}

	recKeyIdx, err := findVerKey(km, candidateKeys)
	if err != nil {
		return nil, fmt.Errorf("getCEK: no key accessible %w", err)
	}

	recip := recipients[recKeyIdx]
	recKey := base58.Decode(recip.Header.KID)

	encCEK, err := base64.URLEncoding.DecodeString(recip.EncryptedKey)
	if err != nil {
		return nil, err
	}

	b, err := newCryptoBox(km)
	if err != nil {
		return nil, err
	}

	cekSlice, err := b.SealOpen(encCEK, recKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt CEK: %w", err)
	}

	var cek [chacha.KeySize]byte

	copy(cek[:], cekSlice)

	return &keys{
		cek:   &cek,
		myKey: recKey,
	}, nil
}

func findVerKey(km kms.KeyManager, candidateKeys []string) (int, error) {
	var errs []error

	for i, key := range candidateKeys {
		recKID, err := jwkkid.CreateKID(base58.Decode(key), kms.ED25519Type)
		if err != nil {
			return -1, err
		}

		_, err = km.Get(recKID)
		if err == nil {
			return i, nil
		}

		errs = append(errs, err)
	}

	return -1, fmt.Errorf("none of the recipient keys were found in kms: %v", errs)
}

// decodeCipherText decodes (from base64) and decrypts the ciphertext using chacha20poly1305.
func (p *Packer) decodeCipherText(cek *[chacha.KeySize]byte, envelope *legacyEnvelope) ([]byte, error) {
	var cipherText, nonce, tag, aad, message []byte
	aad = []byte(envelope.Protected)

	cipherText, err := base64.URLEncoding.DecodeString(envelope.CipherText)
	if err != nil {
		return nil, fmt.Errorf("decodeCipherText: failed to decode b64Sender: %w", err)
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
