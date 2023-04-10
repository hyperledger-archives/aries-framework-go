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
	"golang.org/x/crypto/poly1305"

	"github.com/hyperledger/aries-framework-go/pkg/doc/util/jwkkid"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/webkms"
)

var logger = log.New("aries-framework/pkg/didcomm/packer/legacy")

// Pack will encode the payload argument
// Using the protocol defined by Aries RFC 0019.
func (p *Packer) Pack(_ string, payload, sender []byte, recipientPubKeys [][]byte) ([]byte, error) {
	var err error

	if len(recipientPubKeys) == 0 {
		return nil, errors.New("empty recipients keys, must have at least one recipient")
	}

	nonce := make([]byte, chacha.NonceSize)

	_, err = p.randSource.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("pack: failed to generate random nonce: %w", err)
	}

	// cek (content encryption key) is a symmetric key, for chacha20, a symmetric cipher
	cek := &[chacha.KeySize]byte{}

	_, err = p.randSource.Read(cek[:])
	if err != nil {
		return nil, fmt.Errorf("pack: failed to generate cek: %w", err)
	}

	var recipients []recipient

	recipients, err = p.buildRecipients(cek, sender, recipientPubKeys)
	if err != nil {
		return nil, fmt.Errorf("pack: failed to build recipients: %w", err)
	}

	header := protected{
		Enc:        "chacha20poly1305_ietf",
		Typ:        encodingType,
		Alg:        "Authcrypt",
		Recipients: recipients,
	}

	return p.buildEnvelope(nonce, payload, cek[:], &header)
}

func (p *Packer) buildEnvelope(nonce, payload, cek []byte, header *protected) ([]byte, error) {
	protectedBytes, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}

	protectedB64 := base64.URLEncoding.EncodeToString(protectedBytes)

	chachaCipher, err := chacha.New(cek)
	if err != nil {
		return nil, err
	}

	// 	Additional data is b64encode(jsonencode(header))
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

func (p *Packer) buildRecipients(cek *[chacha.KeySize]byte, senderKey []byte, recPubKeys [][]byte) ([]recipient, error) { // nolint: lll
	encodedRecipients := make([]recipient, 0)

	for _, recKey := range recPubKeys {
		rec, err := p.buildRecipient(cek, senderKey, recKey)
		if err != nil {
			logger.Warnf("buildRecipients: failed to build recipient: %w", err)

			continue
		}

		encodedRecipients = append(encodedRecipients, *rec)
	}

	if len(encodedRecipients) == 0 {
		return nil, fmt.Errorf("recipients keys are empty")
	}

	return encodedRecipients, nil
}

// buildRecipient encodes the necessary data for the recipient to decrypt the message
// encrypting the CEK and sender Pub key.
func (p *Packer) buildRecipient(cek *[chacha.KeySize]byte, senderKey, recKey []byte) (*recipient, error) { // nolint: lll
	var nonce [24]byte

	_, err := p.randSource.Read(nonce[:])
	if err != nil {
		return nil, fmt.Errorf("buildRecipient: failed to generate random nonce: %w", err)
	}

	senderKID, err := jwkkid.CreateKID(senderKey, kms.ED25519Type)
	if err != nil {
		return nil, fmt.Errorf("buildRecipient: failed to create KID for public key: %w", err)
	}

	recEncKey, err := cryptoutil.PublicEd25519toCurve25519(recKey)
	if err != nil {
		return nil, fmt.Errorf("buildRecipient: failed to convert public Ed25519 to Curve25519: %w", err)
	}

	box, err := newCryptoBox(p.kms)
	if err != nil {
		return nil, fmt.Errorf("buildRecipient: failed to create new CryptoBox: %w", err)
	}

	encCEK, err := box.Easy(cek[:], nonce[:], recEncKey, senderKID)
	if err != nil {
		return nil, fmt.Errorf("buildRecipient: failed to encrypt cek: %w", err)
	}

	// assumption: senderKey is ed25519
	encSender, err := box.Seal([]byte(base58.Encode(senderKey)), recEncKey, p.randSource)
	if err != nil {
		return nil, fmt.Errorf("buildRecipient: failed to encrypt sender key: %w", err)
	}

	return &recipient{
		EncryptedKey: base64.URLEncoding.EncodeToString(encCEK),
		Header: recipientHeader{
			KID:    base58.Encode(recKey), // recKey is the Ed25519 recipient pk in b58 encoding
			Sender: base64.URLEncoding.EncodeToString(encSender),
			IV:     base64.URLEncoding.EncodeToString(nonce[:]),
		},
	}, nil
}

func newCryptoBox(manager kms.KeyManager) (kms.CryptoBox, error) {
	switch manager.(type) {
	case *localkms.LocalKMS:
		return localkms.NewCryptoBox(manager)
	case *webkms.RemoteKMS:
		return webkms.NewCryptoBox(manager)
	default:
		return localkms.NewCryptoBox(manager)
	}
}
