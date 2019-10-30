/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package authcrypt

import (
	"crypto/rand"
	"io"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

// Crypter represents an Authcrypt Encrypter (Decrypter) that outputs/reads legacy Aries envelopes
type Crypter struct {
	randSource io.Reader
	wallet     wallet.Crypto
}

// New will create a Crypter that encrypts messages using the legacy Aries format
// Note: legacy crypter does not support XChacha20Poly1035 (XC20P), only Chacha20Poly1035 (C20P)
func New(ctx crypto.Provider) *Crypter {
	w := ctx.CryptoWallet()

	return &Crypter{
		randSource: rand.Reader,
		wallet:     w,
	}
}

// legacyEnvelope is the full payload envelope for the JSON message
type legacyEnvelope struct {
	Protected  string `json:"protected,omitempty"`
	IV         string `json:"iv,omitempty"`
	CipherText string `json:"ciphertext,omitempty"`
	Tag        string `json:"tag,omitempty"`
}

// protected is the protected header of the JSON envelope
type protected struct {
	Enc        string      `json:"enc,omitempty"`
	Typ        string      `json:"typ,omitempty"`
	Alg        string      `json:"alg,omitempty"`
	Recipients []recipient `json:"recipients,omitempty"`
}

// recipient holds the data for a recipient in the envelope header
type recipient struct {
	EncryptedKey string          `json:"encrypted_key,omitempty"`
	Header       recipientHeader `json:"header,omitempty"`
}

// recipientHeader holds the header data for a recipient
type recipientHeader struct {
	KID    string `json:"kid,omitempty"`
	Sender string `json:"sender,omitempty"`
	IV     string `json:"iv,omitempty"`
}
