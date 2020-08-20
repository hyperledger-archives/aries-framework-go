/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package authcrypt

import (
	"crypto/rand"
	"io"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

// Packer represents an Authcrypt Pack/Unpacker that outputs/reads legacy Aries envelopes.
type Packer struct {
	randSource io.Reader
	kms        kms.KeyManager
}

// encodingType is the `typ` string identifier in a message that identifies the format as being legacy.
const encodingType string = "JWM/1.0"

// New will create a Packer that encrypts messages using the legacy Aries format.
// Note: legacy Packer does not support XChacha20Poly1035 (XC20P), only Chacha20Poly1035 (C20P).
func New(ctx packer.Provider) *Packer {
	k := ctx.KMS()

	return &Packer{
		randSource: rand.Reader,
		kms:        k,
	}
}

// legacyEnvelope is the full payload envelope for the JSON message.
type legacyEnvelope struct {
	Protected  string `json:"protected,omitempty"`
	IV         string `json:"iv,omitempty"`
	CipherText string `json:"ciphertext,omitempty"`
	Tag        string `json:"tag,omitempty"`
}

// protected is the protected header of the JSON envelope.
type protected struct {
	Enc        string      `json:"enc,omitempty"`
	Typ        string      `json:"typ,omitempty"`
	Alg        string      `json:"alg,omitempty"`
	Recipients []recipient `json:"recipients,omitempty"`
}

// recipient holds the data for a recipient in the envelope header.
type recipient struct {
	EncryptedKey string          `json:"encrypted_key,omitempty"`
	Header       recipientHeader `json:"header,omitempty"`
}

// recipientHeader holds the header data for a recipient.
type recipientHeader struct {
	KID    string `json:"kid,omitempty"`
	Sender string `json:"sender,omitempty"`
	IV     string `json:"iv,omitempty"`
}

// EncodingType returns the type of the encoding, as in the `Typ` field of the envelope header.
func (p *Packer) EncodingType() string {
	return encodingType
}
