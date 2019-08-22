/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package authcrypt

import (
	"crypto/rand"
	"fmt"

	errors "golang.org/x/xerrors"

	"golang.org/x/crypto/chacha20poly1305"
)

// This package deals with Authcrypt encryption for Packing/Unpacking DID Comm exchange
// Using Chacha20Poly1035 encryption/authentication

// ContentEncryption represents a content encryption algorithm.
type ContentEncryption string

// C20P Chacha20Poly1035 algorithm
const C20P = ContentEncryption("C20P") // Chacha20 encryption + Poly1035 authenticator cipher (96 bits nonce)

// XC20P XChacha20Poly1035 algorithm
const XC20P = ContentEncryption("XC20P") // XChacha20 encryption + Poly1035 authenticator cipher (192 bits nonce)

// randReader is a cryptographically secure random number generator.
var randReader = rand.Reader

type keyPair struct {
	priv *[chacha20poly1305.KeySize]byte
	pub  *[chacha20poly1305.KeySize]byte
}

// Crypter represents an Authcrypt Encrypter (Decrypter) that outputs/reads JWE envelopes
type Crypter struct {
	sender     keyPair
	recipients []*[chacha20poly1305.KeySize]byte
	alg        ContentEncryption
	nonceSize  int
}

// Envelope represents a JWE envelope as per the Aries Encryption envelope specs
type Envelope struct {
	Protected  string      `json:"protected,omitempty"`
	Recipients []Recipient `json:"recipients,omitempty"`
	AAD        string      `json:"aad,omitempty"`
	IV         string      `json:"iv,omitempty"`
	Tag        string      `json:"tag,omitempty"`
	CipherText string      `json:"ciphertext,omitempty"`
}

// jweHeaders are the Protected JWE headers in a map format
type jweHeaders map[string]string

// Recipient is a recipient of an envelope including the shared encryption key
type Recipient struct {
	EncryptedKey string           `json:"encrypted_key,omitempty"`
	Header       RecipientHeaders `json:"header,omitempty"`
}

// RecipientHeaders are the recipient headers
type RecipientHeaders struct {
	APU string `json:"apu,omitempty"`
	IV  string `json:"iv,omitempty"`
	Tag string `json:"tag,omitempty"`
	KID string `json:"kid,omitempty"`
	OID string `json:"oid,omitempty"`
}

// New will create an encrypter instance to 'AuthCrypt' payloads for the given sender and recipients arguments
// and the encryption alg argument. Possible algorithms supported are:
// C20P (chacha20-poly1035 ietf)
// XC20P (xchacha20-poly1035 ietf)
// The returned crypter contains all the information required to encrypt payloads.
func New(sender keyPair, recipients []*[chacha20poly1305.KeySize]byte, alg ContentEncryption) (*Crypter, error) {
	var nonceSize int
	switch alg {
	case C20P:
		nonceSize = chacha20poly1305.NonceSize
	case XC20P:
		nonceSize = chacha20poly1305.NonceSizeX
	default:
		return nil, errors.New(fmt.Sprintf("encryption algorithm '%s' not supported", alg))
	}
	if len(recipients) == 0 {
		return nil, errors.New("empty recipients keys, must have at least one recipient")
	}
	var recipientsKey []*[chacha20poly1305.KeySize]byte
	recipientsKey = append(recipientsKey, recipients...)

	c := &Crypter{
		sender,
		recipientsKey,
		alg,
		nonceSize,
	}

	if !isKeyPairValid(sender) {
		return nil, errors.New(fmt.Sprintf("sender keyPair not supported, it must have %d bytes keys", chacha20poly1305.KeySize))
	}

	return c, nil
}

func isKeyPairValid(kp keyPair) bool {
	if kp.priv == nil || kp.pub == nil {
		return false
	}

	return true
}
