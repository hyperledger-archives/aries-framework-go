/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package authcrypt

import (
	"crypto/rand"
	"errors"
	"io"

	chacha "golang.org/x/crypto/chacha20poly1305"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
)

// This package deals with Authcrypt encryption for Packing/Unpacking DID Comm exchange
// Using Chacha20Poly1305 encryption/authentication

// ContentEncryption represents a content encryption algorithm.
type ContentEncryption string

const (
	// C20P Chacha20Poly1305 algorithm
	C20P = ContentEncryption("C20P") // Chacha20 encryption + Poly1305 authenticator cipher (96 bits nonce)
	// XC20P XChacha20Poly1305 algorithm
	XC20P = ContentEncryption("XC20P") // XChacha20 encryption + Poly1305 authenticator cipher (192 bits nonce)
	// encodingType is the `typ` string identifier in a message that identifies the format as being JWE
	encodingType string = "prs.hyperledger.aries-auth-message"
)

// errUnsupportedAlg is used when a bad encryption algorithm is used
var errUnsupportedAlg = errors.New("algorithm not supported")

// TODO https://github.com/hyperledger/aries-framework-go/issues/475 pull alg and nonceSize into separate crypter,
//  add crypter reference to Packer

// Packer represents an Authcrypt Packer/Unpacker that outputs/reads JWE envelopes
type Packer struct {
	alg        ContentEncryption
	nonceSize  int
	kms        legacykms.KeyManager
	randReader io.Reader
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
type jweHeaders struct {
	Typ string `json:"typ,omitempty"`
	Alg string `json:"alg,omitempty"`
	Enc string `json:"enc,omitempty"`
}

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
	SPK string `json:"spk,omitempty"`
}

// recipientSPKJWEHeaders are the Protected JWE headers of a recipient's SPK field (which is a JWE with a JWK payload)
type recipientSPKJWEHeaders struct {
	Typ string `json:"typ,omitempty"`
	CTY string `json:"cty,omitempty"`
	Alg string `json:"alg,omitempty"`
	Enc string `json:"enc,omitempty"`
	IV  string `json:"iv,omitempty"`
	Tag string `json:"tag,omitempty"`
	EPK jwk    `json:"epk,omitempty"`
}

// jwk formatted key
type jwk struct {
	Kty string `json:"kty,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
}

// New will create an Packer instance to 'AuthCrypt' payloads for the given sender and recipients arguments
// and the encryption alg argument. Possible algorithms supported are:
// C20P (chacha20-poly1305 ietf)
// XC20P (xchacha20-poly1305 ietf)
// The returned Packer contains all the information required to pack and unpack payloads.
func New(ctx packer.Provider, alg ContentEncryption) (*Packer, error) {
	k := ctx.KMS()

	var nonceSize int

	switch alg {
	case C20P:
		nonceSize = chacha.NonceSize
	case XC20P:
		nonceSize = chacha.NonceSizeX
	default:
		return nil, errUnsupportedAlg
	}

	return &Packer{
		alg:        alg,
		nonceSize:  nonceSize,
		kms:        k,
		randReader: rand.Reader,
	}, nil
}

// EncodingType returns the type of the encoding, as in the `Typ` field of the envelope header
func (p *Packer) EncodingType() string {
	return encodingType
}
