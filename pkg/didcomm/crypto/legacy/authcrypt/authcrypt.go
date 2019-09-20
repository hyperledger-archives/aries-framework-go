/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package authcrypt

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/agl/ed25519/extra25519"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/box"
)

type privateEd25519 [ed25519.PrivateKeySize]byte
type publicEd25519 [ed25519.PublicKeySize]byte

type keyPairEd25519 struct {
	priv *privateEd25519
	pub  *publicEd25519
}

// CurveKeySize is the size of public and private Curve25519 keys in bytes
const CurveKeySize int = 32

type privateCurve25519 [CurveKeySize]byte
type publicCurve25519 [CurveKeySize]byte

type keyPairCurve25519 struct {
	priv *privateCurve25519
	pub  *publicCurve25519
}

// Crypter represents an Authcrypt Encrypter (Decrypter) that outputs/reads legacy Aries envelopes
type Crypter struct {
	sender     keyPairEd25519
	recipients []*publicEd25519
	randSource io.Reader
}

// New will create a Crypter that encrypts messages using the legacy Aries format
// Note: legacy crypter does not support XChacha20Poly1035 (XC20P), only Chacha20Poly1035 (C20P)
func New(sender keyPairEd25519, recipients []*publicEd25519) (*Crypter, error) { // nolint: lll

	if len(recipients) == 0 {
		return nil, errors.New("empty recipients keys, must have at least one recipient")
	}

	c := &Crypter{
		sender:     sender,
		recipients: recipients,
		randSource: rand.Reader,
	}

	if !isKeyPairValid(sender) {
		return nil, fmt.Errorf(
			"sender keyPair not supported, it must have a %d byte private key and %d byte public key",
			ed25519.PrivateKeySize, ed25519.PublicKeySize)
	}

	return c, nil
}

func (c *Crypter) setRandSource(source io.Reader) {
	c.randSource = source
}

func isKeyPairValid(kp keyPairEd25519) bool {
	if kp.priv == nil || kp.pub == nil {
		return false
	}

	return true
}

// envelope is the full payload envelope for the JSON message
type envelope struct {
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

// publicEd25519toCurve25519 takes an Ed25519 public key and provides the corresponding Curve25519 public key
//  This function wraps PublicKeyToCurve25519 from Adam Langley's ed25519 repo: https://github.com/agl/ed25519
func publicEd25519toCurve25519(pub *publicEd25519) (*publicCurve25519, error) {
	if pub == nil {
		return nil, errors.New("key is nil")
	}
	pkOut := new([CurveKeySize]byte)
	success := extra25519.PublicKeyToCurve25519(pkOut, (*[ed25519.PublicKeySize]byte)(pub))
	if !success {
		return nil, errors.New("failed to convert public key")
	}
	return (*publicCurve25519)(pkOut), nil
}

// secretEd25519toCurve25519 converts a secret key from Ed25519 to curve25519 format
//  This function wraps PrivateKeyToCurve25519 from Adam Langley's ed25519 repo: https://github.com/agl/ed25519
func secretEd25519toCurve25519(priv *privateEd25519) (*privateCurve25519, error) {
	if priv == nil {
		return nil, errors.New("key is nil")
	}
	sKOut := new([CurveKeySize]byte)
	extra25519.PrivateKeyToCurve25519(sKOut, (*[ed25519.PrivateKeySize]byte)(priv))
	return (*privateCurve25519)(sKOut), nil
}

func makeNonce(pub1, pub2 []byte) ([]byte, error) {
	var nonce [24]byte
	// generate an equivalent nonce to libsodium's (see link above)
	nonceWriter, err := blake2b.New(24, nil)
	if err != nil {
		return nil, err
	}
	_, err = nonceWriter.Write(pub1)
	if err != nil {
		return nil, err
	}
	_, err = nonceWriter.Write(pub2)
	if err != nil {
		return nil, err
	}

	nonceOut := nonceWriter.Sum(nil)
	copy(nonce[:], nonceOut)

	return nonce[:], nil
}

// sodiumBoxSeal will encrypt a msg (in the case of this package, it will be
// an ephemeral key concatenated to the sender's public key) using the
// recipient's pubKey, this is equivalent to libsodium's C function: crypto_box_seal()
// https://libsodium.gitbook.io/doc/public-key_cryptography/sealed_boxes#usage
func sodiumBoxSeal(msg []byte, recPub *publicCurve25519, randSource io.Reader) ([]byte, error) {
	var nonce [24]byte
	// generate ephemeral curve25519 asymmetric keys
	epk, esk, err := box.GenerateKey(randSource)
	if err != nil {
		return nil, err
	}
	// generate an equivalent nonce to libsodium's (see link above)
	nonceSlice, err := makeNonce(epk[:], recPub[:])
	if err != nil {
		return nil, err
	}
	copy(nonce[:], nonceSlice)

	var out = make([]byte, len(epk))
	copy(out, epk[:])

	// now seal the msg with the ephemeral key, nonce and recPub (which is recipient's publicKey)
	ret := box.Seal(out, msg, &nonce, (*[32]byte)(recPub), esk)

	return ret, nil
}
