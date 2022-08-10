/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
)

const (
	alg = "EdDSA"
)

// NewEd25519Signer creates a new Ed25519 signer with generated key.
func NewEd25519Signer() (*Ed25519Signer, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &Ed25519Signer{privateKey: privKey, PubKey: pubKey}, nil
}

// GetEd25519Signer creates a new Ed25519 signer with passed Ed25519 key pair.
func GetEd25519Signer(privKey ed25519.PrivateKey, pubKey ed25519.PublicKey) *Ed25519Signer {
	return &Ed25519Signer{privateKey: privKey, PubKey: pubKey}
}

// Ed25519Signer makes Ed25519 based signatures.
type Ed25519Signer struct {
	privateKey ed25519.PrivateKey
	PubKey     ed25519.PublicKey
}

// PublicKey returns a public key object (ed25519.VerificationMethod).
func (s *Ed25519Signer) PublicKey() interface{} {
	return s.PubKey
}

// PublicKeyBytes returns bytes of the public key.
func (s *Ed25519Signer) PublicKeyBytes() []byte {
	return s.PubKey
}

// Alg return alg.
func (s *Ed25519Signer) Alg() string {
	return alg
}

// Sign signs a message.
func (s *Ed25519Signer) Sign(msg []byte) ([]byte, error) {
	if l := len(s.privateKey); l != ed25519.PrivateKeySize {
		return nil, errors.New("ed25519: bad private key length")
	}

	return ed25519.Sign(s.privateKey, msg), nil
}
