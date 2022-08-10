/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
)

const (
	rs256Alg = "RS256"
	ps256Alg = "PS256"
)

// NewRS256Signer creates a new RS256 signer with generated key.
func NewRS256Signer() (*RS256Signer, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	return newRS256Signer(privKey), nil
}

// GetRS256Signer creates a new RS256 signer with provided RSA private key.
func GetRS256Signer(privKey *rsa.PrivateKey) *RS256Signer {
	return newRS256Signer(privKey)
}

func newRS256Signer(privKey *rsa.PrivateKey) *RS256Signer {
	return &RS256Signer{rsaSigner: *newRSASigner(privKey), alg: rs256Alg}
}

// RS256Signer makes RS256 based signatures.
type RS256Signer struct {
	rsaSigner
	alg string
}

// Sign signs a message.
func (s *RS256Signer) Sign(msg []byte) ([]byte, error) {
	hasher := crypto.SHA256.New()
	_, _ = hasher.Write(msg)
	hashed := hasher.Sum(nil)

	return rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, hashed)
}

// Alg return alg.
func (s *RS256Signer) Alg() string {
	return s.alg
}

// NewPS256Signer creates a new PS256 signer with generated key.
func NewPS256Signer() (*PS256Signer, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	return newPS256Signer(privKey), nil
}

// GetPS256Signer creates a new PS256 signer with provided RSA private key.
func GetPS256Signer(privKey *rsa.PrivateKey) *PS256Signer {
	return newPS256Signer(privKey)
}

func newPS256Signer(privKey *rsa.PrivateKey) *PS256Signer {
	return &PS256Signer{rsaSigner: *newRSASigner(privKey), alg: ps256Alg}
}

// PS256Signer makes PS256 based signatures.
type PS256Signer struct {
	rsaSigner
	alg string
}

// Sign signs a message.
func (s *PS256Signer) Sign(msg []byte) ([]byte, error) {
	hasher := crypto.SHA256.New()

	_, _ = hasher.Write(msg)

	hashed := hasher.Sum(nil)

	return rsa.SignPSS(rand.Reader, s.privateKey, crypto.SHA256, hashed, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	})
}

// Alg return alg.
func (s *PS256Signer) Alg() string {
	return s.alg
}

func newRSASigner(privKey *rsa.PrivateKey) *rsaSigner {
	pubKey := &privKey.PublicKey

	return &rsaSigner{
		privateKey:  privKey,
		PubKey:      pubKey,
		pubKeyBytes: x509.MarshalPKCS1PublicKey(pubKey),
	}
}

type rsaSigner struct {
	privateKey  *rsa.PrivateKey
	PubKey      *rsa.PublicKey
	pubKeyBytes []byte
}

func (s *rsaSigner) PublicKey() interface{} {
	return s.PubKey
}

func (s *rsaSigner) PublicKeyBytes() []byte {
	return s.pubKeyBytes
}
