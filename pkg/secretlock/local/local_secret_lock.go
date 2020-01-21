/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package local

import (
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/google/tink/go/subtle/random"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
)

// Lock is a local secrete lock service responsible for encrypting keys using a master key stored locally
type Lock struct {
	aead cipher.AEAD
}

// NewService creates a new instance of a local secret lock service
func NewService(keyURI string) (secretlock.Service, error) {
	mk := os.Getenv("LOCAL_" + strings.ReplaceAll(keyURI, "/", "_"))
	if mk == "" {
		return nil, fmt.Errorf("masterKey not set")
	}

	masterKey, err := base64.URLEncoding.DecodeString(mk)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(masterKey)
	if err != nil {
		return nil, err
	}

	return &Lock{aead: aead}, nil
}

// Encrypt req using key in the local secret lock service (keyURI is used for remote locks, it is ignored by this
// implementation)
func (s *Lock) Encrypt(keyURI string, req *secretlock.EncryptRequest) (*secretlock.EncryptResponse, error) {
	nonce := random.GetRandomBytes(chacha20poly1305.NonceSizeX)
	ct := s.aead.Seal(nil, nonce, []byte(req.Plaintext), []byte(req.AdditionalAuthenticatedData))
	ct = append(nonce, ct...)

	return &secretlock.EncryptResponse{
		Ciphertext: base64.URLEncoding.EncodeToString(ct),
	}, nil
}

// Decrypt req using key in the local secret lock service (keyURI is used for remote locks, it is ignored by this
// implementation)
func (s *Lock) Decrypt(keyURI string, req *secretlock.DecryptRequest) (*secretlock.DecryptResponse, error) {
	ct, err := base64.URLEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		return nil, err
	}

	nonce := ct[0:chacha20poly1305.NonceSizeX]
	ct = ct[chacha20poly1305.NonceSizeX:]

	pt, err := s.aead.Open(nil, nonce, ct, []byte(req.AdditionalAuthenticatedData))
	if err != nil {
		return nil, err
	}

	return &secretlock.DecryptResponse{Plaintext: string(pt)}, nil
}
