/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pbkdf2

import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash"

	"github.com/google/tink/go/subtle/random"
	"golang.org/x/crypto/pbkdf2"

	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	cipherutil "github.com/hyperledger/aries-framework-go/pkg/secretlock/local/internal/cipher"
)

// package pbkdf2 provides an pbkdf2 implementation of secretlock as a masterlock.
// the underlying golang.org/x/crypto/pbkdf2 package implements IETF RFC 8018's PBKDF2 specification found at:
// https://tools.ietf.org/html/rfc8018#section-5.2. Similarly the NIST document 800-132 section 5 provides PBKDF
// recommendations.

type masterLockPBKDF2 struct {
	h    func() hash.Hash
	salt []byte
	aead cipher.AEAD
}

// NewMasterLock is responsible for encrypting/decrypting with a master key expanded from a passphrase using PBKDF2
// using `passphrase`, hash function `h`, `salt`.
// The salt is optional and can be set to nil.
// This implementation must not be used directly in Aries framework. It should be passed in
// as the second argument to local secret lock service constructor:
// `local.NewService(masterKeyReader io.Reader, secLock secretlock.Service)`.
func NewMasterLock(passphrase string, h func() hash.Hash, iterations int, salt []byte) (secretlock.Service, error) {
	if passphrase == "" {
		return nil, fmt.Errorf("passphrase is empty")
	}

	if h == nil {
		return nil, fmt.Errorf("hash is nil")
	}

	size := h().Size()
	if size > sha256.Size { // AEAD cipher requires at most sha256.Size
		return nil, fmt.Errorf("hash size not supported")
	}

	masterKey := pbkdf2.Key([]byte(passphrase), salt, iterations, sha256.Size, h)

	aead, err := cipherutil.CreateAESCipher(masterKey)
	if err != nil {
		return nil, err
	}

	return &masterLockPBKDF2{
		h:    h,
		salt: salt,
		aead: aead,
	}, nil
}

// Encrypt a master key in req
//  (keyURI is used for remote locks, it is ignored by this implementation)
func (m *masterLockPBKDF2) Encrypt(keyURI string, req *secretlock.EncryptRequest) (*secretlock.EncryptResponse, error) {
	nonce := random.GetRandomBytes(uint32(m.aead.NonceSize()))
	ct := m.aead.Seal(nil, nonce, []byte(req.Plaintext), []byte(req.AdditionalAuthenticatedData))
	ct = append(nonce, ct...)

	return &secretlock.EncryptResponse{
		Ciphertext: base64.URLEncoding.EncodeToString(ct),
	}, nil
}

// Decrypt a master key in req
// (keyURI is used for remote locks, it is ignored by this implementation).
func (m *masterLockPBKDF2) Decrypt(keyURI string, req *secretlock.DecryptRequest) (*secretlock.DecryptResponse, error) {
	ct, err := base64.URLEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		return nil, err
	}

	nonceSize := uint32(m.aead.NonceSize())

	// ensure ciphertext contains more than nonce+ciphertext (result from Encrypt())
	if len(ct) <= int(nonceSize) {
		return nil, fmt.Errorf("invalid request")
	}

	nonce := ct[0:nonceSize]
	ct = ct[nonceSize:]

	pt, err := m.aead.Open(nil, nonce, ct, []byte(req.AdditionalAuthenticatedData))
	if err != nil {
		return nil, err
	}

	return &secretlock.DecryptResponse{Plaintext: string(pt)}, nil
}
