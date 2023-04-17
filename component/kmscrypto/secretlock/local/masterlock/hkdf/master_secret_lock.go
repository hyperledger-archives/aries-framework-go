/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package hkdf

import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash"
	"io"

	"github.com/google/tink/go/subtle/random"
	"golang.org/x/crypto/hkdf"

	"github.com/hyperledger/aries-framework-go/spi/secretlock"

	cipherutil "github.com/hyperledger/aries-framework-go/component/kmscrypto/secretlock/local/internal/cipher"
)

// package hkdf provides an hkdf implementation of secretlock as a masterlock.
// See golang.org/x/crypto/hkdf/hkdf.go for IETF reference.
// The IETF RFC in question is RFC 5869. It mentions the following paragraph in the introduction about NIST documents:
// " Note that some existing KDF specifications, such as NIST Special
//   Publication 800-56A [800-56A], NIST Special Publication 800-108
//   [800-108] and IEEE Standard 1363a-2004 [1363a], either only consider
//   the second stage (expanding a pseudorandom key), or do not explicitly
//   differentiate between the "extract" and "expand" stages, often
//   resulting in design shortcomings.  The goal of this specification is
//   to accommodate a wide range of KDF requirements while minimizing the
//   assumptions about the underlying hash function.  The "extract-then-
//   expand" paradigm supports well this goal (see [HKDF-paper] for more
//   information about the design rationale). "

type masterLockHKDF struct {
	h    func() hash.Hash
	salt []byte
	aead cipher.AEAD
}

// NewMasterLock is responsible for encrypting/decrypting with a master key expanded from a passphrase using HKDF
// using `passphrase`, hash function `h`, `salt`.
// The salt is optional and can be set to nil.
// This implementation must not be used directly in Aries framework. It should be passed in
// as the second argument to local secret lock service constructor:
// `local.NewService(masterKeyReader io.Reader, secLock secretlock.Service)`.
func NewMasterLock(passphrase string, h func() hash.Hash, salt []byte) (secretlock.Service, error) {
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

	// expand an encryption key from passphrase
	expander := hkdf.New(h, []byte(passphrase), salt, nil)

	masterKey := make([]byte, size)

	_, err := io.ReadFull(expander, masterKey)
	if err != nil {
		return nil, err
	}

	aead, err := cipherutil.CreateAESCipher(masterKey)
	if err != nil {
		return nil, err
	}

	return &masterLockHKDF{
		h:    h,
		salt: salt,
		aead: aead,
	}, nil
}

// Encrypt a master key in req
//  (keyURI is used for remote locks, it is ignored by this implementation)
func (m *masterLockHKDF) Encrypt(keyURI string, req *secretlock.EncryptRequest) (*secretlock.EncryptResponse, error) {
	nonce := random.GetRandomBytes(uint32(m.aead.NonceSize()))
	ct := m.aead.Seal(nil, nonce, []byte(req.Plaintext), []byte(req.AdditionalAuthenticatedData))
	ct = append(nonce, ct...)

	return &secretlock.EncryptResponse{
		Ciphertext: base64.URLEncoding.EncodeToString(ct),
	}, nil
}

// Decrypt a master key in req
// (keyURI is used for remote locks, it is ignored by this implementation).
func (m *masterLockHKDF) Decrypt(keyURI string, req *secretlock.DecryptRequest) (*secretlock.DecryptResponse, error) {
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
