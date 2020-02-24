/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package noop

import (
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
)

// NoLock is a secret lock service that does no key wrapping (keys are not encrypted)
type NoLock struct {
}

// Encrypt a key in req using master key in the local secret lock service
// Noop implementation returns the key as is with no encryption
// (keyURI is used for remote locks, it is ignored by this implementation)
func (s *NoLock) Encrypt(keyURI string, req *secretlock.EncryptRequest) (*secretlock.EncryptResponse, error) {
	return &secretlock.EncryptResponse{
		Ciphertext: req.Plaintext,
	}, nil
}

// Decrypt a key in req using master key in the local secret lock service
// Noop implementation returns the key as is with no decryption
// (keyURI is used for remote locks, it is ignored by this implementation)
func (s *NoLock) Decrypt(keyURI string, req *secretlock.DecryptRequest) (*secretlock.DecryptResponse, error) {
	return &secretlock.DecryptResponse{Plaintext: req.Ciphertext}, nil
}
