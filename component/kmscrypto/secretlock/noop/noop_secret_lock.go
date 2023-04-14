/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package noop

import (
	"github.com/hyperledger/aries-framework-go/spi/secretlock"
)

// package noop provides a noop secret lock service. This allows for quick testing of key storage using the KMS. Keys
// stored with noop are unprotected. Therefore, this implementation is be used for testing purposes only.
// Production code must always use pkg/secretlock/local implementation. In order to minimize the impact on existing
// clients, noop is the default implementation in the framework. Therefore, the use of a context.WithSecretLock() option
// with a secretlock/local implementation is highly recommended to secure key storage in the KMS.

// NoLock is a secret lock service that does no key wrapping (keys are not encrypted).
type NoLock struct{}

// Encrypt a key in req using master key in the local secret lock service
// Noop implementation returns the key as is with no encryption
// (keyURI is used for remote locks, it is ignored by this implementation).
func (s *NoLock) Encrypt(keyURI string, req *secretlock.EncryptRequest) (*secretlock.EncryptResponse, error) {
	return &secretlock.EncryptResponse{
		Ciphertext: req.Plaintext,
	}, nil
}

// Decrypt a key in req using master key in the local secret lock service
// Noop implementation returns the key as is with no decryption
// (keyURI is used for remote locks, it is ignored by this implementation).
func (s *NoLock) Decrypt(keyURI string, req *secretlock.DecryptRequest) (*secretlock.DecryptResponse, error) {
	return &secretlock.DecryptResponse{Plaintext: req.Ciphertext}, nil
}
