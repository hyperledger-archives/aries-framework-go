/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	"encoding/base64"

	"github.com/google/tink/go/tink"

	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
)

// AEAD represents a local kms aead service invoking a local SecretLock to a particular key URI.
// Instances of AEAD are invoked internally by Tink for wrapping/unwrapping keys. It must not
// be used elsewhere.
type AEAD struct {
	keyURI     string
	secretLock secretlock.Service
}

// newLocalStorageAEAD returns a new localstorage AEAD service containing a local SecretLock service.
func newLocalStorageAEAD(keyURI string, secLock secretlock.Service) tink.AEAD {
	return &AEAD{
		keyURI:     keyURI,
		secretLock: secLock,
	}
}

// Encrypt AEAD encrypts the plaintext data and uses addtionaldata from authentication.
func (a *AEAD) Encrypt(plaintext, additionalData []byte) ([]byte, error) {
	req := &secretlock.EncryptRequest{
		Plaintext:                   base64.URLEncoding.EncodeToString(plaintext),
		AdditionalAuthenticatedData: base64.URLEncoding.EncodeToString(additionalData),
	}

	resp, err := a.secretLock.Encrypt(a.keyURI, req)
	if err != nil {
		return nil, err
	}

	ct, err := base64.URLEncoding.DecodeString(resp.Ciphertext)
	if err != nil {
		return nil, err
	}

	return ct, nil
}

// Decrypt AEAD decrypts the data and verified the additional data.
func (a *AEAD) Decrypt(ciphertext, additionalData []byte) ([]byte, error) {
	req := &secretlock.DecryptRequest{
		Ciphertext:                  base64.URLEncoding.EncodeToString(ciphertext),
		AdditionalAuthenticatedData: base64.URLEncoding.EncodeToString(additionalData),
	}

	resp, err := a.secretLock.Decrypt(a.keyURI, req)
	if err != nil {
		return nil, err
	}

	pt, err := base64.URLEncoding.DecodeString(resp.Plaintext)
	if err != nil {
		return nil, err
	}

	return pt, nil
}
