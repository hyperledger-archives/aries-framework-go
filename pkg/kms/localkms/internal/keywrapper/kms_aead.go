/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package keywrapper

import (
	"encoding/base64"
	"errors"
	"regexp"

	"github.com/google/tink/go/tink"

	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
)

// LocalKeyURIPrefix for locally stored keys.
const LocalKeyURIPrefix = "local-lock://"

// LocalAEAD represents a local kms aead service invoking a local SecretLock to a particular key URI.
// Instances of LocalAEAD are invoked internally by Tink for wrapping/unwrapping keys. It must not
// be used elsewhere.
type LocalAEAD struct {
	keyURI     string
	secretLock secretlock.Service
}

// New creates a new key wrapper with the given uriPrefix and a local secretLock service.
func New(secretLock secretlock.Service, keyURI string) (tink.AEAD, error) {
	uri, err := trimPrefix(keyURI)
	if err != nil {
		return nil, err
	}

	return &LocalAEAD{
		keyURI:     uri,
		secretLock: secretLock,
	}, nil
}

// Encrypt LocalAEAD encrypts plaintext with addtionaldata.
func (a *LocalAEAD) Encrypt(plaintext, additionalData []byte) ([]byte, error) {
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

// Decrypt LocalAEAD decrypts the data and verified the additional data.
func (a *LocalAEAD) Decrypt(ciphertext, additionalData []byte) ([]byte, error) {
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

func trimPrefix(keyURI string) (string, error) {
	re1 := regexp.MustCompile(`[a-zA-Z0-9-_]+://`)
	loc := re1.FindStringIndex(keyURI)

	if len(loc) == 0 || loc[0] > 0 {
		return "", errors.New("keyURI must have a prefix in form 'prefixname://'")
	}

	if loc[1] == len(keyURI) {
		return "", errors.New("keyURI can't consist only from a prefix")
	}

	return keyURI[loc[1]:], nil
}
