/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package local

import (
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/google/tink/go/subtle/random"

	"github.com/hyperledger/aries-framework-go/spi/secretlock"

	"github.com/hyperledger/aries-framework-go/component/log"

	cipherutil "github.com/hyperledger/aries-framework-go/component/kmscrypto/secretlock/local/internal/cipher"
)

// package local provides a local secret lock service. The user must create a master key and store it
// in a local file or an environment variable prior to using this service.
//
// The user has the option to encrypt the master key using hkdf.NewMasterLock(passphrase, hash func(), salt)
// found in the sub package masterlock/hkdf. There's also the option of using pbkdf2.NewMasterLock() instead of hkdf
// which is located under masterlock/pbkdf2.
//
// This lock services uses the NIST approved AES-GCM 256 bit encryption as per NIST SP 800-38D.
//
// The user can then call either:
//		MasterKeyFromPath(path) or
//		MasterKeyFromEnv(envPrefix, keyURI)
// to get an io.Reader instance needed to read the master key and create a keys Lock service.
//
// The content of the master key reader may be either raw bytes or base64URL encoded (by masterlock if protected or
// manually if not). Base64URL encoding is useful when setting a master key in an environment variable as some OSs may
// reject setting env variables with binary data as value. The service will attempt to base64URL decode the content of
// reader first and if it fails, will try to create the service with the raw (binary) content.
//
// To get the lock service, call:
// 		NewService(reader, secLock)
// where reader is the instance returned from one of the MasterKeyFrom..() functions mentioned above
// and secLock which is the masterKey lock used to encrypt/decrypt the master key. If secLock is nil
// then the masterKey content in reader will be used as-is without being decrypted. The keys however are always
// encrypted using the read masterKey.

var logger = log.New("aries-framework/lock")

const masterKeyLen = 512

// Lock is a secret lock service responsible for encrypting keys using a master key.
type Lock struct {
	aead cipher.AEAD
}

// NewService creates a new instance of local secret lock service using a master key in masterKeyReader.
// If the masterKey is not protected (secLock=nil) this function will attempt to base64 URL Decode the
// content of masterKeyReader and if it fails, then will attempt to create a secret lock cipher with the raw key as is.
func NewService(masterKeyReader io.Reader, secLock secretlock.Service) (secretlock.Service, error) {
	masterKeyData := make([]byte, masterKeyLen)

	if masterKeyReader == nil {
		return nil, fmt.Errorf("masterKeyReader is nil")
	}

	n, err := masterKeyReader.Read(masterKeyData)
	if err != nil {
		if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, err
		}
	}

	if n == 0 {
		return nil, fmt.Errorf("masterKeyReader is empty")
	}

	var masterKey []byte

	// if secLock not empty, then masterKeyData is encrypted (protected), let's decrypt it first.
	if secLock != nil {
		decResponse, e := secLock.Decrypt("", &secretlock.DecryptRequest{
			Ciphertext: string(masterKeyData[:n]),
		})
		if e != nil {
			return nil, e
		}

		masterKey = []byte(decResponse.Plaintext)
	} else {
		// masterKeyData is not encrypted, base64URL decode it
		masterKey, err = base64.URLEncoding.DecodeString(string(masterKeyData[:n]))
		if err != nil {
			// attempt to create a service using the key content from reader as is

			masterKey = make([]byte, n)

			// copy masterKey read from reader directly
			copy(masterKey, masterKeyData)
		}
	}

	// finally create the cipher to be used by the lock service
	aead, err := cipherutil.CreateAESCipher(masterKey)
	if err != nil {
		return nil, err
	}

	return &Lock{aead: aead}, nil
}

// Encrypt a key in req using master key in the local secret lock service
// (keyURI is used for remote locks, it is ignored by this implementation).
func (s *Lock) Encrypt(keyURI string, req *secretlock.EncryptRequest) (*secretlock.EncryptResponse, error) {
	nonce := random.GetRandomBytes(uint32(s.aead.NonceSize()))
	ct := s.aead.Seal(nil, nonce, []byte(req.Plaintext), []byte(req.AdditionalAuthenticatedData))
	ct = append(nonce, ct...)

	return &secretlock.EncryptResponse{
		Ciphertext: base64.URLEncoding.EncodeToString(ct),
	}, nil
}

// Decrypt a key in req using master key in the local secret lock service
// (keyURI is used for remote locks, it is ignored by this implementation).
func (s *Lock) Decrypt(keyURI string, req *secretlock.DecryptRequest) (*secretlock.DecryptResponse, error) {
	ct, err := base64.URLEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		return nil, err
	}

	nonceSize := uint32(s.aead.NonceSize())

	// ensure ciphertext contains more than nonce+ciphertext (result from Encrypt())
	if len(ct) <= int(nonceSize) {
		return nil, fmt.Errorf("invalid request")
	}

	nonce := ct[0:nonceSize]
	ct = ct[nonceSize:]

	pt, err := s.aead.Open(nil, nonce, ct, []byte(req.AdditionalAuthenticatedData))
	if err != nil {
		return nil, err
	}

	return &secretlock.DecryptResponse{Plaintext: string(pt)}, nil
}
