/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package local provides a local secret lock service. The user must create a master key and store it
// in a local file or an environment variable prior to using this service.
//
// The user has the option to encrypt the master key using hkdf.NewMasterLock(passphrase, hash func(), salt)
// found in the sub package masterlock/hkdf. There's also the option of using pbkdf2.NewMasterLock() instead of hkdf
// which is located under masterlock/pbkdf2.
//
// This lock services uses the NIST approved AES-GCM 256 bit encryption as per NIST SP 800-38D.
//
// The user can then call either:
//
//	MasterKeyFromPath(path) or
//	MasterKeyFromEnv(envPrefix, keyURI)
//
// to get an io.Reader instance needed to read the master key and create a keys Lock service.
//
// The content of the master key reader may be either raw bytes or base64URL encoded (by masterlock if protected or
// manually if not). Base64URL encoding is useful when setting a master key in an environment variable as some OSs may
// reject setting env variables with binary data as value. The service will attempt to base64URL decode the content of
// reader first and if it fails, will try to create the service with the raw (binary) content.
//
// To get the lock service, call:
//
//	NewService(reader, secLock)
//
// where reader is the instance returned from one of the MasterKeyFrom..() functions mentioned above
// and secLock which is the masterKey lock used to encrypt/decrypt the master key. If secLock is nil
// then the masterKey content in reader will be used as-is without being decrypted. The keys however are always
// encrypted using the read masterKey.
package local

import (
	"io"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/secretlock/local"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
)

// Lock is a secret lock service responsible for encrypting keys using a master key.
type Lock = local.Lock

// NewService creates a new instance of local secret lock service using a master key in masterKeyReader.
// If the masterKey is not protected (secLock=nil) this function will attempt to base64 URL Decode the
// content of masterKeyReader and if it fails, then will attempt to create a secret lock cipher with the raw key as is.
func NewService(masterKeyReader io.Reader, secLock secretlock.Service) (secretlock.Service, error) {
	return local.NewService(masterKeyReader, secLock)
}
