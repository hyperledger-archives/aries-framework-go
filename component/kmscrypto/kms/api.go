/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"errors"
	"io"
)

// ErrKeyNotFound is an error type that a KMS expects from the Store.Get method if no key stored under the given
// key ID could be found.
var ErrKeyNotFound = errors.New("key not found")

// CryptoBox is a libsodium crypto service used by legacy authcrypt packer.
// TODO remove this service when legacy packer is retired from the framework.
type CryptoBox interface {
	// Easy seals a payload with a provided nonce
	Easy(payload, nonce, theirPub []byte, myKID string) ([]byte, error)
	// EashOpen unseals a cipherText sealed with Easy, where the nonce is provided
	EasyOpen(cipherText, nonce, theirPub, myPub []byte) ([]byte, error)
	// Seal seals a payload using the equivalent logic of libsodium box_seal
	Seal(payload, theirEncPub []byte, randSource io.Reader) ([]byte, error)
	// SealOpen decrypts a payload encrypted with Seal
	SealOpen(cipherText, myPub []byte) ([]byte, error)
}
