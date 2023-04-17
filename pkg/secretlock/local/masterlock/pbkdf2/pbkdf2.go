/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package pbkdf2 provides an pbkdf2 implementation of secretlock as a masterlock.
// the underlying golang.org/x/crypto/pbkdf2 package implements IETF RFC 8018's PBKDF2 specification found at:
// https://tools.ietf.org/html/rfc8018#section-5.2. Similarly the NIST document 800-132 section 5 provides PBKDF
// recommendations.
package pbkdf2

import (
	"hash"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/secretlock/local/masterlock/pbkdf2"

	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
)

// NewMasterLock is responsible for encrypting/decrypting with a master key expanded from a passphrase using PBKDF2
// using `passphrase`, hash function `h`, `salt`.
// The salt is optional and can be set to nil.
// This implementation must not be used directly in Aries framework. It should be passed in
// as the second argument to local secret lock service constructor:
// `local.NewService(masterKeyReader io.Reader, secLock secretlock.Service)`.
func NewMasterLock(passphrase string, h func() hash.Hash, iterations int, salt []byte) (secretlock.Service, error) {
	return pbkdf2.NewMasterLock(passphrase, h, iterations, salt)
}
