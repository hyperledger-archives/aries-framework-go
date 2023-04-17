/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package hkdf provides an hkdf implementation of secretlock as a masterlock.
// See golang.org/x/crypto/hkdf/hkdf.go for IETF reference.
// The IETF RFC in question is RFC 5869. It mentions the following paragraph in the introduction about NIST documents:
//
//	"Note that some existing KDF specifications, such as NIST Special
//	Publication 800-56A [800-56A], NIST Special Publication 800-108
//	[800-108] and IEEE Standard 1363a-2004 [1363a], either only consider
//	the second stage (expanding a pseudorandom key), or do not explicitly
//	differentiate between the "extract" and "expand" stages, often
//	resulting in design shortcomings.  The goal of this specification is
//	to accommodate a wide range of KDF requirements while minimizing the
//	assumptions about the underlying hash function.  The "extract-then-
//	expand" paradigm supports well this goal (see [HKDF-paper] for more
//	information about the design rationale)."
package hkdf

import (
	"hash"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/secretlock/local/masterlock/hkdf"

	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
)

// NewMasterLock is responsible for encrypting/decrypting with a master key expanded from a passphrase using HKDF
// using `passphrase`, hash function `h`, `salt`.
// The salt is optional and can be set to nil.
// This implementation must not be used directly in Aries framework. It should be passed in
// as the second argument to local secret lock service constructor:
// `local.NewService(masterKeyReader io.Reader, secLock secretlock.Service)`.
func NewMasterLock(passphrase string, h func() hash.Hash, salt []byte) (secretlock.Service, error) {
	return hkdf.NewMasterLock(passphrase, h, salt)
}
