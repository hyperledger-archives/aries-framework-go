/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/kms/localkms"

	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

// TODO: move CryptoBox out of the KMS package.
//   this currently only sits inside LocalKMS so it can access private keys. See issue #511
// TODO delete this file and its corresponding test file when LegacyPacker is removed.

// CryptoBox provides an elliptic-curve-based authenticated encryption scheme
//
// Payloads are encrypted using symmetric encryption (XChacha20Poly1305)
// using a shared key derived from a shared secret created by
//
//	Curve25519 Elliptic Curve Diffie-Hellman key exchange.
//
// CryptoBox is created by a KMS, and reads secret keys from the KMS
//
//	for encryption/decryption, so clients do not need to see
//	the secrets themselves.
type CryptoBox = localkms.CryptoBox

// NewCryptoBox creates a CryptoBox which provides crypto box encryption using the given KMS's key.
func NewCryptoBox(w kms.KeyManager) (*CryptoBox, error) {
	return localkms.NewCryptoBox(w)
}
