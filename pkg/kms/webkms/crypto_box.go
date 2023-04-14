/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webkms

import (
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/kms/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

// TODO move CryptoBox out of webkms package.
//  this currently only sits inside webkms so it can execute crypto with private keys remotely. See issue #511
// TODO delete this file and its corresponding test file when LegacyPacker is removed.

// CryptoBox provides an elliptic-curve-based authenticated encryption scheme executed on a remote key server
//
// Payloads are encrypted using symmetric encryption (XChacha20Poly1305)
// using a shared key derived from a shared secret created by Curve25519 Elliptic Curve Diffie-Hellman key exchange.
//
// CryptoBox is created by a remote KMS, and remotely reads secret keys from the KMS for encryption/decryption,
// so clients do not need to see the secrets themselves.
type CryptoBox = webkms.CryptoBox

// NewCryptoBox creates a CryptoBox which provides remote crypto box encryption using the given KMS's key.
func NewCryptoBox(w kms.KeyManager) (*CryptoBox, error) {
	return webkms.NewCryptoBox(w)
}
