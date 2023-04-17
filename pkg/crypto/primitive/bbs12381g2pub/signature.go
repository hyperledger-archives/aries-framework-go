/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub

import (
	bbs "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
)

// Signature defines BLS signature.
type Signature = bbs.Signature

// ParseSignature parses a Signature from bytes.
func ParseSignature(sigBytes []byte) (*Signature, error) {
	return bbs.ParseSignature(sigBytes)
}
