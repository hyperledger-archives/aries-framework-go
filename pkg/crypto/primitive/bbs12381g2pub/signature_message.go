/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub

import (
	bbs "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
)

// SignatureMessage defines a message to be used for a signature check.
type SignatureMessage = bbs.SignatureMessage

// ParseSignatureMessage parses SignatureMessage from bytes.
func ParseSignatureMessage(message []byte) *SignatureMessage {
	return bbs.ParseSignatureMessage(message)
}
