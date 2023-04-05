/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub

import (
	bls12381 "github.com/kilic/bls12-381"
)

// SignatureMessage defines a message to be used for a signature check.
type SignatureMessage struct {
	FR *bls12381.Fr
}

// ParseSignatureMessage parses SignatureMessage from bytes.
func ParseSignatureMessage(message []byte) *SignatureMessage {
	elm := frFromOKM(message)

	return &SignatureMessage{
		FR: elm,
	}
}
