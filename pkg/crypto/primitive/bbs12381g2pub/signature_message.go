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

// parseSignatureMessage parses SignatureMessage from bytes.
func parseSignatureMessage(message []byte) *SignatureMessage {
	elm := Hash2scalar(message)

	return &SignatureMessage{
		FR: elm,
	}
}

// ParseSignatureMessages parses SignatureMessages from bytes.
func ParseSignatureMessages(messages [][]byte) []*SignatureMessage {
	messagesFr := make([]*SignatureMessage, len(messages))

	for i, msg := range messages {
		messagesFr[i] = parseSignatureMessage(msg)
	}

	return messagesFr
}
