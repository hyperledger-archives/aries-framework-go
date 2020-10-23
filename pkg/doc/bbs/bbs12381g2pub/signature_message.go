/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub

import (
	"fmt"

	"github.com/phoreproject/bls"
)

// SignatureMessage defines a message to be used for a signature check.
type SignatureMessage struct {
	FR *bls.FR
}

// ParseSignatureMessage parses SignatureMessage from bytes.
func ParseSignatureMessage(message []byte) (*SignatureMessage, error) {
	elm, err := frFromOKM(message)
	if err != nil {
		return nil, fmt.Errorf("parse message OKM: %w", err)
	}

	return &SignatureMessage{
		FR: elm,
	}, nil
}
