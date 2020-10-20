/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub

import (
	"github.com/phoreproject/bls"
	"golang.org/x/crypto/blake2b"
)

// SignatureMessage defines a message to be used for a signature check.
type SignatureMessage struct {
	FR *bls.FR
}

// ParseSignatureMessage parses SignatureMessage from bytes.
func ParseSignatureMessage(message []byte) (*SignatureMessage, error) {
	const (
		eightBytes = 8
		okmMiddle  = 24
	)

	// We pass a null key so error is impossible here.
	h, _ := blake2b.New384(nil) //nolint:errcheck

	// blake2b.digest() does not return an error.
	_, _ = h.Write(message) //nolint:errcheck
	okm := h.Sum(nil)
	emptyEightBytes := make([]byte, eightBytes)

	elm, err := parseFr(append(emptyEightBytes, okm[:okmMiddle]...))
	if err != nil {
		return nil, err
	}

	elm.MulAssign(f2192())

	fr, err := parseFr(append(emptyEightBytes, okm[okmMiddle:]...))
	if err != nil {
		return nil, err
	}

	elm.AddAssign(fr)

	return &SignatureMessage{
		FR: elm,
	}, nil
}

func f2192() *bls.FR {
	return bls.NewFr(&bls.FRRepr{
		0x59476ebc41b4528f,
		0xc5a30cb243fcc152,
		0x2b34e63940ccbd72,
		0x1e179025ca247088,
	})
}
