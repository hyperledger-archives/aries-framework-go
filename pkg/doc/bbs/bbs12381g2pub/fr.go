/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub

import (
	"errors"

	"github.com/phoreproject/bls"
	"golang.org/x/crypto/blake2b"
)

func frFromOKM(message []byte) (*bls.FR, error) {
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

	return elm, nil
}

func parseFr(data []byte) (*bls.FR, error) {
	var arr [frCompressedSize]byte

	copy(arr[:], data)

	fr := bls.FRReprToFR(bls.FRReprFromBytes(arr))
	if fr == nil {
		return nil, errors.New("invalid FR")
	}

	return fr, nil
}

func frToBytes(fr *bls.FR) []byte {
	bytes := fr.ToRepr().Bytes()
	return bytes[:]
}

func f2192() *bls.FR {
	return bls.NewFr(&bls.FRRepr{
		0x59476ebc41b4528f,
		0xc5a30cb243fcc152,
		0x2b34e63940ccbd72,
		0x1e179025ca247088,
	})
}
