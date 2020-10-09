package bbs12381g2pub

import (
	"golang.org/x/crypto/blake2b"

	"github.com/phoreproject/bls"
)

// SignatureMessage defines a message to be used for signature check.
type SignatureMessage struct {
	FR *bls.FR
}

// NewSignatureMessage creates a new SignatureMessage.
func NewSignatureMessage(message []byte) *SignatureMessage {
	const (
		eightBytes = 8
		okmMiddle  = 24
	)
	h, _ := blake2b.New384(nil)
	_, _ = h.Write(message)
	okm := h.Sum(nil)

	elm := parseFr(append(make([]byte, eightBytes, eightBytes), okm[:okmMiddle]...))
	elm.MulAssign(f2192())
	elm.AddAssign(parseFr(append(make([]byte, eightBytes, eightBytes), okm[okmMiddle:]...)))

	return &SignatureMessage{
		FR: elm,
	}
}

func parseFr(data []byte) *bls.FR {
	var arr [32]byte
	copy(arr[:], data)

	return bls.FRReprToFR(bls.FRReprFromBytes(arr))
}

func f2192() *bls.FR {
	return bls.NewFr(&bls.FRRepr{
		0x59476ebc41b4528f,
		0xc5a30cb243fcc152,
		0x2b34e63940ccbd72,
		0x1e179025ca247088})
}
