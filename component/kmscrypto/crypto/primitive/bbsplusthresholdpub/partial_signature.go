package bbsplusthresholdpub

import (
	"errors"
	"fmt"

	ml "github.com/IBM/mathlib"
)

type PartialSignature struct {
	CapitalAShare *ml.G1
	DeltaShare    *ml.Zr
	EShare        *ml.Zr
	SShare        *ml.Zr
}

func ParsePartialSignature(partSigBytes []byte) (*PartialSignature, error) {
	if len(partSigBytes) != bbsplusPartialSignatureLen {
		return nil, errors.New("invalid size of partial signature")
	}

	pointG1, err := curve.NewG1FromCompressed(partSigBytes[:g1CompressedSize])
	if err != nil {
		return nil, fmt.Errorf("deserialize G1 compressed signature: %w", err)
	}

	delta := parseFr(partSigBytes[g1CompressedSize : g1CompressedSize+frCompressedSize])
	e := parseFr(partSigBytes[g1CompressedSize+frCompressedSize : g1CompressedSize+frCompressedSize*2])
	s := parseFr(partSigBytes[g1CompressedSize+frCompressedSize*2:])

	return &PartialSignature{
		CapitalAShare: pointG1,
		DeltaShare:    delta,
		EShare:        e,
		SShare:        s,
	}, nil
}

func (ps *PartialSignature) ToBytes() ([]byte, error) {
	bytes := make([]byte, bbsplusPartialSignatureLen)

	copy(bytes, ps.CapitalAShare.Compressed())
	copy(bytes[g1CompressedSize:g1CompressedSize+frCompressedSize], ps.DeltaShare.Bytes())
	copy(bytes[g1CompressedSize+frCompressedSize:g1CompressedSize+frCompressedSize*2], ps.EShare.Bytes())
	copy(bytes[g1CompressedSize+frCompressedSize*2:], ps.SShare.Bytes())

	return bytes, nil
}
