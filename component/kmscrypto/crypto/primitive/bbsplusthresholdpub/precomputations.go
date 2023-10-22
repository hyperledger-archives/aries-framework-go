package bbsplusthresholdpub

import (
	"encoding/binary"
	"errors"

	ml "github.com/IBM/mathlib"
)

type PerPartyPresignature struct {
	AShare     *ml.Zr   // a^k_i for k in [t].
	EShare     *ml.Zr   // e^k_i for k in [t].
	SShare     *ml.Zr   // s^k_i for k in [t].
	AeTermOwn  *ml.Zr   // a^k_i * e^k_i for k in [t].   // Might not be necessary.
	AsTermOwn  *ml.Zr   // a^k_i * s^k_i for k in [t]   // Might not be necessary.
	AskTermOwn *ml.Zr   // a^k_i * sk_i for k in [t]    // Might not be necessary.
	AeTermsA   []*ml.Zr // Share of a^k_i * e^k_j for k in [t], j in [n] (j can also be i).
	AeTermsE   []*ml.Zr // Share of a^k_j * e^k_i for k in [t], j in [n] (j can also be i -- this time other share).
	AsTermsA   []*ml.Zr // Share of a^k_i * s^k_j for k in [t], j in [n] (j can also be i).
	AsTermsS   []*ml.Zr // Share of a^k_j * s^k_i for k in [t], j in [n] (j can also be i -- this time other share).
	AskTermsA  []*ml.Zr // Share of a^k_i * sk_j for k in [t], j in [n] (j can also be i).
	AskTermsSK []*ml.Zr // Share of a^k_j * sk_i for k in [t], j in [n] (j can also be i -- this time other share).
}

func ParsePerPartyPresignature(presigBytes []byte) (*PerPartyPresignature, error) {
	if len(presigBytes) < 6*intSize {
		return nil, errors.New("input presigBytes is too short to represent the PerPartyPresignature")
	}

	// Deserialize slices' lengths
	aeTermsALen := int(binary.LittleEndian.Uint32(presigBytes[:4]))
	aeTermsELen := int(binary.LittleEndian.Uint32(presigBytes[4:8]))
	asTermsALen := int(binary.LittleEndian.Uint32(presigBytes[8:12]))
	asTermsSLen := int(binary.LittleEndian.Uint32(presigBytes[12:16]))
	askTermsALen := int(binary.LittleEndian.Uint32(presigBytes[16:20]))
	askTermsSKLen := int(binary.LittleEndian.Uint32(presigBytes[20:24]))

	presigBytes = presigBytes[24:]
	if len(presigBytes) != frCompressedSize*
		(6+aeTermsALen+aeTermsELen+
			asTermsALen+asTermsSLen+
			askTermsALen+askTermsSKLen) {
		return nil, errors.New("input presigBytes is too short to represent the PerPartyPreSignature")
	}

	// Deserialize AShare
	aShareBytes := presigBytes[:frCompressedSize]
	presigBytes = presigBytes[frCompressedSize:]
	aShare := parseFr(aShareBytes)

	// Deserialize EShare
	eShareBytes := presigBytes[:frCompressedSize]
	presigBytes = presigBytes[frCompressedSize:]
	eShare := parseFr(eShareBytes)

	// Deserialize SShare
	sShareBytes := presigBytes[:frCompressedSize]
	presigBytes = presigBytes[frCompressedSize:]
	sShare := parseFr(sShareBytes)

	// Deserialize AeTermOwn
	aeTermOwnBytes := presigBytes[:frCompressedSize]
	presigBytes = presigBytes[frCompressedSize:]
	aeTermOwn := parseFr(aeTermOwnBytes)

	// Deserialize AsTermOwn
	asTermOwnBytes := presigBytes[:frCompressedSize]
	presigBytes = presigBytes[frCompressedSize:]
	asTermOwn := parseFr(asTermOwnBytes)

	// Deserialize AskTermOwn
	askTermOwnBytes := presigBytes[:frCompressedSize]
	presigBytes = presigBytes[frCompressedSize:]
	askTermOwn := parseFr(askTermOwnBytes)

	// Deserialise AeTermsA
	aeTermsABytes := presigBytes[:frCompressedSize*aeTermsALen]
	presigBytes = presigBytes[frCompressedSize*aeTermsALen:]
	aeTermsA := make([]*ml.Zr, aeTermsALen)
	for i := 0; i < aeTermsALen; i++ {
		offset := i * frCompressedSize
		aeTermABytes := aeTermsABytes[offset : offset+frCompressedSize]
		aeTermsA[i] = parseFr(aeTermABytes)
	}

	// Deserialise AeTermsE
	aeTermsEBytes := presigBytes[:frCompressedSize*aeTermsELen]
	presigBytes = presigBytes[frCompressedSize*aeTermsELen:]
	aeTermsE := make([]*ml.Zr, aeTermsELen)
	for i := 0; i < aeTermsELen; i++ {
		offset := i * frCompressedSize
		aeTermEBytes := aeTermsEBytes[offset : offset+frCompressedSize]
		aeTermsE[i] = parseFr(aeTermEBytes)
	}

	// Deserialise AsTermsA
	asTermsABytes := presigBytes[:frCompressedSize*asTermsALen]
	presigBytes = presigBytes[frCompressedSize*asTermsALen:]
	asTermsA := make([]*ml.Zr, asTermsALen)
	for i := 0; i < asTermsALen; i++ {
		offset := i * frCompressedSize
		asTermABytes := asTermsABytes[offset : offset+frCompressedSize]
		asTermsA[i] = parseFr(asTermABytes)
	}

	// Deserialise AsTermsS
	asTermsSBytes := presigBytes[:frCompressedSize*asTermsSLen]
	presigBytes = presigBytes[frCompressedSize*asTermsSLen:]
	asTermsS := make([]*ml.Zr, asTermsSLen)
	for i := 0; i < asTermsSLen; i++ {
		offset := i * frCompressedSize
		asTermSBytes := asTermsSBytes[offset : offset+frCompressedSize]
		asTermsS[i] = parseFr(asTermSBytes)
	}

	// Deserialise AskTermsA
	askTermsABytes := presigBytes[:frCompressedSize*askTermsALen]
	presigBytes = presigBytes[frCompressedSize*askTermsALen:]
	askTermsA := make([]*ml.Zr, askTermsALen)
	for i := 0; i < askTermsALen; i++ {
		offset := i * frCompressedSize
		askTermABytes := askTermsABytes[offset : offset+frCompressedSize]
		askTermsA[i] = parseFr(askTermABytes)
	}
	// Deserialise AskTermsSK
	askTermsSKBytes := presigBytes[:frCompressedSize*askTermsSKLen]
	askTermsSK := make([]*ml.Zr, askTermsSKLen)
	for i := 0; i < askTermsSKLen; i++ {
		offset := i * frCompressedSize
		askTermSKBytes := askTermsSKBytes[offset : offset+frCompressedSize]
		askTermsSK[i] = parseFr(askTermSKBytes)
	}

	return &PerPartyPresignature{
		AShare:     aShare,
		EShare:     eShare,
		SShare:     sShare,
		AeTermOwn:  aeTermOwn,
		AsTermOwn:  asTermOwn,
		AskTermOwn: askTermOwn,
		AeTermsA:   aeTermsA,
		AeTermsE:   aeTermsE,
		AsTermsA:   asTermsA,
		AsTermsS:   asTermsS,
		AskTermsA:  askTermsA,
		AskTermsSK: askTermsSK,
	}, nil
}

func (ppp *PerPartyPresignature) ToBytes() ([]byte, error) {
	// Serialize AShare
	aShareBytes := ppp.AShare.Bytes()

	// Serialize EShare
	eShareBytes := ppp.EShare.Bytes()

	// Serialize sShare
	sShareBytes := ppp.SShare.Bytes()

	// Serialize AeTermOwn
	aeTermOwnBytes := ppp.AeTermOwn.Bytes()

	// Serialize AsTermOwn
	asTermOwnBytes := ppp.AsTermOwn.Bytes()

	// Serialize AskTermOwn
	askTermOwnBytes := ppp.AskTermOwn.Bytes()

	// Serialize AeTermsA
	aeTermsALenBytes := make([]byte, intSize)
	binary.LittleEndian.PutUint32(aeTermsALenBytes, uint32(len(ppp.AeTermsA)))
	var aeTermsABytes []byte
	for _, aeTermA := range ppp.AeTermsA {
		aeTermsABytes = append(aeTermsABytes, aeTermA.Bytes()...)
	}

	// Serialize AeTermsE
	aeTermsELenBytes := make([]byte, intSize)
	binary.LittleEndian.PutUint32(aeTermsELenBytes, uint32(len(ppp.AeTermsE)))
	var aeTermsEBytes []byte
	for _, aeTermE := range ppp.AeTermsE {
		aeTermsEBytes = append(aeTermsEBytes, aeTermE.Bytes()...)
	}
	// Serialize AsTermsA
	asTermsALenBytes := make([]byte, intSize)
	binary.LittleEndian.PutUint32(asTermsALenBytes, uint32(len(ppp.AsTermsA)))
	var asTermsABytes []byte
	for _, asTermA := range ppp.AsTermsA {
		asTermsABytes = append(asTermsABytes, asTermA.Bytes()...)
	}

	// Serialize AsTermsS
	asTermsSLenBytes := make([]byte, intSize)
	binary.LittleEndian.PutUint32(asTermsSLenBytes, uint32(len(ppp.AsTermsS)))
	var asTermsSBytes []byte
	for _, asTermS := range ppp.AsTermsS {
		asTermsSBytes = append(asTermsSBytes, asTermS.Bytes()...)
	}

	// Serialize AskTermsA
	askTermsALenBytes := make([]byte, intSize)
	binary.LittleEndian.PutUint32(askTermsALenBytes, uint32(len(ppp.AskTermsA)))
	var askTermsABytes []byte
	for _, askTermA := range ppp.AskTermsA {
		askTermsABytes = append(askTermsABytes, askTermA.Bytes()...)
	}

	// Serialize AskTermsSK
	askTermsSKLenBytes := make([]byte, intSize)
	binary.LittleEndian.PutUint32(askTermsSKLenBytes, uint32(len(ppp.AskTermsSK)))
	var askTermsSKBytes []byte
	for _, askTermSK := range ppp.AskTermsSK {
		askTermsSKBytes = append(askTermsSKBytes, askTermSK.Bytes()...)
	}

	serialized := append(aeTermsALenBytes, aeTermsELenBytes...)
	serialized = append(serialized, asTermsALenBytes...)
	serialized = append(serialized, asTermsSLenBytes...)
	serialized = append(serialized, askTermsALenBytes...)
	serialized = append(serialized, askTermsSKLenBytes...)
	serialized = append(serialized, aShareBytes...)
	serialized = append(serialized, eShareBytes...)
	serialized = append(serialized, sShareBytes...)
	serialized = append(serialized, aeTermOwnBytes...)
	serialized = append(serialized, asTermOwnBytes...)
	serialized = append(serialized, askTermOwnBytes...)
	serialized = append(serialized, aeTermsABytes...)
	serialized = append(serialized, aeTermsEBytes...)
	serialized = append(serialized, asTermsABytes...)
	serialized = append(serialized, asTermsSBytes...)
	serialized = append(serialized, askTermsABytes...)
	serialized = append(serialized, askTermsSKBytes...)

	if len(serialized) < intSize*6+frCompressedSize*
		(6+len(ppp.AeTermsA)+len(ppp.AeTermsE)+
			len(ppp.AsTermsA)+len(ppp.AsTermsS)+
			len(ppp.AskTermsA)+len(ppp.AskTermsSK)) {
		return nil, errors.New("invalid size of presignature")
	}
	return serialized, nil
}

type PerPartyPrecomputations struct {
	Index         int // Position at which sk-polynomial for own secret key share is evaluated.
	SkShare       *ml.Zr
	PublicKey     *ml.G2
	Presignatures []*PerPartyPresignature
}

func ParsePerPartyPrecomputations(pppBytes []byte) (*PerPartyPrecomputations, error) {
	if len(pppBytes) < 2*intSize+frCompressedSize+g2CompressedSize {
		return nil, errors.New("input data is too short to represent the PerPartyPrecomputation")
	}

	preSigsLen := int(binary.LittleEndian.Uint32(pppBytes[:4]))
	index := int(binary.LittleEndian.Uint32(pppBytes[4:8]))
	skShare := parseFr(pppBytes[8 : 8+frCompressedSize])
	publicKey, err := curve.NewG2FromCompressed(pppBytes[8+frCompressedSize : 8+frCompressedSize+g2CompressedSize])
	if err != nil {
		return nil, err
	}
	var presignatures []*PerPartyPresignature

	preSigsBytes := pppBytes[8+frCompressedSize+g2CompressedSize:]
	if len(preSigsBytes) < 4*preSigsLen {
		return nil, errors.New("input presignatures too short")
	}
	for i := 0; i < preSigsLen; i++ {
		preSigLen := int(binary.LittleEndian.Uint32(preSigsBytes[:intSize]))
		presignature, err := ParsePerPartyPresignature(preSigsBytes[intSize : intSize+preSigLen])
		if err != nil {
			return nil, err
		}
		preSigsBytes = preSigsBytes[intSize+preSigLen:]
		presignatures = append(presignatures, presignature)
	}

	return &PerPartyPrecomputations{
		Index:         index,
		SkShare:       skShare,
		PublicKey:     publicKey,
		Presignatures: presignatures,
	}, nil
}

func (ppp *PerPartyPrecomputations) ToBytes() ([]byte, error) {
	preSigsLenBytes := make([]byte, intSize)
	binary.LittleEndian.PutUint32(preSigsLenBytes, uint32(len(ppp.Presignatures)))
	indexBytes := make([]byte, intSize)
	binary.LittleEndian.PutUint32(indexBytes, uint32(ppp.Index))

	skShareBytes := ppp.SkShare.Bytes()

	pubKeyBytes := ppp.PublicKey.Compressed()

	var preSigsBytes []byte
	for _, presignature := range ppp.Presignatures {
		preSigBytes, err := presignature.ToBytes()
		if err != nil {
			return nil, err
		}
		preSigLenBytes := make([]byte, intSize)
		binary.LittleEndian.PutUint32(preSigLenBytes, uint32(len(preSigBytes)))
		preSigsBytes = append(preSigsBytes, preSigLenBytes...)
		preSigsBytes = append(preSigsBytes, preSigBytes...)
	}

	result := append(preSigsLenBytes, indexBytes...)
	result = append(result, skShareBytes...)
	result = append(result, pubKeyBytes...)
	result = append(result, preSigsBytes...)
	return result, nil
}

func (ppp *PerPartyPrecomputations) PartyPrivateKey() *PartyPrivateKey {
	return &PartyPrivateKey{
		SKShare:   ppp.SkShare,
		publicKey: ppp.PublicKey,
		Index:     ppp.Index,
	}
}

type LivePresignature struct {
	AShare     *ml.Zr
	EShare     *ml.Zr
	SShare     *ml.Zr
	DeltaShare *ml.Zr
	AlphaShare *ml.Zr
}

func ParseLivePresignature(livePresigBytes []byte) (*LivePresignature, error) {
	if len(livePresigBytes) != bbsplusThresholdLivePresignatureLen {
		return nil, errors.New("invalid size of live presignature")
	}

	aShare := parseFr(livePresigBytes[:frCompressedSize])
	eShare := parseFr(livePresigBytes[frCompressedSize : frCompressedSize*2])
	sShare := parseFr(livePresigBytes[frCompressedSize*2 : frCompressedSize*3])
	deltaShare := parseFr(livePresigBytes[frCompressedSize*3 : frCompressedSize*4])
	alphaShare := parseFr(livePresigBytes[frCompressedSize*4 : frCompressedSize*5])

	return &LivePresignature{
		AShare:     aShare,
		EShare:     eShare,
		SShare:     sShare,
		DeltaShare: deltaShare,
		AlphaShare: alphaShare,
	}, nil
}

func (lp *LivePresignature) ToBytes() ([]byte, error) {
	bytes := make([]byte, bbsplusThresholdLivePresignatureLen)
	copy(bytes, lp.AShare.Bytes())
	copy(bytes[frCompressedSize:frCompressedSize*2], lp.EShare.Bytes())
	copy(bytes[frCompressedSize*2:frCompressedSize*3], lp.SShare.Bytes())
	copy(bytes[frCompressedSize*3:frCompressedSize*4], lp.DeltaShare.Bytes())
	copy(bytes[frCompressedSize*4:frCompressedSize*5], lp.AlphaShare.Bytes())
	return bytes, nil
}

func NewLivePresignature(
	ownIndex int,
	indices []int,
	presignature *PerPartyPresignature) *LivePresignature {
	lagrangeCoefficients := Get0LagrangeCoefficientSetFr(indices)
	return newLivePresignatureWithCoefficients(ownIndex, indices, presignature, lagrangeCoefficients)
}

func newLivePresignatureWithCoefficients(
	ownIndex int,
	indices []int,
	presignature *PerPartyPresignature,
	lagrangeCoefficients []*ml.Zr) *LivePresignature {

	// For (ae,as = alpha)-shares start with the multiplication of both own shares
	alphaShare := presignature.AsTermOwn.Copy()
	aeShare := presignature.AeTermOwn.Copy()

	// ASK-Share is split into a part which is to multiplied with own-index-lagrange and one which directly gets
	// other-index-lagrange.
	askShare := curve.NewZrFromInt(0)
	tmpAskOwnCoefficient := presignature.AskTermOwn.Copy()

	indI := 0
	for indJ, elJ := range indices {
		if elJ != ownIndex {
			// Add shares of a_i * e/s_j (ae/s_terms_a), a_j * e_i (ae/s_terms_a/s)
			aeShare = aeShare.Plus(presignature.AeTermsA[elJ-1])
			aeShare = aeShare.Plus(presignature.AeTermsE[elJ-1])
			aeShare.Mod(curve.GroupOrder)
			alphaShare = alphaShare.Plus(presignature.AsTermsA[elJ-1])
			alphaShare = alphaShare.Plus(presignature.AsTermsS[elJ-1])
			alphaShare.Mod(curve.GroupOrder)

			// Share of  a_i * sk_j (using j's lagrange coefficient) is added to share_of_ask
			tmp := presignature.AskTermsA[elJ-1].Copy()
			tmp = tmp.Mul(lagrangeCoefficients[indJ])
			tmp.Mod(curve.GroupOrder)

			askShare = askShare.Plus(tmp)
			askShare.Mod(curve.GroupOrder)
			// Share of a_j * sk_i (using i's lagrange coefficient) is added to tmp_ask_own_lagrange (coefficient is
			// applied later for all at once).
			tmpAskOwnCoefficient = tmpAskOwnCoefficient.Plus(presignature.AskTermsSK[elJ-1])
			tmpAskOwnCoefficient.Mod(curve.GroupOrder)
		} else {
			indI = indJ
		}
	}
	// Apply i's lagrange coefficient to sum of share of all cross-terms incorporating sk_i and add result to share of ask.
	tmpAskOwnCoefficient = tmpAskOwnCoefficient.Mul(lagrangeCoefficients[indI])
	tmpAskOwnCoefficient.Mod(curve.GroupOrder)
	askShare = askShare.Plus(tmpAskOwnCoefficient)
	askShare.Mod(curve.GroupOrder)

	// Compute delta_share
	deltaShare := aeShare.Copy()
	deltaShare = deltaShare.Plus(askShare)
	deltaShare.Mod(curve.GroupOrder)

	return &LivePresignature{
		AShare:     presignature.AShare,
		EShare:     presignature.EShare,
		SShare:     presignature.SShare,
		DeltaShare: deltaShare,
		AlphaShare: alphaShare,
	}
}
