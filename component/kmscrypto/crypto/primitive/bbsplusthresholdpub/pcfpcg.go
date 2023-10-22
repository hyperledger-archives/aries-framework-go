package bbsplusthresholdpub

import (
	ml "github.com/IBM/mathlib"
)

type PCFPCGOutput struct {
	Sk       *ml.Zr
	SkShares []*ml.Zr
	AShares  [][]*ml.Zr
	EShares  [][]*ml.Zr
	SShares  [][]*ml.Zr
	AeTerms  [][][]*OLECorrelation
	AsTerms  [][][]*OLECorrelation
	AskTerms [][][]*OLECorrelation
}

func GeneratePPPrecomputation(t, k, n int) (*ml.Zr, []*PerPartyPrecomputations) {
	output := GeneratePCFPCGOutput(t, k, n)
	pk := curve.GenG2.Mul(frToRepr(output.Sk))
	return output.Sk, CreatePPPrecomputationFromVOLEEvaluation(k, n,
		pk,
		output.SkShares,
		output.AShares,
		output.EShares,
		output.SShares,
		output.AeTerms,
		output.AsTerms,
		output.AskTerms,
	)
}

func GeneratePCFPCGOutput(t int, k int, n int) PCFPCGOutput {
	sk, skShares := GetShamirSharedRandomElement(t, n)
	aShares := GetRandomElements(k, n)
	eShares := GetRandomElements(k, n)
	sShares := GetRandomElements(k, n)
	aeTerms := MakeAllPartiesOLE(k, n, aShares, eShares)
	asTerms := MakeAllPartiesOLE(k, n, aShares, sShares)
	askTerms := MakeAllPartiesVOLE(k, n, aShares, skShares)

	return PCFPCGOutput{sk, skShares, aShares, eShares, sShares, aeTerms, asTerms, askTerms}
}

func CreatePPPrecomputationFromVOLEEvaluation(
	k int,
	n int,
	publicKey *ml.G2,
	skShares []*ml.Zr,
	aShares, eShares, sShares [][]*ml.Zr,
	aeTerms, asTerms, askTerms [][][]*OLECorrelation,
) []*PerPartyPrecomputations {
	precomputations := make([]*PerPartyPrecomputations, n)
	for iN := 0; iN < n; iN++ {
		presignaturesList := make([]*PerPartyPresignature, k)

		for iK := 0; iK < k; iK++ {
			aeTermOwn := aShares[iK][iN].Copy()
			aeTermOwn = aeTermOwn.Mul(eShares[iK][iN])
			aeTermOwn.Mod(curve.GroupOrder)

			asTermOwn := aShares[iK][iN].Copy()
			asTermOwn = asTermOwn.Mul(sShares[iK][iN])
			asTermOwn.Mod(curve.GroupOrder)

			askTermOwn := aShares[iK][iN].Copy()
			askTermOwn = askTermOwn.Mul(skShares[iN])
			askTermOwn.Mod(curve.GroupOrder)

			aeTermsA := make([]*ml.Zr, n)
			aeTermsE := make([]*ml.Zr, n)
			asTermsA := make([]*ml.Zr, n)
			asTermsS := make([]*ml.Zr, n)
			askTermsA := make([]*ml.Zr, n)
			askTermsSK := make([]*ml.Zr, n)

			for jN := 0; jN < n; jN++ {
				aeTermsA[jN] = aeTerms[iK][iN][jN].U.Copy()
				aeTermsE[jN] = aeTerms[iK][jN][iN].V.Copy()
				asTermsA[jN] = asTerms[iK][iN][jN].U.Copy()
				asTermsS[jN] = asTerms[iK][jN][iN].V.Copy()
				askTermsA[jN] = askTerms[iK][iN][jN].U.Copy()
				askTermsSK[jN] = askTerms[iK][jN][iN].V.Copy()
			}

			presignaturesList[iK] = &PerPartyPresignature{
				AShare:     aShares[iK][iN],
				EShare:     eShares[iK][iN],
				SShare:     sShares[iK][iN],
				AeTermOwn:  aeTermOwn,
				AsTermOwn:  asTermOwn,
				AskTermOwn: askTermOwn,
				AeTermsA:   aeTermsA,
				AeTermsE:   aeTermsE,
				AsTermsA:   asTermsA,
				AsTermsS:   asTermsS,
				AskTermsA:  askTermsA,
				AskTermsSK: askTermsSK,
			}
		}

		precomputations[iN] = &PerPartyPrecomputations{
			Index:         iN,
			SkShare:       skShares[iN],
			PublicKey:     publicKey,
			Presignatures: presignaturesList,
		}
	}

	return precomputations
}

func GeneratePCFPCGOutputFromPrivKey(sk *ml.Zr, t int, k int, n int) PCFPCGOutput {
	skShares := GetShamirSharedRandomElementFromPrivKey(sk, t, n)
	aShares := GetRandomElements(k, n)
	eShares := GetRandomElements(k, n)
	sShares := GetRandomElements(k, n)
	aeTerms := MakeAllPartiesOLE(k, n, aShares, eShares)
	asTerms := MakeAllPartiesOLE(k, n, aShares, sShares)
	askTerms := MakeAllPartiesVOLE(k, n, aShares, skShares)
	return PCFPCGOutput{sk, skShares, aShares, eShares, sShares, aeTerms, asTerms, askTerms}
}
