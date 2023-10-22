package bbsplusthresholdpub_test

import (
	"crypto/rand"
	"testing"

	ml "github.com/IBM/mathlib"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbsplusthresholdpub"
	"github.com/stretchr/testify/require"
)

func TestAllPrecomputationGeneration(t *testing.T) {
	seed := make([]byte, 32)

	_, err := rand.Read(seed)
	if err != nil {
		panic(err)
	}

	indices := make([][]int, k)
	for i := 0; i < k; i++ {
		indices[i] = generateRandomIndices(threshold, n)
	}
	pubKey, privKey, _, err := generateKeyPairRandom(threshold, n, k)
	require.NoError(t, err)

	output := bbsplusthresholdpub.GeneratePCFPCGOutputFromPrivKey(privKey.FR, threshold, k, n)

	sk := output.Sk
	skShares := output.SkShares
	aShares := output.AShares
	eShares := output.EShares
	sShares := output.SShares
	aeTerms := output.AeTerms
	asTerms := output.AsTerms
	askTerms := output.AskTerms
	precomputations := bbsplusthresholdpub.CreatePPPrecomputationFromVOLEEvaluation(k, n,
		pubKey.PointG2,
		output.SkShares,
		output.AShares,
		output.EShares,
		output.SShares,
		output.AeTerms,
		output.AsTerms,
		output.AskTerms,
	)

	testPCFPCGOutputAeAsAsk(t, k, indices, sk, aShares, eShares, sShares, aeTerms, asTerms, askTerms)

	for iK := 0; iK < k; iK++ {
		testInterpolationForSk(t, sk, skShares, indices[iK])
	}

	testPerPartyPrecomputationsWithoutCoefficients(t, k, indices, precomputations,
		sk, aShares, eShares, sShares)
}

func testPCFPCGOutputAeAsAsk(t *testing.T,
	k int,
	indices [][]int,
	sk *ml.Zr,
	aShares, eShares, sShares [][]*ml.Zr,
	aeTerms, asTerms, askTerms [][][]*bbsplusthresholdpub.OLECorrelation,
) {
	for iK := 0; iK < k; iK++ {
		a := curve.NewZrFromInt(0)
		e := curve.NewZrFromInt(0)
		s := curve.NewZrFromInt(0)

		aeIndirect := curve.NewZrFromInt(0)
		asIndirect := curve.NewZrFromInt(0)
		askIndirect := curve.NewZrFromInt(0)

		for _, iN := range indices[iK] {
			a = a.Plus(aShares[iK][iN-1])
			e = e.Plus(eShares[iK][iN-1])
			s = s.Plus(sShares[iK][iN-1])
		}
		a.Mod(curve.GroupOrder)
		e.Mod(curve.GroupOrder)
		s.Mod(curve.GroupOrder)
		aIndirect := aShares[0][0].Plus(aShares[0][1])
		aIndirect.Mod(curve.GroupOrder)
		eIndirect := eShares[0][0].Plus(eShares[0][1])
		eIndirect.Mod(curve.GroupOrder)

		aeDirect := a.Mul(e)
		aeDirect.Mod(curve.GroupOrder)

		asDirect := a.Mul(s)
		asDirect.Mod(curve.GroupOrder)
		askDirect := a.Mul(sk)
		askDirect.Mod(curve.GroupOrder)

		for _, iN := range indices[iK] {
			for _, jN := range indices[iK] {
				tmpAE := aeTerms[iK][iN-1][jN-1].U.Plus(aeTerms[iK][iN-1][jN-1].V)
				tmpAE.Mod(curve.GroupOrder)
				tmpAS := asTerms[iK][iN-1][jN-1].U.Plus(asTerms[iK][iN-1][jN-1].V)
				tmpAS.Mod(curve.GroupOrder)
				tmpASK := askTerms[iK][iN-1][jN-1].U.Plus(askTerms[iK][iN-1][jN-1].V)
				tmpASK.Mod(curve.GroupOrder)
				lagrangeCoeff := bbsplusthresholdpub.Get0LagrangeCoefficientFr(indices[iK], jN)
				tmpASK = tmpASK.Mul(lagrangeCoeff)
				tmpASK.Mod(curve.GroupOrder)
				aeIndirect = aeIndirect.Plus(tmpAE)
				aeIndirect.Mod(curve.GroupOrder)

				asIndirect = asIndirect.Plus(tmpAS)
				asIndirect.Mod(curve.GroupOrder)

				askIndirect = askIndirect.Plus(tmpASK)
				askIndirect.Mod(curve.GroupOrder)
			}
		}

		if !aeDirect.Equals(aeIndirect) {
			t.Errorf("Computation of AE is not consistent")
		}

		if !asDirect.Equals(asIndirect) {
			t.Errorf("Computation of AS is not consistent")
		}

		if !askDirect.Equals(askIndirect) {
			t.Errorf("Computation of ASK is not consistent")
		}
	}
}

func testInterpolationForSk(t *testing.T, sk *ml.Zr, skShares []*ml.Zr, indices []int) {
	interpolationResult := curve.NewZrFromInt(0)
	for _, i := range indices {
		tmp := skShares[i-1].Copy()
		tmp = tmp.Mul(bbsplusthresholdpub.Get0LagrangeCoefficientFr(indices, i))
		interpolationResult = interpolationResult.Plus(tmp)
		interpolationResult.Mod(curve.GroupOrder)
	}
	if !sk.Equals(interpolationResult) {
		t.Errorf("Problems with interpolation")
	}
}

func testPerPartyPrecomputationsWithoutCoefficients(t *testing.T, k int, indices [][]int,
	precomputations []*bbsplusthresholdpub.PerPartyPrecomputations, sk *ml.Zr,
	aShares, eShares, sShares [][]*ml.Zr) {

	coefficients := make([][]*ml.Zr, len(indices))
	for i, idx := range indices {
		coefficients[i] = bbsplusthresholdpub.Get0LagrangeCoefficientSetFr(idx)
	}

	testPerPartyPrecomputationsWithCoefficients(
		t,
		k,
		indices,
		coefficients,
		precomputations,
		sk, aShares, eShares, sShares)
}

func testPerPartyPrecomputationsWithCoefficients(
	t *testing.T,
	k int,
	indices [][]int,
	coefficients [][]*ml.Zr,
	precomputations []*bbsplusthresholdpub.PerPartyPrecomputations,
	sk *ml.Zr,
	aShares, eShares, sShares [][]*ml.Zr,
) {
	for iK := 0; iK < k; iK++ {
		aDirect := curve.NewZrFromInt(0)
		eDirect := curve.NewZrFromInt(0)
		sDirect := curve.NewZrFromInt(0)
		aIndirect := curve.NewZrFromInt(0)
		eIndirect := curve.NewZrFromInt(0)
		sIndirect := curve.NewZrFromInt(0)
		aeIndirect := curve.NewZrFromInt(0)
		asIndirect := curve.NewZrFromInt(0)
		askIndirect := curve.NewZrFromInt(0)

		for _, elI := range indices[iK] {
			aDirect = aDirect.Plus(aShares[iK][elI-1])
			eDirect = eDirect.Plus(eShares[iK][elI-1])
			sDirect = sDirect.Plus(sShares[iK][elI-1])

			aIndirect = aIndirect.Plus(precomputations[elI-1].Presignatures[iK].AShare)
			eIndirect = eIndirect.Plus(precomputations[elI-1].Presignatures[iK].EShare)
			sIndirect = sIndirect.Plus(precomputations[elI-1].Presignatures[iK].SShare)
		}

		aDirect.Mod(curve.GroupOrder)
		eDirect.Mod(curve.GroupOrder)
		sDirect.Mod(curve.GroupOrder)
		aIndirect.Mod(curve.GroupOrder)
		eIndirect.Mod(curve.GroupOrder)
		sIndirect.Mod(curve.GroupOrder)

		aeDirect := aDirect.Copy()
		aeDirect = aeDirect.Mul(eDirect)
		aeDirect.Mod(curve.GroupOrder)

		asDirect := aDirect.Copy()
		asDirect = asDirect.Mul(sDirect)
		asDirect.Mod(curve.GroupOrder)

		askDirect := aDirect.Copy()
		askDirect = askDirect.Mul(sk)
		askDirect.Mod(curve.GroupOrder)

		//Compute share of each party and add it to the total
		for indI, elI := range indices[iK] {
			//For (ae,as)-shares start with the multiplication of both own shares
			shareOfAE := precomputations[elI-1].Presignatures[iK].AeTermOwn.Copy()
			shareOfAS := precomputations[elI-1].Presignatures[iK].AsTermOwn.Copy()

			// ASK-Share is split into a part which is to multiplied with own-index-lagrange and one which directly gets other-index-lagrange
			shareOfAsk := curve.NewZrFromInt(0)
			tmpAskOwnLagrange := precomputations[elI-1].Presignatures[iK].AskTermOwn.Copy() // Own-index-lagrange starts with multiplication of both own shares

			for indJ, elJ := range indices[iK] {
				if elJ != elI {
					// Add shares of a_i * e/s_j (ae/sTermsA), a_j * e_i (ae/sTermsA/s)
					shareOfAE = shareOfAE.Plus(precomputations[elI-1].Presignatures[iK].AeTermsA[elJ-1])
					shareOfAE = shareOfAE.Plus(precomputations[elI-1].Presignatures[iK].AeTermsE[elJ-1])
					shareOfAE.Mod(curve.GroupOrder)
					shareOfAS = shareOfAS.Plus(precomputations[elI-1].Presignatures[iK].AsTermsA[elJ-1])
					shareOfAS = shareOfAS.Plus(precomputations[elI-1].Presignatures[iK].AsTermsS[elJ-1])
					shareOfAS.Mod(curve.GroupOrder)
					// Share of a_i * sk_j (using j's lagrange coefficient) is added to shareOfAsk
					tmp := precomputations[elI-1].Presignatures[iK].AskTermsA[elJ-1].Copy()
					tmp = tmp.Mul(coefficients[iK][indJ])
					tmp.Mod(curve.GroupOrder)
					shareOfAsk = shareOfAsk.Plus(tmp)
					shareOfAsk.Mod(curve.GroupOrder)
					//Share of a_j * sk_i (using i's lagrange coefficeint) is added to tmp_ask_own_lagrange (coefficient is applied later for all at once)
					tmpAskOwnLagrange = tmpAskOwnLagrange.Plus(precomputations[elI-1].Presignatures[iK].AskTermsSK[elJ-1])
					tmpAskOwnLagrange.Mod(curve.GroupOrder)
				}
			}

			//Apply i's lagrange coefficient to sum of share of all cross-terms incoperating sk_i and add result to share of ask
			tmpAskOwnLagrange = tmpAskOwnLagrange.Mul(coefficients[iK][indI])
			tmpAskOwnLagrange.Mod(curve.GroupOrder)
			shareOfAsk = shareOfAsk.Plus(tmpAskOwnLagrange)
			shareOfAsk.Mod(curve.GroupOrder)
			// Add computed share of ae/as/ask to the computation of ae/as/ask
			aeIndirect = aeIndirect.Plus(shareOfAE)
			aeIndirect.Mod(curve.GroupOrder)
			asIndirect = asIndirect.Plus(shareOfAS)
			asIndirect.Mod(curve.GroupOrder)
			askIndirect = askIndirect.Plus(shareOfAsk)
			askIndirect.Mod(curve.GroupOrder)
		}

		if !aDirect.Equals(aIndirect) {
			t.Errorf("Computation of A is not consistent")
		}
		if !eDirect.Equals(eIndirect) {
			t.Errorf("Computation of E is not consistent")
		}
		if !sDirect.Equals(sIndirect) {
			t.Errorf("Computation of S is not consistent")
		}
		if !aeDirect.Equals(aeIndirect) {
			t.Errorf("Computation of AE is not consistent")
		}
		if !asDirect.Equals(asIndirect) {
			t.Errorf("Computation of AS is not consistent")
		}
		if !askDirect.Equals(askIndirect) {
			t.Errorf("Computation of ASK is not consistent")
		}
	}

}
