package bbsplusthresholdpub

import (
	"crypto/rand"

	ml "github.com/IBM/mathlib"
)

// GetLagrangeCoefficientFr computes the lagrange coefficient that is to be applied to the evaluation of the polynomial
// at position evaluation_x for an interpolation to position interpolation_x if the available evaluated positions are
// defined by indices.
func GetLagrangeCoefficientFr(indices []int, evaluationX int, interpolationX int) *ml.Zr {
	top := curve.NewZrFromInt(1)
	bot := curve.NewZrFromInt(1)

	for _, index := range indices {
		if index != evaluationX {
			tmpTop := curve.NewZrFromInt(int64(interpolationX))
			tmpTop = tmpTop.Minus(curve.NewZrFromInt(int64(index)))
			top = top.Mul(tmpTop)

			tmpBot := curve.NewZrFromInt(int64(evaluationX))
			tmpBot = tmpBot.Minus(curve.NewZrFromInt(int64(index)))
			bot = bot.Mul(tmpBot)
		}
	}
	botInv := bot.Copy()
	botInv.InvModP(curve.GroupOrder)
	top = top.Mul(botInv)

	return top
}

// Get0LagrangeCoefficientFr computes the lagrange coefficient that is to be applied to the evaluation of the polynomial
// at position evaluation_x for an interpolation to position 0 if the available evaluated positions are defined by indices.
func Get0LagrangeCoefficientFr(indices []int, evaluationX int) *ml.Zr {
	return GetLagrangeCoefficientFr(indices, evaluationX, 0)
}

// Get0LagrangeCoefficientSetFr computes all lagrange coefficients for an interpolation to position 0 if the available
// evaluated positions are defined by indices.
func Get0LagrangeCoefficientSetFr(indices []int) []*ml.Zr {
	coefficients := make([]*ml.Zr, len(indices))
	for i, idx := range indices {
		coefficients[i] = Get0LagrangeCoefficientFr(indices, idx)
	}
	return coefficients
}

// GetShamirSharedRandomElement generates a t-out-of-n shamir secret sharing of a random element.
func GetShamirSharedRandomElement(t, n int) (*ml.Zr, []*ml.Zr) {
	// Generate the secret key element
	secretKeyElement := curve.NewRandomZr(rand.Reader)

	// Shamir Coefficients
	coefficients := make([]*ml.Zr, t-1)
	for i := 0; i < t-1; i++ {
		coefficients[i] = curve.NewRandomZr(rand.Reader)
	}

	// Shares
	shares := make([]*ml.Zr, n)
	for i := 0; i < n; i++ {
		share := secretKeyElement.Copy() // Share initialized with secret key element

		incrExponentiation := curve.NewZrFromInt(1)

		for j := 0; j < t-1; j++ {
			incrExponentiation = incrExponentiation.Mul(curve.NewZrFromInt(int64(i + 1)))
			tmp := coefficients[j].Copy()
			tmp = tmp.Mul(incrExponentiation)
			share = share.Plus(tmp)
		}
		share.Mod(curve.GroupOrder)
		shares[i] = share
	}
	return secretKeyElement, shares
}

func GetShamirSharedRandomElementFromPrivKey(privKey *ml.Zr, t, n int) []*ml.Zr {
	// Shamir Coefficients
	coefficients := make([]*ml.Zr, t-1)
	for i := 0; i < t-1; i++ {
		coefficients[i] = curve.NewRandomZr(rand.Reader)
	}

	// Shares
	shares := make([]*ml.Zr, n)
	for i := 0; i < n; i++ {
		share := privKey.Copy() // Share initialized with secret key element
		incrExponentiation := curve.NewZrFromInt(1)
		for j := 0; j < t-1; j++ {
			incrExponentiation = incrExponentiation.Mul(curve.NewZrFromInt(int64(i + 1)))
			tmp := coefficients[j].Copy()
			tmp = tmp.Mul(incrExponentiation)
			share = share.Plus(tmp)
		}
		share.Mod(curve.GroupOrder)
		shares[i] = share
	}
	return shares
}
