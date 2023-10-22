package bbsplusthresholdpub

import (
	"crypto/rand"

	ml "github.com/IBM/mathlib"
)

type OLECorrelation struct {
	U *ml.Zr
	V *ml.Zr
}

// MakeAllPartiesOLE generates OLE correlations for all parties based on input data.
func MakeAllPartiesOLE(k, n int, x, y [][]*ml.Zr) [][][]*OLECorrelation {
	if k != len(x) {
		panic("make_all_parties_vole got ill-structured input format x.len() != k")
	}

	if k != len(y) {
		panic("make_all_parties_vole got ill-structured input format y.len() != k")
	}

	voleCorrelation := make([][][]*OLECorrelation, k)

	for i := 0; i < k; i++ {
		if n != len(x[i]) {
			panic("MakeAllPartiesOLE got ill-structured input format x[i_k].len() != n")
		}
		if n != len(y[i]) {
			panic("MakeAllPartiesOLE got ill-structured input format y[i].len() != n")
		}

		voleCorrelation[i] = make([][]*OLECorrelation, n)
		for j := 0; j < n; j++ {
			voleCorrelation[i][j] = make([]*OLECorrelation, n)
			for l := 0; l < n; l++ {
				voleCorrelation[i][j][l] = makeOLESingle(x[i][j], y[i][l])
			}
		}
	}
	return voleCorrelation
}

// MakeAllPartiesVOLE Gets t elements and one scalar of each party (x[i_k][i]: element i_k of party i, y[i]: scalar of party i)
func MakeAllPartiesVOLE(k, n int, x [][]*ml.Zr, y []*ml.Zr) [][][]*OLECorrelation {
	if k != len(x) {
		panic("make_all_parties_vole got ill-structured input format x.len() != k")
	}
	if n != len(y) {
		panic("make_all_parties_vole got ill-structured input format y.len() != n")
	}
	voleCorrelation := make([][][]*OLECorrelation, k)
	for i := 0; i < k; i++ {
		if n != len(x[i]) {
			panic("make_all_parties_vole got ill-structured input format x[i_k].len() != n")
		}
		voleCorrelation[i] = make([][]*OLECorrelation, n)
		for j := 0; j < n; j++ {
			if n != len(y) {
				panic("make_all_parties_vole got ill-structured input format y[i].len() != n")
			}
			voleCorrelation[i][j] = make([]*OLECorrelation, n)
			for l := 0; l < n; l++ {
				voleCorrelation[i][j][l] = makeOLESingle(x[i][j], y[l])
			}
		}
	}
	return voleCorrelation
}

// makeOLESingle computes the OLE correlation for a single pair of field elements.
// For inputs x and y, it generates u,v such that x*y = u+v.
func makeOLESingle(x, y *ml.Zr) *OLECorrelation {
	u := curve.NewRandomZr(rand.Reader)
	v := x.Mul(y)
	v = v.Minus(u)
	v.Mod(curve.GroupOrder)
	return &OLECorrelation{u, v}
}
