package bls12381

// swuMapG1Pre is implementation of Simplified Shallue-van de Woestijne-Ulas Method
// follows the implementation at draft-irtf-cfrg-hash-to-curve-06.
// The swuMapG1 function is modified to perform the sign correction outside.
func swuMapG1Pre(u *fe) (*fe, *fe, *fe) {
	var params = swuParamsForG1
	var tv [4]*fe
	for i := 0; i < 4; i++ {
		tv[i] = new(fe)
	}
	square(tv[0], u)
	mul(tv[0], tv[0], params.z)
	square(tv[1], tv[0])
	x1 := new(fe)
	add(x1, tv[0], tv[1])
	inverse(x1, x1)
	e1 := x1.isZero()
	one := new(fe).one()
	add(x1, x1, one)
	if e1 {
		x1.set(params.zInv)
	}
	mul(x1, x1, params.minusBOverA)
	gx1 := new(fe)
	square(gx1, x1)
	add(gx1, gx1, params.a)
	mul(gx1, gx1, x1)
	add(gx1, gx1, params.b)
	x2 := new(fe)
	mul(x2, tv[0], x1)
	mul(tv[1], tv[0], tv[1])
	gx2 := new(fe)
	mul(gx2, gx1, tv[1])
	e2 := !isQuadraticNonResidue(gx1)
	x, y2 := new(fe), new(fe)
	if e2 {
		x.set(x1)
		y2.set(gx1)
	} else {
		x.set(x2)
		y2.set(gx2)
	}
	y := new(fe)
	sqrt(y, y2)

	// This function is modified to perform the sign correction outside.
	return x, y, u
}
