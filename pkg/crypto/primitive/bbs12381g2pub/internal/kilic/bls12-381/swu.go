/*
Taken from https://github.com/kilic/bls12-381/blob/master/swu.go
(rev a288617c07f1bd60613c43dbde211b4a911e4791)

SPDX-License-Identifier: Apache-2.0
(https://github.com/kilic/bls12-381/blob/master/LICENSE)

This file is modified to allow sign correction of swuMapG1 outside of the function.
*/

package bls12381

// swuMapG1Pre is implementation of Simplified Shallue-van de Woestijne-Ulas Method
// follows the implementation at draft-irtf-cfrg-hash-to-curve-06.
// This function is modified to perform the sign correction outside.
func swuMapG1Pre(u *fe) (*fe, *fe, *fe) {
	var params = swuParamsForG1
	var tv [4]*fe
	for i := 0; i < 4; i++ {
		tv[i] = new(fe)
	}
	square(tv[0], u)
	mul(tv[0], tv[0], params.z)
	square(tv[1], tv[0])
	x1 := new(fe) // x1 is x0_num
	add(x1, tv[0], tv[1])
	inverse(x1, x1)
	e1 := x1.isZero()
	one := new(fe).one()
	add(x1, x1, one)
	if e1 {
		x1.set(params.zInv)
	}
	mul(x1, x1, params.minusBOverA)
	gx1 := new(fe) // gx1 is sqrt_candidate
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

var swuParamsForG1 = struct {
	z           *fe
	zInv        *fe
	a           *fe
	b           *fe
	minusBOverA *fe
}{
	a:           &fe{0x2f65aa0e9af5aa51, 0x86464c2d1e8416c3, 0xb85ce591b7bd31e2, 0x27e11c91b5f24e7c, 0x28376eda6bfc1835, 0x155455c3e5071d85},
	b:           &fe{0xfb996971fe22a1e0, 0x9aa93eb35b742d6f, 0x8c476013de99c5c4, 0x873e27c3a221e571, 0xca72b5e45a52d888, 0x06824061418a386b},
	z:           &fe{0x886c00000023ffdc, 0x0f70008d3090001d, 0x77672417ed5828c3, 0x9dac23e943dc1740, 0x50553f1b9c131521, 0x078c712fbe0ab6e8},
	zInv:        &fe{0x0e8a2e8ba2e83e10, 0x5b28ba2ca4d745d1, 0x678cd5473847377a, 0x4c506dd8a8076116, 0x9bcb227d79284139, 0x0e8d3154b0ba099a},
	minusBOverA: &fe{0x052583c93555a7fe, 0x3b40d72430f93c82, 0x1b75faa0105ec983, 0x2527e7dc63851767, 0x99fffd1f34fc181d, 0x097cab54770ca0d3},
}
