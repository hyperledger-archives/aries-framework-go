/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bls12381

import (
	"hash"
)

func HashToCurve(msg, domain []byte, hashFunc func() hash.Hash) ([]byte, error) {
	hashRes, err := hashToFpXMD(hashFunc, msg, domain, 2)
	if err != nil {
		return nil, err
	}
	u0, u1 := hashRes[0], hashRes[1]

	p0, p1 := osswuMap(u0), osswuMap(u1)
	Add(p0, p0, p1)
	Affine(p0)
	isogenyMapG1(&p0[0], &p0[1])
	ClearCofactor(p0)
	return ToBytes(Affine(p0)), nil
}

// Algorithm is re-written from Rust code (https://github.com/algorand/pairing-plus/blob/7ec2ae03aae4ba2fc5210810211478171ccededf/src/bls12_381/osswu_map/g1.rs#L48).
func osswuMap(u *fe) *PointG1 {
	var params = swuParamsForG1

	usq := new(fe)
	square(usq, u)

	xi_usq := new(fe)
	mul(xi_usq, usq, params.z) // XI

	xi2_u4 := new(fe)
	square(xi2_u4, xi_usq)

	nd_common := new(fe)
	add(nd_common, xi_usq, xi2_u4)

	x0_num := new(fe)
	add(x0_num, nd_common, new(fe).one())
	mul(x0_num, x0_num, params.b) // ELLP_B

	x0_den := new(fe)
	if nd_common.isZero() {
		mul(x0_den, params.a, params.z) // ELLP_A, XI
	} else {
		mul(x0_den, params.a, nd_common) // ELLP_A
		neg(x0_den, x0_den)
	}

	gx0_den_sq := new(fe)
	square(gx0_den_sq, x0_den)
	gx0_den := new(fe)
	mul(gx0_den, gx0_den_sq, x0_den)

	gx0_num := new(fe)
	mul(gx0_num, gx0_den, params.b) // ELLP_B
	tmp2 := new(fe)
	mul(tmp2, gx0_den_sq, x0_num)
	mul(tmp2, tmp2, params.a) // ELLP_A

	add(gx0_num, gx0_num, tmp2)

	square(tmp2, x0_num)
	mul(tmp2, tmp2, x0_num)

	add(gx0_num, gx0_num, tmp2)

	sqrt_candidate := func() *fe {
		tmp1 := new(fe)
		mul(tmp1, gx0_num, gx0_den)

		tmp2 := new(fe)
		square(tmp2, gx0_den)
		mul(tmp2, tmp2, tmp1)

		tmp3 := new(fe)
		*tmp3 = *tmp2

		chain_pm3div4(tmp2, tmp3)

		mul(tmp2, tmp2, tmp1)

		return tmp2
	}()

	test_cand := new(fe)
	square(test_cand, sqrt_candidate)
	mul(test_cand, test_cand, gx0_den)

	x_num, y := new(fe), new(fe)
	if test_cand.equal(gx0_num) {
		x_num = x0_num
		y = sqrt_candidate
	} else {
		mul(x_num, x0_num, xi_usq)

		mul(y, usq, u)
		mul(y, y, sqrt_candidate)
		mul(y, y, SQRT_M_XI_CUBED)
	}

	if y.signBE() != u.signBE() {
		neg(y, y)
	}

	mul(x_num, x_num, x0_den)
	mul(y, y, gx0_den)

	return &PointG1{
		*x_num,
		*y,
		*x0_den,
	}
}

var SQRT_M_XI_CUBED = &fe{
	0x43b571cad3215f1f,
	0xccb460ef1c702dc2,
	0x742d884f4f97100b,
	0xdb2c3e3238a3382b,
	0xe40f3fa13fce8f88,
	0x73a2af9892a2ff,
}

// Algorithm is re-written from Rust code (https://github.com/algorand/pairing-plus/blob/master/src/bls12_381/osswu_map/chain.rs#L14).
func chain_pm3div4(tmpvar1, tmpvar0 *fe) {
	square(tmpvar1, tmpvar0)

	tmpvar9 := new(fe)
	mul(tmpvar9, tmpvar1, tmpvar0)

	tmpvar5 := new(fe)
	square(tmpvar5, tmpvar1)

	tmpvar2 := new(fe)
	mul(tmpvar2, tmpvar9, tmpvar1)

	tmpvar7 := new(fe)
	mul(tmpvar7, tmpvar5, tmpvar9)

	tmpvar10 := new(fe)
	mul(tmpvar10, tmpvar2, tmpvar5)

	tmpvar13 := new(fe)
	mul(tmpvar13, tmpvar7, tmpvar5)

	tmpvar4 := new(fe)
	mul(tmpvar4, tmpvar10, tmpvar5)

	tmpvar8 := new(fe)
	mul(tmpvar8, tmpvar13, tmpvar5)

	tmpvar15 := new(fe)
	mul(tmpvar15, tmpvar4, tmpvar5)

	tmpvar11 := new(fe)
	mul(tmpvar11, tmpvar8, tmpvar5)

	tmpvar3 := new(fe)
	mul(tmpvar3, tmpvar15, tmpvar5)

	tmpvar12 := new(fe)
	mul(tmpvar12, tmpvar11, tmpvar5)

	tmpvar14 := new(fe)
	mul(tmpvar14, tmpvar12, tmpvar5)

	square(tmpvar1, tmpvar4)

	tmpvar6 := new(fe)
	mul(tmpvar6, tmpvar1, tmpvar9)

	mul(tmpvar5, tmpvar1, tmpvar2)

	for i := 0; i < 12; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar15)

	for i := 0; i < 7; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar8)

	for i := 0; i < 4; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar2)

	for i := 0; i < 6; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar7)

	for i := 0; i < 7; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar12)

	for i := 0; i < 5; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar5)

	for i := 0; i < 2; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar9)

	for i := 0; i < 6; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar4)

	for i := 0; i < 6; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar4)

	for i := 0; i < 6; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar10)

	for i := 0; i < 3; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar9)

	for i := 0; i < 7; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar4)

	for i := 0; i < 4; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar4)

	for i := 0; i < 6; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar8)

	for i := 0; i < 6; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar14)

	for i := 0; i < 3; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar0)

	for i := 0; i < 8; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar4)

	for i := 0; i < 7; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar12)

	for i := 0; i < 5; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar13)

	for i := 0; i < 6; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar4)

	for i := 0; i < 6; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar6)

	for i := 0; i < 4; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar10)

	for i := 0; i < 8; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar6)

	for i := 0; i < 4; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar4)

	for i := 0; i < 7; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar12)

	for i := 0; i < 9; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar11)

	for i := 0; i < 2; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar9)

	for i := 0; i < 5; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar7)

	for i := 0; i < 7; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar2)

	for i := 0; i < 7; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar10)

	for i := 0; i < 6; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar12)

	for i := 0; i < 5; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar6)

	for i := 0; i < 5; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar11)

	for i := 0; i < 5; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar11)

	for i := 0; i < 8; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar4)

	for i := 0; i < 7; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar3)

	for i := 0; i < 9; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar8)

	for i := 0; i < 5; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar4)

	for i := 0; i < 3; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar9)

	for i := 0; i < 8; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar8)

	for i := 0; i < 3; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar9)

	for i := 0; i < 7; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar10)

	for i := 0; i < 9; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar8)

	for i := 0; i < 6; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar3)

	for i := 0; i < 6; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar5)

	for i := 0; i < 5; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar5)

	for i := 0; i < 5; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar5)

	for i := 0; i < 4; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar4)

	for i := 0; i < 3; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar9)

	for i := 0; i < 8; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar3)

	for i := 0; i < 7; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar5)

	for i := 0; i < 5; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar5)

	for i := 0; i < 5; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar5)

	for i := 0; i < 4; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar8)

	for i := 0; i < 4; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar7)

	for i := 0; i < 7; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar5)

	for i := 0; i < 5; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar6)

	for i := 0; i < 5; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar5)

	for i := 0; i < 5; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar5)

	for i := 0; i < 5; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar5)

	for i := 0; i < 5; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar5)

	for i := 0; i < 5; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar5)

	for i := 0; i < 5; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar5)

	for i := 0; i < 4; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar4)

	for i := 0; i < 6; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar3)

	for i := 0; i < 4; i++ {
		square(tmpvar1, tmpvar1)
	}
	mul(tmpvar1, tmpvar1, tmpvar2)

	square(tmpvar1, tmpvar1)
}
