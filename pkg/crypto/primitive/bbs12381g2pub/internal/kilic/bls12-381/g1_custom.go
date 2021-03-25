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

	x0, y0 := swuMapG1BE(u0)
	x1, y1 := swuMapG1BE(u1)
	one := new(fe).one()
	p0, p1 := &PointG1{*x0, *y0, *one}, &PointG1{*x1, *y1, *one}

	Add(p0, p0, p1)
	Affine(p0)
	isogenyMapG1(&p0[0], &p0[1])
	ClearCofactor(p0)
	return ToBytes(Affine(p0)), nil
}
