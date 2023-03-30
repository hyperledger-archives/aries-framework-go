/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bls12381

import (
	"hash"

	"golang.org/x/crypto/sha3"
)

func (g *G1) hashToCurveGeneric(msg, domain []byte, expand func([]byte, []byte, int) ([]byte, error)) (*PointG1, error) {
	hashRes, err := hashToFpGeneric(expand, msg, domain, 2)
	if err != nil {
		return nil, err
	}
	u0, u1 := hashRes[0], hashRes[1]

	x0, y0 := swuMapG1(u0)
	x1, y1 := swuMapG1(u1)
	one := new(fe).one()
	p0, p1 := &PointG1{*x0, *y0, *one}, &PointG1{*x1, *y1, *one}

	g.Add(p0, p0, p1)
	g.Affine(p0)
	isogenyMapG1(&p0[0], &p0[1])
	g.ClearCofactor(p0)
	return g.Affine(p0), nil
}

func (g *G1) HashToCurveGenericXMD(msg, domain []byte, hashFunc func() hash.Hash) (*PointG1, error) {
	expand := func(msg []byte, tag []byte, outLen int) ([]byte, error) {
		return expandMsgXMD(hashFunc, msg, tag, outLen)
	}
	return g.hashToCurveGeneric(msg, domain, expand)
}

func (g *G1) HashToCurveGenericXOF(msg, domain []byte, hash sha3.ShakeHash) (*PointG1, error) {
	expand := func(msg []byte, tag []byte, outLen int) ([]byte, error) {
		return ExpandMsgXOF(hash, msg, tag, outLen)
	}
	return g.hashToCurveGeneric(msg, domain, expand)
}
