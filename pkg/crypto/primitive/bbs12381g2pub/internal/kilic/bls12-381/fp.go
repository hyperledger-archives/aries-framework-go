/*
Taken from https://github.com/kilic/bls12-381/blob/master/fp.go
(rev 63668807ad6a84b02b1d905373956f2ae8eb2afa)

SPDX-License-Identifier: Apache-2.0
(https://github.com/kilic/bls12-381/blob/master/LICENSE)
*/

package bls12381

import (
	"errors"
	"math/big"
)

func fromBytes(in []byte) (*fe, error) {
	fe := &fe{}
	if len(in) != fpByteSize {
		return nil, errors.New("input string should be equal 48 bytes")
	}
	fe.setBytes(in)
	if !fe.isValid() {
		return nil, errors.New("must be less than modulus")
	}
	toMont(fe, fe)
	return fe, nil
}

func from64Bytes(in []byte) (*fe, error) {
	if len(in) != 32*2 {
		return nil, errors.New("input string should be equal 64 bytes")
	}
	a0 := make([]byte, fpByteSize)
	copy(a0[fpByteSize-32:fpByteSize], in[:32])
	a1 := make([]byte, fpByteSize)
	copy(a1[fpByteSize-32:fpByteSize], in[32:])
	e0, err := fromBytes(a0)
	if err != nil {
		return nil, err
	}
	e1, err := fromBytes(a1)
	if err != nil {
		return nil, err
	}
	// F = 2 ^ 256 * R
	F := fe{
		0x75b3cd7c5ce820f,
		0x3ec6ba621c3edb0b,
		0x168a13d82bff6bce,
		0x87663c4bf8c449d2,
		0x15f34c83ddc8d830,
		0xf9628b49caa2e85,
	}

	mul(e0, e0, &F)
	add(e1, e1, e0)
	return e1, nil
}

func newTempG1() [9]*fe {
	t := [9]*fe{}

	for i := 0; i < 9; i++ {
		t[i] = &fe{}
	}

	return t
}

func toBytes(e *fe) []byte {
	e2 := new(fe)
	fromMont(e2, e)
	return e2.bytes()
}

func toBig(e *fe) *big.Int {
	e2 := new(fe)
	fromMont(e2, e)
	return e2.big()
}

func toMont(c, a *fe) {
	mul(c, a, r2)
}

func fromMont(c, a *fe) {
	mul(c, a, &fe{1})
}

func exp(c, a *fe, e *big.Int) {
	z := new(fe).set(r1)
	for i := e.BitLen(); i >= 0; i-- {
		mul(z, z, z)
		if e.Bit(i) == 1 {
			mul(z, z, a)
		}
	}
	c.set(z)
}

func inverse(inv, e *fe) {
	if e.isZero() {
		inv.zero()
		return
	}
	u := new(fe).set(&modulus)
	v := new(fe).set(e)
	s := &fe{1}
	r := &fe{0}
	var k int
	var z uint64
	var found = false
	// Phase 1
	for i := 0; i < sixWordBitSize*2; i++ {
		if v.isZero() {
			found = true
			break
		}
		if u.isEven() {
			u.div2(0)
			s.mul2()
		} else if v.isEven() {
			v.div2(0)
			z += r.mul2()
		} else if u.cmp(v) == 1 {
			lsubAssign(u, v)
			u.div2(0)
			laddAssign(r, s)
			s.mul2()
		} else {
			lsubAssign(v, u)
			v.div2(0)
			laddAssign(s, r)
			z += r.mul2()
		}
		k += 1
	}

	if !found {
		inv.zero()
		return
	}

	if k < fpBitSize || k > fpBitSize+sixWordBitSize {
		inv.zero()
		return
	}

	if r.cmp(&modulus) != -1 || z > 0 {
		lsubAssign(r, &modulus)
	}
	u.set(&modulus)
	lsubAssign(u, r)

	// Phase 2
	for i := k; i < 2*sixWordBitSize; i++ {
		double(u, u)
	}
	inv.set(u)
}

func sqrt(c, a *fe) bool {
	u, v := new(fe).set(a), new(fe)
	// a ^ (p - 3) / 4
	sqrtAddchain(c, a)
	// a ^ (p + 1) / 4
	mul(c, c, u)

	square(v, c)
	return u.equal(v)
}

func sqrtAddchain(c, a *fe) {
	chain := func(c *fe, n int, a *fe) {
		for i := 0; i < n; i++ {
			square(c, c)
		}
		mul(c, c, a)
	}

	t := make([]fe, 16)
	t[13].set(a)
	square(&t[0], &t[13])
	mul(&t[8], &t[0], &t[13])
	square(&t[4], &t[0])
	mul(&t[1], &t[8], &t[0])
	mul(&t[6], &t[4], &t[8])
	mul(&t[9], &t[1], &t[4])
	mul(&t[12], &t[6], &t[4])
	mul(&t[3], &t[9], &t[4])
	mul(&t[7], &t[12], &t[4])
	mul(&t[15], &t[3], &t[4])
	mul(&t[10], &t[7], &t[4])
	mul(&t[2], &t[15], &t[4])
	mul(&t[11], &t[10], &t[4])
	square(&t[0], &t[3])
	mul(&t[14], &t[11], &t[4])
	mul(&t[5], &t[0], &t[8])
	mul(&t[4], &t[0], &t[1])

	chain(&t[0], 12, &t[15])
	chain(&t[0], 7, &t[7])
	chain(&t[0], 4, &t[1])
	chain(&t[0], 6, &t[6])
	chain(&t[0], 7, &t[11])
	chain(&t[0], 5, &t[4])
	chain(&t[0], 2, &t[8])
	chain(&t[0], 6, &t[3])
	chain(&t[0], 6, &t[3])
	chain(&t[0], 6, &t[9])
	chain(&t[0], 3, &t[8])
	chain(&t[0], 7, &t[3])
	chain(&t[0], 4, &t[3])
	chain(&t[0], 6, &t[7])
	chain(&t[0], 6, &t[14])
	chain(&t[0], 3, &t[13])
	chain(&t[0], 8, &t[3])
	chain(&t[0], 7, &t[11])
	chain(&t[0], 5, &t[12])
	chain(&t[0], 6, &t[3])
	chain(&t[0], 6, &t[5])
	chain(&t[0], 4, &t[9])
	chain(&t[0], 8, &t[5])
	chain(&t[0], 4, &t[3])
	chain(&t[0], 7, &t[11])
	chain(&t[0], 9, &t[10])
	chain(&t[0], 2, &t[8])
	chain(&t[0], 5, &t[6])
	chain(&t[0], 7, &t[1])
	chain(&t[0], 7, &t[9])
	chain(&t[0], 6, &t[11])
	chain(&t[0], 5, &t[5])
	chain(&t[0], 5, &t[10])
	chain(&t[0], 5, &t[10])
	chain(&t[0], 8, &t[3])
	chain(&t[0], 7, &t[2])
	chain(&t[0], 9, &t[7])
	chain(&t[0], 5, &t[3])
	chain(&t[0], 3, &t[8])
	chain(&t[0], 8, &t[7])
	chain(&t[0], 3, &t[8])
	chain(&t[0], 7, &t[9])
	chain(&t[0], 9, &t[7])
	chain(&t[0], 6, &t[2])
	chain(&t[0], 6, &t[4])
	chain(&t[0], 5, &t[4])
	chain(&t[0], 5, &t[4])
	chain(&t[0], 4, &t[3])
	chain(&t[0], 3, &t[8])
	chain(&t[0], 8, &t[2])
	chain(&t[0], 7, &t[4])
	chain(&t[0], 5, &t[4])
	chain(&t[0], 5, &t[4])
	chain(&t[0], 4, &t[7])
	chain(&t[0], 4, &t[6])
	chain(&t[0], 7, &t[4])
	chain(&t[0], 5, &t[5])
	chain(&t[0], 5, &t[4])
	chain(&t[0], 5, &t[4])
	chain(&t[0], 5, &t[4])
	chain(&t[0], 5, &t[4])
	chain(&t[0], 5, &t[4])
	chain(&t[0], 5, &t[4])
	chain(&t[0], 4, &t[3])
	chain(&t[0], 6, &t[2])
	chain(&t[0], 4, &t[1])
	square(c, &t[0])
}

func isQuadraticNonResidue(a *fe) bool {
	if a.isZero() {
		return true
	}
	return !sqrt(new(fe), a)
}
