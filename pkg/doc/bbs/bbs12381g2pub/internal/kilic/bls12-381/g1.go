/*
Taken from https://github.com/kilic/bls12-381/blob/master/g1.go
(rev a288617c07f1bd60613c43dbde211b4a911e4791)

Changes (placed separately at g1_custom.go).
1) Pass black2b as hash function for HashToCurve().
2) Custom implementation of osswuMap() (this algorithm is re-written from Rust code
(https://github.com/algorand/pairing-plus/blob/master/src/bls12_381/osswu_map/chain.rs#L14).

SPDX-License-Identifier: Apache-2.0
(https://github.com/kilic/bls12-381/blob/master/LICENSE)
*/

package bls12381

import (
	"math/big"
)

// PointG1 is type for point in G1 and used for both Affine and Jacobian point representation.
// A point is accounted as in affine form if z is equal to one.
type PointG1 [3]fe

func (p *PointG1) Set(p2 *PointG1) *PointG1 {
	p[0].set(&p2[0])
	p[1].set(&p2[1])
	p[2].set(&p2[2])
	return p
}

func (p *PointG1) Zero() *PointG1 {
	p[0].zero()
	p[1].one()
	p[2].zero()
	return p
}

// ToBytes serializes a point into bytes in uncompressed form.
// ToBytes returns (0, 0) if point is infinity.
func ToBytes(p *PointG1) []byte {
	out := make([]byte, 2*fpByteSize)
	if IsZero(p) {
		return out
	}
	Affine(p)
	copy(out[:fpByteSize], toBytes(&p[0]))
	copy(out[fpByteSize:], toBytes(&p[1]))
	return out
}

// ClearCofactor maps given a G1 point to correct subgroup
func ClearCofactor(p *PointG1) {
	MulScalarBig(p, p, cofactorEFFG1)
}

// MulScalar multiplies a point by given scalar value in big.Int and assigns the result to point at first argument.
func MulScalarBig(c, p *PointG1, e *big.Int) *PointG1 {
	q, n := &PointG1{}, &PointG1{}
	n.Set(p)
	l := e.BitLen()
	for i := 0; i < l; i++ {
		if e.Bit(i) == 1 {
			Add(q, q, n)
		}
		Double(n, n)
	}
	return c.Set(q)
}

// Double doubles a G1 point p and assigns the result to the point at first argument.
func Double(r, p *PointG1) *PointG1 {
	// http://www.hyperelliptic.org/EFD/gp/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
	if IsZero(p) {
		return r.Set(p)
	}
	t := newTempG1()
	square(t[0], &p[0])     // a = x^2
	square(t[1], &p[1])     // b = y^2
	square(t[2], t[1])      // c = b^2
	add(t[1], &p[0], t[1])  // b + x1
	square(t[1], t[1])      // (b + x1)^2
	subAssign(t[1], t[0])   // (b + x1)^2 - a
	subAssign(t[1], t[2])   // (b + x1)^2 - a - c
	doubleAssign(t[1])      // d = 2((b+x1)^2 - a - c)
	double(t[3], t[0])      // 2a
	addAssign(t[0], t[3])   // e = 3a
	square(t[4], t[0])      // f = e^2
	double(t[3], t[1])      // 2d
	sub(&r[0], t[4], t[3])  // x3 = f - 2d
	subAssign(t[1], &r[0])  // d-x3
	doubleAssign(t[2])      //
	doubleAssign(t[2])      //
	doubleAssign(t[2])      // 8c
	mul(t[0], t[0], t[1])   // e * (d - x3)
	sub(t[1], t[0], t[2])   // x3 = e * (d - x3) - 8c
	mul(t[0], &p[1], &p[2]) // y1 * z1
	r[1].set(t[1])          //
	double(&r[2], t[0])     // z3 = 2(y1 * z1)
	return r
}

// Affine returns the affine representation of the given point
func Affine(p *PointG1) *PointG1 {
	if IsZero(p) {
		return p
	}
	if !IsAffine(p) {
		t := newTempG1()
		inverse(t[0], &p[2])    // z^-1
		square(t[1], t[0])      // z^-2
		mul(&p[0], &p[0], t[1]) // x = x * z^-2
		mul(t[0], t[0], t[1])   // z^-3
		mul(&p[1], &p[1], t[0]) // y = y * z^-3
		p[2].one()              // z = 1
	}
	return p
}

// IsAffine checks a G1 point whether it is in affine form.
func IsAffine(p *PointG1) bool {
	return p[2].isOne()
}

// IsZero returns true if given point is equal to zero.
func IsZero(p *PointG1) bool {
	return p[2].isZero()
}

// Add adds two G1 points p1, p2 and assigns the result to point at first argument.
func Add(r, p1, p2 *PointG1) *PointG1 {
	// http://www.hyperelliptic.org/EFD/gp/auto-shortw-jacobian-0.html#addition-add-2007-bl
	if IsZero(p1) {
		return r.Set(p2)
	}
	if IsZero(p2) {
		return r.Set(p1)
	}
	t := newTempG1()
	square(t[7], &p1[2])    // z1z1
	mul(t[1], &p2[0], t[7]) // u2 = x2 * z1z1
	mul(t[2], &p1[2], t[7]) // z1z1 * z1
	mul(t[0], &p2[1], t[2]) // s2 = y2 * z1z1 * z1
	square(t[8], &p2[2])    // z2z2
	mul(t[3], &p1[0], t[8]) // u1 = x1 * z2z2
	mul(t[4], &p2[2], t[8]) // z2z2 * z2
	mul(t[2], &p1[1], t[4]) // s1 = y1 * z2z2 * z2
	if t[1].equal(t[3]) {
		if t[0].equal(t[2]) {
			return Double(r, p1)
		} else {
			return r.Zero()
		}
	}
	subAssign(t[1], t[3])     // h = u2 - u1
	double(t[4], t[1])        // 2h
	square(t[4], t[4])        // i = 2h^2
	mul(t[5], t[1], t[4])     // j = h*i
	subAssign(t[0], t[2])     // s2 - s1
	doubleAssign(t[0])        // r = 2*(s2 - s1)
	square(t[6], t[0])        // r^2
	subAssign(t[6], t[5])     // r^2 - j
	mul(t[3], t[3], t[4])     // v = u1 * i
	double(t[4], t[3])        // 2*v
	sub(&r[0], t[6], t[4])    // x3 = r^2 - j - 2*v
	sub(t[4], t[3], &r[0])    // v - x3
	mul(t[6], t[2], t[5])     // s1 * j
	doubleAssign(t[6])        // 2 * s1 * j
	mul(t[0], t[0], t[4])     // r * (v - x3)
	sub(&r[1], t[0], t[6])    // y3 = r * (v - x3) - (2 * s1 * j)
	add(t[0], &p1[2], &p2[2]) // z1 + z2
	square(t[0], t[0])        // (z1 + z2)^2
	subAssign(t[0], t[7])     // (z1 + z2)^2 - z1z1
	subAssign(t[0], t[8])     // (z1 + z2)^2 - z1z1 - z2z2
	mul(&r[2], t[0], t[1])    // z3 = ((z1 + z2)^2 - z1z1 - z2z2) * h
	return r
}
