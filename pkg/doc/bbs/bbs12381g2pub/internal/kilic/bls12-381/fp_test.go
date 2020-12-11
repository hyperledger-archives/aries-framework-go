/*
Taken from https://github.com/kilic/bls12-381/blob/master/fp_test.go
(rev a288617c07f1bd60613c43dbde211b4a911e4791)

SPDX-License-Identifier: Apache-2.0
(https://github.com/kilic/bls12-381/blob/master/LICENSE)
*/

package bls12381

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"
)

func TestFpSerialization(t *testing.T) {
	t.Run("zero", func(t *testing.T) {
		in := make([]byte, fpByteSize)
		fe, err := fromBytes(in)
		if err != nil {
			t.Fatal(err)
		}
		if !fe.isZero() {
			t.Fatal("serialization failed")
		}
		if !bytes.Equal(in, toBytes(fe)) {
			t.Fatal("serialization failed")
		}
	})
	t.Run("bytes", func(t *testing.T) {
		for i := 0; i < fuz; i++ {
			a, _ := new(fe).rand(rand.Reader)
			b, err := fromBytes(toBytes(a))
			if err != nil {
				t.Fatal(err)
			}
			if !a.equal(b) {
				t.Fatal("serialization failed")
			}
		}
	})
}

func TestFpAdditionCrossAgainstBigInt(t *testing.T) {
	for i := 0; i < fuz; i++ {
		a, _ := new(fe).rand(rand.Reader)
		b, _ := new(fe).rand(rand.Reader)
		c := new(fe)
		big_a := a.big()
		big_b := b.big()
		big_c := new(big.Int)
		add(c, a, b)
		out_1 := c.bytes()
		out_2 := padBytes(big_c.Add(big_a, big_b).Mod(big_c, modulus.big()).Bytes(), fpByteSize)
		if !bytes.Equal(out_1, out_2) {
			t.Fatal("cross test against big.Int is failed A")
		}
		double(c, a)
		out_1 = c.bytes()
		out_2 = padBytes(big_c.Add(big_a, big_a).Mod(big_c, modulus.big()).Bytes(), fpByteSize)
		if !bytes.Equal(out_1, out_2) {
			t.Fatal("cross test against big.Int is failed B")
		}
		sub(c, a, b)
		out_1 = c.bytes()
		out_2 = padBytes(big_c.Sub(big_a, big_b).Mod(big_c, modulus.big()).Bytes(), fpByteSize)
		if !bytes.Equal(out_1, out_2) {
			t.Fatal("cross test against big.Int is failed C")
		}
		neg(c, a)
		out_1 = c.bytes()
		out_2 = padBytes(big_c.Neg(big_a).Mod(big_c, modulus.big()).Bytes(), fpByteSize)
		if !bytes.Equal(out_1, out_2) {
			t.Fatal("cross test against big.Int is failed D")
		}
	}
}

func TestFpAdditionCrossAgainstBigIntAssigned(t *testing.T) {
	for i := 0; i < fuz; i++ {
		a, _ := new(fe).rand(rand.Reader)
		b, _ := new(fe).rand(rand.Reader)
		big_a, big_b := a.big(), b.big()
		addAssign(a, b)
		out_1 := a.bytes()
		out_2 := padBytes(big_a.Add(big_a, big_b).Mod(big_a, modulus.big()).Bytes(), fpByteSize)
		if !bytes.Equal(out_1, out_2) {
			t.Fatal("cross test against big.Int is failed A")
		}
		a, _ = new(fe).rand(rand.Reader)
		big_a = a.big()
		doubleAssign(a)
		out_1 = a.bytes()
		out_2 = padBytes(big_a.Add(big_a, big_a).Mod(big_a, modulus.big()).Bytes(), fpByteSize)
		if !bytes.Equal(out_1, out_2) {
			t.Fatal("cross test against big.Int is failed B")
		}
		a, _ = new(fe).rand(rand.Reader)
		b, _ = new(fe).rand(rand.Reader)
		big_a, big_b = a.big(), b.big()
		subAssign(a, b)
		out_1 = a.bytes()
		out_2 = padBytes(big_a.Sub(big_a, big_b).Mod(big_a, modulus.big()).Bytes(), fpByteSize)
		if !bytes.Equal(out_1, out_2) {
			t.Fatal("cross test against big.Int is failed A")
		}
	}
}

func TestFpAdditionProperties(t *testing.T) {
	for i := 0; i < fuz; i++ {

		zero := new(fe).zero()
		a, _ := new(fe).rand(rand.Reader)
		b, _ := new(fe).rand(rand.Reader)
		c_1, c_2 := new(fe), new(fe)
		add(c_1, a, zero)
		if !c_1.equal(a) {
			t.Fatal("a + 0 == a")
		}
		sub(c_1, a, zero)
		if !c_1.equal(a) {
			t.Fatal("a - 0 == a")
		}
		double(c_1, zero)
		if !c_1.equal(zero) {
			t.Fatal("2 * 0 == 0")
		}
		neg(c_1, zero)
		if !c_1.equal(zero) {
			t.Fatal("-0 == 0")
		}
		sub(c_1, zero, a)
		neg(c_2, a)
		if !c_1.equal(c_2) {
			t.Fatal("0-a == -a")
		}
		double(c_1, a)
		add(c_2, a, a)
		if !c_1.equal(c_2) {
			t.Fatal("2 * a == a + a")
		}
		add(c_1, a, b)
		add(c_2, b, a)
		if !c_1.equal(c_2) {
			t.Fatal("a + b = b + a")
		}
		sub(c_1, a, b)
		sub(c_2, b, a)
		neg(c_2, c_2)
		if !c_1.equal(c_2) {
			t.Fatal("a - b = - ( b - a )")
		}
		c_x, _ := new(fe).rand(rand.Reader)
		add(c_1, a, b)
		add(c_1, c_1, c_x)
		add(c_2, a, c_x)
		add(c_2, c_2, b)
		if !c_1.equal(c_2) {
			t.Fatal("(a + b) + c == (a + c ) + b")
		}
		sub(c_1, a, b)
		sub(c_1, c_1, c_x)
		sub(c_2, a, c_x)
		sub(c_2, c_2, b)
		if !c_1.equal(c_2) {
			t.Fatal("(a - b) - c == (a - c ) -b")
		}
	}
}

func TestFpAdditionPropertiesAssigned(t *testing.T) {
	for i := 0; i < fuz; i++ {
		zero := new(fe).zero()
		a, b := new(fe), new(fe)
		_, _ = a.rand(rand.Reader)
		b.set(a)
		addAssign(a, zero)
		if !a.equal(b) {
			t.Fatal("a + 0 == a")
		}
		subAssign(a, zero)
		if !a.equal(b) {
			t.Fatal("a - 0 == a")
		}
		a.set(zero)
		doubleAssign(a)
		if !a.equal(zero) {
			t.Fatal("2 * 0 == 0")
		}
		a.set(zero)
		subAssign(a, b)
		neg(b, b)
		if !a.equal(b) {
			t.Fatal("0-a == -a")
		}
		_, _ = a.rand(rand.Reader)
		b.set(a)
		doubleAssign(a)
		addAssign(b, b)
		if !a.equal(b) {
			t.Fatal("2 * a == a + a")
		}
		_, _ = a.rand(rand.Reader)
		_, _ = b.rand(rand.Reader)
		c_1, c_2 := new(fe).set(a), new(fe).set(b)
		addAssign(c_1, b)
		addAssign(c_2, a)
		if !c_1.equal(c_2) {
			t.Fatal("a + b = b + a")
		}
		_, _ = a.rand(rand.Reader)
		_, _ = b.rand(rand.Reader)
		c_1.set(a)
		c_2.set(b)
		subAssign(c_1, b)
		subAssign(c_2, a)
		neg(c_2, c_2)
		if !c_1.equal(c_2) {
			t.Fatal("a - b = - ( b - a )")
		}
		_, _ = a.rand(rand.Reader)
		_, _ = b.rand(rand.Reader)
		c, _ := new(fe).rand(rand.Reader)
		a0 := new(fe).set(a)
		addAssign(a, b)
		addAssign(a, c)
		addAssign(b, c)
		addAssign(b, a0)
		if !a.equal(b) {
			t.Fatal("(a + b) + c == (b + c) + a")
		}
		_, _ = a.rand(rand.Reader)
		_, _ = b.rand(rand.Reader)
		_, _ = c.rand(rand.Reader)
		a0.set(a)
		subAssign(a, b)
		subAssign(a, c)
		subAssign(a0, c)
		subAssign(a0, b)
		if !a.equal(a0) {
			t.Fatal("(a - b) - c == (a - c) -b")
		}
	}
}

func TestFpMultiplicationCrossAgainstBigInt(t *testing.T) {
	for i := 0; i < fuz; i++ {
		a, _ := new(fe).rand(rand.Reader)
		b, _ := new(fe).rand(rand.Reader)
		c := new(fe)
		big_a := toBig(a)
		big_b := toBig(b)
		big_c := new(big.Int)
		mul(c, a, b)
		out_1 := toBytes(c)
		out_2 := padBytes(big_c.Mul(big_a, big_b).Mod(big_c, modulus.big()).Bytes(), fpByteSize)
		if !bytes.Equal(out_1, out_2) {
			t.Fatal("cross test against big.Int is failed")
		}
	}
}

func TestFpMultiplicationProperties(t *testing.T) {
	for i := 0; i < fuz; i++ {
		a, _ := new(fe).rand(rand.Reader)
		b, _ := new(fe).rand(rand.Reader)
		zero, one := new(fe).zero(), new(fe).one()
		c_1, c_2 := new(fe), new(fe)
		mul(c_1, a, zero)
		if !c_1.equal(zero) {
			t.Fatal("a * 0 == 0")
		}
		mul(c_1, a, one)
		if !c_1.equal(a) {
			t.Fatal("a * 1 == a")
		}
		mul(c_1, a, b)
		mul(c_2, b, a)
		if !c_1.equal(c_2) {
			t.Fatal("a * b == b * a")
		}
		c_x, _ := new(fe).rand(rand.Reader)
		mul(c_1, a, b)
		mul(c_1, c_1, c_x)
		mul(c_2, c_x, b)
		mul(c_2, c_2, a)
		if !c_1.equal(c_2) {
			t.Fatal("(a * b) * c == (a * c) * b")
		}
		square(a, zero)
		if !a.equal(zero) {
			t.Fatal("0^2 == 0")
		}
		square(a, one)
		if !a.equal(one) {
			t.Fatal("1^2 == 1")
		}
		_, _ = a.rand(rand.Reader)
		square(c_1, a)
		mul(c_2, a, a)
		if !c_1.equal(c_1) {
			t.Fatal("a^2 == a*a")
		}
	}
}

func TestFpInversion(t *testing.T) {
	for i := 0; i < fuz; i++ {
		u := new(fe)
		zero, one := new(fe).zero(), new(fe).one()
		inverse(u, zero)
		if !u.equal(zero) {
			t.Fatal("(0^-1) == 0)")
		}
		inverse(u, one)
		if !u.equal(one) {
			t.Fatal("(1^-1) == 1)")
		}
		a, _ := new(fe).rand(rand.Reader)
		inverse(u, a)
		mul(u, u, a)
		if !u.equal(one) {
			t.Fatal("(r*a) * r*(a^-1) == r)")
		}
		v := new(fe)
		p := modulus.big()
		exp(u, a, p.Sub(p, big.NewInt(2)))
		inverse(v, a)
		if !v.equal(u) {
			t.Fatal("a^(p-2) == a^-1")
		}
	}
}

func padBytes(in []byte, size int) []byte {
	out := make([]byte, size)
	if len(in) > size {
		panic("bad input for padding")
	}
	copy(out[size-len(in):], in)
	return out
}
