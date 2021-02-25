/*
Taken from https://github.com/kilic/bls12-381/blob/master/arithmetic_fallback.go
(rev a288617c07f1bd60613c43dbde211b4a911e4791)

SPDX-License-Identifier: Apache-2.0
(https://github.com/kilic/bls12-381/blob/master/LICENSE)
*/

package bls12381

const fpNumberOfLimbs = 6
const fpByteSize = 48
const fpBitSize = 381
const sixWordBitSize = 384

// modulus = p
var modulus = fe{0xb9feffffffffaaab, 0x1eabfffeb153ffff, 0x6730d2a0f6b0f624, 0x64774b84f38512bf, 0x4b1ba7b6434bacd7, 0x1a0111ea397fe69a}

// r1 = r mod p
var r1 = &fe{0x760900000002fffd, 0xebf4000bc40c0002, 0x5f48985753c758ba, 0x77ce585370525745, 0x5c071a97a256ec6d, 0x15f65ec3fa80e493}

// r2 = r^2 mod p
var r2 = &fe{
	0xf4df1f341c341746, 0x0a76e6a609d104f1, 0x8de5476c4c95b6d5, 0x67eb88a9939d83c0, 0x9a793e85b519952d, 0x11988fe592cae3aa,
}

// Efficient G1 cofactor
var cofactorEFFG1 = bigFromHex("0xd201000000010001")
