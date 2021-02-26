/*
Taken from https://github.com/kilic/bls12-381/blob/master/swu.go
(rev a288617c07f1bd60613c43dbde211b4a911e4791)

SPDX-License-Identifier: Apache-2.0
(https://github.com/kilic/bls12-381/blob/master/LICENSE)
*/

package bls12381

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
