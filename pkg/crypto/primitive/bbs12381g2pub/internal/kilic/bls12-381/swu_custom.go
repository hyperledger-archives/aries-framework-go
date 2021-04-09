/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bls12381

// swuMapG1BE is implementation of Simplified Shallue-van de Woestijne-Ulas Method
// follows the implementation at draft-irtf-cfrg-hash-to-curve-06.
// uses big-endian variant: https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-06#section-4.1.1
func swuMapG1BE(u *fe) (*fe, *fe) {
	x, y, u := swuMapG1Pre(u)

	if y.signBE() != u.signBE() {
		neg(y, y)
	}
	return x, y
}
