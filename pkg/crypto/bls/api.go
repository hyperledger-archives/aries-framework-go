/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bls

type Bls interface {

	// Verify will verify each signature against a public key
	// returns:
	// 		error in case of errors or nil if signature verification was successful
	Verify(signatures [][]byte, msg, pubKey []byte) error
}
