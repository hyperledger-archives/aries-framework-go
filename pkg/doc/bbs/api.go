/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs

// BBS defines BBS+ signature scheme (https://eprint.iacr.org/2016/663.pdf, section 4.3).
type BBS interface {

	// Verify will verify an aggregated signature of one or more messages against a public key
	// returns:
	// 		error in case of errors or nil if signature verification was successful
	Verify(messages [][]byte, signature, pubKey []byte) error

	// Sign will sign create signature of each message and aggregate it into a single signature using
	// provided private key in binary form.
	// returns:
	// 		signature in []byte
	//		error in case of errors
	Sign(messages [][]byte, privKey []byte) ([]byte, error)
}
