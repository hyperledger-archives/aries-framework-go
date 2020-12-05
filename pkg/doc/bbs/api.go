/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs

// BBS defines BBS+ signature scheme (https://eprint.iacr.org/2016/663.pdf, section 4.3).
type BBS interface {

	// Verify will verify an aggregated signature of one or more messages against a public key.
	// returns:
	// 		error in case of errors or nil if signature verification was successful
	Verify(messages [][]byte, signature, pubKey []byte) error

	// Sign will sign create signature of each message and aggregate it into a single signature using
	// provided private key in binary form.
	// returns:
	// 		signature in []byte
	//		error in case of errors
	Sign(messages [][]byte, privKey []byte) ([]byte, error)

	// VerifyProof will verify a BBS+ signature proof (generated e.g. by DeriveProof()) with a BLS12-381 public key.
	// returns:
	// 		error in case of errors or nil if signature proof verification was successful
	VerifyProof(messages [][]byte, proof, nonce, pubKey []byte) error

	// DeriveProof will create a BBS+ signature proof for a list of revealed messages using BBS signature
	// (can be build using Sign()) and a public key.
	// returns:
	// 		signature proof in []byte
	//		error in case of errors
	DeriveProof(messages [][]byte, signature, nonce, pubKey []byte, revealedIndexes []int) ([]byte, error)
}
