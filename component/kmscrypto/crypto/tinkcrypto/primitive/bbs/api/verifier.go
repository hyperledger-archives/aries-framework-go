/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

// Verifier is the verification interface primitive for BBS+ signatures/proofs used by Tink.
type Verifier interface {
	// Verify will verify an aggregated signature of one or more messages against the signer's public key.
	// returns:
	// 		error in case of errors or nil if signature verification was successful
	Verify(messages [][]byte, signature []byte) error

	// VerifyProof will verify a BBS+ signature proof (generated e.g. by Verifier's DeriveProof() call) with the
	// signer's public key.
	// returns:
	// 		error in case of errors or nil if signature proof verification was successful
	VerifyProof(messages [][]byte, proof, nonce []byte) error

	// DeriveProof will create a BBS+ signature proof for a list of revealed messages using BBS signature
	// (can be built using a Signer's Sign() call) and the signer's public key.
	// returns:
	// 		signature proof in []byte
	//		error in case of errors
	DeriveProof(messages [][]byte, signature, nonce []byte, revealedIndexes []int) ([]byte, error)
}
