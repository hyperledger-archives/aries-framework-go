/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package bbs provides implementations of BBS+ key management and primitives.
//
// The functionality of BBS+ signatures/proofs is represented as a pair of
// primitives (interfaces):
//
//   - Signer for signing a list of messages with a private key
//
//   - Verifier for verifying a signature against a list of messages, deriving a proof from a signature for a given
//     set of sub messages and verifying such derived proof.
//
// Example:
//
//	 package main
//
//	 import (
//	     "bytes"
//
//	     "github.com/google/tink/go/keyset"
//
//	     "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/bbs"
//	 )
//
//	 func main() {
//	     // create signer keyset handle
//	     kh, err := keyset.NewHandle(bbs.BLS12381G2KeyTemplate())
//	     if err != nil {
//	         //handle error
//	     }
//
//	     // extract signer public keyset handle and key for signature verification and proof derivation/verification
//	     verKH, err := kh.Public()
//	     if err != nil {
//	         //handle error
//	     }
//
//			// finally get the BBS+ signing primitive from the private key handle created above
//			s:= bbs.NewSigner(kh)
//
//			// create a message to be signed
//			messages := [][]byte{[]byte("message 1"), []byte("message 2"), []byte("message 3"), []byte("message 4")}
//
//			// and now sign using s
//	     sig, err = s.Sign(messages)
//	     if err != nil {
//	         // handle error
//	     }
//
//			// to verify, get the BBS+ verification primitive from the public key handle created earlier above
//	     v := bbs.NewVerifier(verKH)
//
//			// and verify signature
//	     err = v.Verify(messages, sig)
//	     if err != nil {
//	         // handle error
//	     }
//
//			// to derive a proof from the bbs signature, create the indices of the messages to be revealed by the proof
//			revealedIndexes := []int{0, 2}
//
//			// and a nonce
//			nonce := make([]byte, 10)
//
//			_, err = rand.Read(nonce)
//	     if err != nil {
//	         // handle error
//	     }
//
//			// then derive a proof for messages at index 0 and 2 as follows
//			proof, err := verifier.DeriveProof(messages, sig, nonce, revealedIndexes)
//	     if err != nil {
//	         // handle error
//	     }
//
//			// create a copy of the revealed messages to the party that should only access messages at index 0 and 2
//			revealedMsgs := [][]byte{messages[0], messages[2]}
//
//			// finally to verify the proof's authenticity for revealedMsgs, do the following
//			err = verifier.VerifyProof(revealedMsgs, proof, nonce)
//	     if err != nil {
//	         // handle error
//	     }
//	 }
package bbs

import (
	// import to initialize.
	_ "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/bbs"
)
