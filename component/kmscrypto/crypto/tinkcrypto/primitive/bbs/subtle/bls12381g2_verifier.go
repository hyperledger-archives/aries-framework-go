/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
)

// BLS12381G2Verifier is the BBS+ signature/proof verifier for keys on BLS12-381 curve with a point in the G2 group.
// Currently this is the only available BBS+ verifier in aries-framework-go (see `pkg/doc/bbs/bbs12381g2pub/bbs.go`).
// Other BBS+ verifiers can be added later if needed.
type BLS12381G2Verifier struct {
	signerPubKeyBytes []byte
	bbsPrimitive      *bbs12381g2pub.BBSG2Pub
}

// NewBLS12381G2Verifier creates a new instance of BLS12381G2Verifier with the provided signerPublicKey.
func NewBLS12381G2Verifier(signerPublicKey []byte) *BLS12381G2Verifier {
	return &BLS12381G2Verifier{
		signerPubKeyBytes: signerPublicKey,
		bbsPrimitive:      bbs12381g2pub.New(),
	}
}

// Verify will verify an aggregated signature of one or more messages against the signer's public key.
// returns:
// 		error in case of errors or nil if signature verification was successful
func (v *BLS12381G2Verifier) Verify(messages [][]byte, signature []byte) error {
	return v.bbsPrimitive.Verify(messages, signature, v.signerPubKeyBytes)
}

// VerifyProof will verify a BBS+ signature proof (generated e.g. by DeriveProof()) with the signer's public key.
// returns:
// 		error in case of errors or nil if signature proof verification was successful
func (v *BLS12381G2Verifier) VerifyProof(messages [][]byte, proof, nonce []byte) error {
	return v.bbsPrimitive.VerifyProof(messages, proof, nonce, v.signerPubKeyBytes)
}

// DeriveProof will create a BBS+ signature proof for a list of revealed messages using BBS signature
// (can be built using a Signer's Sign() call) and the signer's public key.
// returns:
// 		signature proof in []byte
//		error in case of errors
func (v *BLS12381G2Verifier) DeriveProof(messages [][]byte, signature, nonce []byte,
	revealedIndexes []int) ([]byte, error) {
	return v.bbsPrimitive.DeriveProof(messages, signature, nonce, v.signerPubKeyBytes, revealedIndexes)
}
