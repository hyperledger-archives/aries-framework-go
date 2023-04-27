/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbsblssignatureproof2020

import "github.com/hyperledger/aries-framework-go/component/models/signature/verifier"

const g2PubKeyType = "Bls12381G2Key2020"

// NewG2PublicKeyVerifier creates a signature verifier that verifies a BbsBlsSignatureProof2020 signature
// taking Bls12381G2Key2020 public key bytes as input.
func NewG2PublicKeyVerifier(nonce []byte) *verifier.PublicKeyVerifier {
	return verifier.NewPublicKeyVerifier(verifier.NewBBSG2SignatureProofVerifier(nonce),
		verifier.WithExactPublicKeyType(g2PubKeyType))
}
