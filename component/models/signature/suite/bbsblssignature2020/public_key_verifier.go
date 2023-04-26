/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbsblssignature2020

import "github.com/hyperledger/aries-framework-go/component/models/signature/verifier"

const g2PubKeyType = "Bls12381G2Key2020"

// NewG2PublicKeyVerifier creates a signature verifier that verifies a BbsBlsSignature2020 signature
// taking Bls12381G2Key2020 public key bytes as input.
func NewG2PublicKeyVerifier() *verifier.PublicKeyVerifier {
	return verifier.NewPublicKeyVerifier(verifier.NewBBSG2SignatureVerifier(),
		verifier.WithExactPublicKeyType(g2PubKeyType))
}
