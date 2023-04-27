/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jsonwebsignature2020

import (
	"github.com/hyperledger/aries-framework-go/component/models/signature/verifier"
)

// NewPublicKeyVerifier creates a signature verifier that verifies a Ed25519 / EC (P-256, P-384, P-521, secp256k1) / RSA
// signature taking public key bytes and / or JSON Web Key as input.
// The list of Supported JWS algorithms of JsonWebSignature2020 is defined here:
// https://github.com/transmute-industries/lds-jws2020#supported-jws-algs
func NewPublicKeyVerifier() *verifier.PublicKeyVerifier {
	return verifier.NewCompositePublicKeyVerifier(
		[]verifier.SignatureVerifier{
			verifier.NewEd25519SignatureVerifier(),
			verifier.NewECDSASecp256k1SignatureVerifier(),
			verifier.NewECDSAES256SignatureVerifier(),
			verifier.NewECDSAES384SignatureVerifier(),
			verifier.NewECDSAES521SignatureVerifier(),
			verifier.NewRSAPS256SignatureVerifier(),
		},
		verifier.WithExactPublicKeyType(jwkType))
}
