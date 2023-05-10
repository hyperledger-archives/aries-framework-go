/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwt

import (
	"crypto/rsa"

	"github.com/hyperledger/aries-framework-go/component/models/jwt"
)

// JoseED25519Signer is a Jose compliant signer.
type JoseED25519Signer = jwt.JoseED25519Signer

// NewEd25519Signer returns a Jose compliant signer that can be passed as a signer to jwt.NewSigned().
func NewEd25519Signer(privKey []byte) *JoseED25519Signer {
	return jwt.NewEd25519Signer(privKey)
}

// JoseEd25519Verifier is a Jose compliant verifier.
type JoseEd25519Verifier = jwt.JoseEd25519Verifier

// NewEd25519Verifier returns a Jose compliant verifier that can be passed as a verifier option to jwt.Parse().
func NewEd25519Verifier(pubKey []byte) (*JoseEd25519Verifier, error) {
	return jwt.NewEd25519Verifier(pubKey)
}

// RS256Signer is a Jose complient signer.
type RS256Signer = jwt.RS256Signer

// NewRS256Signer returns a Jose compliant signer that can be passed as a signer to jwt.NewSigned().
func NewRS256Signer(privKey *rsa.PrivateKey, headers map[string]interface{}) *RS256Signer {
	return jwt.NewRS256Signer(privKey, headers)
}

// RS256Verifier is a Jose compliant verifier.
type RS256Verifier = jwt.RS256Verifier

// NewRS256Verifier returns a Jose compliant verifier that can be passed as a verifier option to jwt.Parse().
func NewRS256Verifier(pubKey *rsa.PublicKey) *RS256Verifier {
	return jwt.NewRS256Verifier(pubKey)
}
