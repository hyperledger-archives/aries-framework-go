/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwt

import (
	"github.com/hyperledger/aries-framework-go/component/models/jwt"
	"github.com/hyperledger/aries-framework-go/component/models/signature/verifier"
)

// KeyResolver resolves public key based on what and kid.
type KeyResolver = jwt.KeyResolver

// KeyResolverFunc defines function.
type KeyResolverFunc = jwt.KeyResolverFunc

// BasicVerifier defines basic Signed JWT verifier based on Issuer Claim and Key ID JOSE Header.
type BasicVerifier = jwt.BasicVerifier

// NewVerifier creates a new basic Verifier.
func NewVerifier(resolver KeyResolver) *BasicVerifier {
	return jwt.NewVerifier(resolver)
}

// GetVerifier returns new BasicVerifier based on *verifier.PublicKey.
func GetVerifier(publicKey *verifier.PublicKey) (*BasicVerifier, error) {
	return jwt.GetVerifier(publicKey)
}
