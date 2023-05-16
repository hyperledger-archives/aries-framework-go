/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwt

import (
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/hyperledger/aries-framework-go/component/models/jwt"
)

const (
	// TypeJWT defines JWT type.
	TypeJWT = jwt.TypeJWT

	// AlgorithmNone used to indicate unsecured JWT.
	AlgorithmNone = jwt.AlgorithmNone
)

// Claims defines JSON Web Token Claims (https://tools.ietf.org/html/rfc7519#section-4)
type Claims = jwt.Claims

// ParseOpt is the JWT Parser option.
type ParseOpt = jwt.ParseOpt

// WithJWTDetachedPayload option is for definition of JWT detached payload.
func WithJWTDetachedPayload(payload []byte) ParseOpt {
	return jwt.WithJWTDetachedPayload(payload)
}

// WithIgnoreClaimsMapDecoding option is for ignore decoding claims into .Payload map[string]interface.
// Decoding to map[string]interface is pretty expensive, so this option can be used for performance critical operations.
func WithIgnoreClaimsMapDecoding(ignoreClaimsMapDecoding bool) ParseOpt {
	return jwt.WithIgnoreClaimsMapDecoding(ignoreClaimsMapDecoding)
}

// WithSignatureVerifier option is for definition of JWT detached payload.
func WithSignatureVerifier(signatureVerifier jose.SignatureVerifier) ParseOpt {
	return jwt.WithSignatureVerifier(signatureVerifier)
}

// UnsecuredJWTVerifier provides verifier for unsecured JWT.
func UnsecuredJWTVerifier() jose.SignatureVerifier {
	return jwt.UnsecuredJWTVerifier()
}

// JSONWebToken defines JSON Web Token (https://tools.ietf.org/html/rfc7519)
type JSONWebToken = jwt.JSONWebToken

// Parse parses input JWT in serialized form into JSON Web Token.
// Currently JWS and unsecured JWT is supported.
func Parse(jwtSerialized string, opts ...ParseOpt) (*JSONWebToken, []byte, error) {
	return jwt.Parse(jwtSerialized, opts...)
}

// NewSigned creates new signed JSON Web Token based on input claims.
func NewSigned(claims interface{}, headers jose.Headers, signer jose.Signer) (*JSONWebToken, error) {
	return jwt.NewSigned(claims, headers, signer)
}

// NewUnsecured creates new unsecured JSON Web Token based on input claims.
func NewUnsecured(claims interface{}, headers jose.Headers) (*JSONWebToken, error) {
	return jwt.NewUnsecured(claims, headers)
}

// IsJWS checks if JWT is a JWS of valid structure.
func IsJWS(s string) bool {
	return jwt.IsJWS(s)
}

// IsJWTUnsecured checks if JWT is an unsecured JWT of valid structure.
func IsJWTUnsecured(s string) bool {
	return jwt.IsJWTUnsecured(s)
}

// PayloadToMap transforms interface to map.
func PayloadToMap(i interface{}) (map[string]interface{}, error) {
	return jwt.PayloadToMap(i)
}
