/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jose

import (
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
)

// JSONWebSignature defines JSON Web Signature (https://tools.ietf.org/html/rfc7515)
type JSONWebSignature = jose.JSONWebSignature

// SignatureVerifier makes verification of JSON Web Signature.
type SignatureVerifier = jose.SignatureVerifier

// SignatureVerifierFunc is a function wrapper for SignatureVerifier.
type SignatureVerifierFunc = jose.SignatureVerifierFunc

// DefaultSigningInputVerifier is a SignatureVerifier that generates the signing input
// from the given headers and payload, instead of using the signing input parameter.
type DefaultSigningInputVerifier = jose.DefaultSigningInputVerifier

// CompositeAlgSigVerifier defines composite signature verifier based on the algorithm
// taken from JOSE header alg.
type CompositeAlgSigVerifier = jose.CompositeAlgSigVerifier

// AlgSignatureVerifier defines verifier for particular signature algorithm.
type AlgSignatureVerifier = jose.AlgSignatureVerifier

// NewCompositeAlgSigVerifier creates a new CompositeAlgSigVerifier.
func NewCompositeAlgSigVerifier(v AlgSignatureVerifier, vOther ...AlgSignatureVerifier) *CompositeAlgSigVerifier {
	return jose.NewCompositeAlgSigVerifier(v, vOther...)
}

// Signer defines JWS Signer interface. It makes signing of data and provides custom JWS headers relevant to the signer.
type Signer = jose.Signer

// NewJWS creates JSON Web Signature.
func NewJWS(protectedHeaders, unprotectedHeaders Headers, payload []byte, signer Signer) (*JSONWebSignature, error) {
	return jose.NewJWS(protectedHeaders, unprotectedHeaders, payload, signer)
}

// JWSParseOpt is the JWS Parser option.
type JWSParseOpt = jose.JWSParseOpt

// WithJWSDetachedPayload option is for definition of JWS detached payload.
func WithJWSDetachedPayload(payload []byte) JWSParseOpt {
	return jose.WithJWSDetachedPayload(payload)
}

// ParseJWS parses serialized JWS. Currently only JWS Compact Serialization parsing is supported.
func ParseJWS(jws string, verifier SignatureVerifier, opts ...JWSParseOpt) (*JSONWebSignature, error) {
	return jose.ParseJWS(jws, verifier, opts...)
}

// IsCompactJWS checks weather input is a compact JWS (based on https://tools.ietf.org/html/rfc7516#section-9)
func IsCompactJWS(s string) bool {
	return jose.IsCompactJWS(s)
}
