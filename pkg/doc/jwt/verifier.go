/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwt

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/square/go-jose/v3/json"
	"golang.org/x/crypto/ed25519"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
)

const (
	// signatureEdDSA defines EdDSA alg
	signatureEdDSA = "EdDSA"

	// signatureRS256 defines RS256 alg
	signatureRS256 = "RS256"
)

const issuerClaim = "iss"

// KeyResolver resolves public key based on what and kid.
type KeyResolver interface {

	// Resolve resolves public key.
	Resolve(what, kid string) (*verifier.PublicKey, error)
}

// KeyResolverFunc defines function
type KeyResolverFunc func(what, kid string) (*verifier.PublicKey, error)

// Resolve resolves public key.
func (k KeyResolverFunc) Resolve(what, kid string) (*verifier.PublicKey, error) {
	return k(what, kid)
}

// BasicVerifier defines basic Signed JWT verifier based on Issuer Claim and Key ID JOSE Header.
type BasicVerifier struct {
	resolver          KeyResolver
	compositeVerifier *jose.CompositeAlgSigVerifier
}

// NewVerifier creates a new basic Verifier.
func NewVerifier(resolver KeyResolver) *BasicVerifier {
	// TODO Support pluggable JWS verifiers
	//  (https://github.com/hyperledger/aries-framework-go/issues/1267)
	compositeVerifier := jose.NewCompositeAlgSigVerifier(
		jose.AlgSignatureVerifier{
			Alg:      signatureEdDSA,
			Verifier: getVerifier(resolver, VerifyEdDSA)},
		jose.AlgSignatureVerifier{
			Alg:      signatureRS256,
			Verifier: getVerifier(resolver, VerifyRS256)},
	)
	// TODO ECDSA to support NIST P256 curve
	//  https://github.com/hyperledger/aries-framework-go/issues/1266

	return &BasicVerifier{resolver: resolver, compositeVerifier: compositeVerifier}
}

type signatureVerifier func(pubKey *verifier.PublicKey, message, signature []byte) error

func getVerifier(resolver KeyResolver, signatureVerifier signatureVerifier) jose.SignatureVerifier {
	return jose.SignatureVerifierFunc(func(joseHeaders jose.Headers, payload, signingInput, signature []byte) error {
		return verifySignature(resolver, signatureVerifier, joseHeaders, payload, signingInput, signature)
	})
}

func verifySignature(resolver KeyResolver, signatureVerifier signatureVerifier,
	joseHeaders jose.Headers, payload, signingInput, signature []byte) error {
	claims := make(map[string]interface{})

	err := json.Unmarshal(payload, &claims)
	if err != nil {
		return fmt.Errorf("read claims from JSON Web Token: %w", err)
	}

	issuer, err := getIssuerClaim(claims)
	if err != nil {
		return fmt.Errorf("read issuer claim: %w", err)
	}

	kid, _ := joseHeaders.KeyID()

	pubKey, err := resolver.Resolve(issuer, kid)
	if err != nil {
		return err
	}

	return signatureVerifier(pubKey, signingInput, signature)
}

// Verify verifies JSON Web Token. Public key is fetched using Issuer Claim and Key ID JOSE Header.
func (v BasicVerifier) Verify(joseHeaders jose.Headers, payload, signingInput, signature []byte) error {
	return v.compositeVerifier.Verify(joseHeaders, payload, signingInput, signature)
}

// VerifyEdDSA verifies EdDSA signature.
func VerifyEdDSA(pubKey *verifier.PublicKey, message, signature []byte) error {
	// TODO Use crypto for signing/verification logic
	//  https://github.com/hyperledger/aries-framework-go/issues/1278
	if l := len(pubKey.Value); l != ed25519.PublicKeySize {
		return errors.New("bad ed25519 public key length")
	}

	if ok := ed25519.Verify(pubKey.Value, message, signature); !ok {
		return errors.New("signature doesn't match")
	}

	return nil
}

// VerifyRS256 verifies RS256 signature.
func VerifyRS256(pubKey *verifier.PublicKey, message, signature []byte) error {
	// TODO Use crypto for signing/verification logic
	//  https://github.com/hyperledger/aries-framework-go/issues/1278
	pubKeyRsa, err := x509.ParsePKCS1PublicKey(pubKey.Value)
	if err != nil {
		return errors.New("not *rsa.PublicKey public key")
	}

	hash := crypto.SHA256.New()

	_, err = hash.Write(message)
	if err != nil {
		return err
	}

	hashed := hash.Sum(nil)

	return rsa.VerifyPKCS1v15(pubKeyRsa, crypto.SHA256, hashed, signature)
}

func getIssuerClaim(claims map[string]interface{}) (string, error) {
	v, ok := claims[issuerClaim]
	if !ok {
		return "", errors.New("issuer claim is not defined")
	}

	s, ok := v.(string)
	if !ok {
		return "", errors.New("issuer claim is not a string")
	}

	return s, nil
}
