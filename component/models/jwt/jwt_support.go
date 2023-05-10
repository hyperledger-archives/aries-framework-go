/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwt

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
)

// JoseED25519Signer is a Jose compliant signer.
type JoseED25519Signer struct {
	privKey []byte
	headers map[string]interface{}
}

// Sign data.
func (s JoseED25519Signer) Sign(data []byte) ([]byte, error) {
	return ed25519.Sign(s.privKey, data), nil
}

// Headers returns the signer's headers map.
func (s JoseED25519Signer) Headers() jose.Headers {
	return s.headers
}

// NewEd25519Signer returns a Jose compliant signer that can be passed as a signer to jwt.NewSigned().
func NewEd25519Signer(privKey []byte) *JoseED25519Signer {
	return &JoseED25519Signer{
		privKey: privKey,
		headers: prepareJWSHeaders(nil, signatureEdDSA),
	}
}

// JoseEd25519Verifier is a Jose compliant verifier.
type JoseEd25519Verifier struct {
	pubKey []byte
}

// Verify signingInput against signature. it validates that joseHeaders contains EdDSA alg for this implementation.
func (v JoseEd25519Verifier) Verify(joseHeaders jose.Headers, _, signingInput, signature []byte) error {
	alg, ok := joseHeaders.Algorithm()
	if !ok {
		return errors.New("alg is not defined")
	}

	if alg != "EdDSA" {
		return errors.New("alg is not EdDSA")
	}

	if ok := ed25519.Verify(v.pubKey, signingInput, signature); !ok {
		return errors.New("signature doesn't match")
	}

	return nil
}

// NewEd25519Verifier returns a Jose compliant verifier that can be passed as a verifier option to jwt.Parse().
func NewEd25519Verifier(pubKey []byte) (*JoseEd25519Verifier, error) {
	if l := len(pubKey); l != ed25519.PublicKeySize {
		return nil, errors.New("bad ed25519 public key length")
	}

	return &JoseEd25519Verifier{pubKey: pubKey}, nil
}

// RS256Signer is a Jose complient signer.
type RS256Signer struct {
	privKey *rsa.PrivateKey
	headers map[string]interface{}
}

// NewRS256Signer returns a Jose compliant signer that can be passed as a signer to jwt.NewSigned().
func NewRS256Signer(privKey *rsa.PrivateKey, headers map[string]interface{}) *RS256Signer {
	return &RS256Signer{
		privKey: privKey,
		headers: prepareJWSHeaders(headers, signatureRS256),
	}
}

// Sign data.
func (s RS256Signer) Sign(data []byte) ([]byte, error) {
	hash := crypto.SHA256.New()

	_, err := hash.Write(data)
	if err != nil {
		return nil, err
	}

	hashed := hash.Sum(nil)

	return rsa.SignPKCS1v15(rand.Reader, s.privKey, crypto.SHA256, hashed)
}

// Headers returns the signer's headers map.
func (s RS256Signer) Headers() jose.Headers {
	return s.headers
}

// RS256Verifier is a Jose compliant verifier.
type RS256Verifier struct {
	pubKey *rsa.PublicKey
}

// NewRS256Verifier returns a Jose compliant verifier that can be passed as a verifier option to jwt.Parse().
func NewRS256Verifier(pubKey *rsa.PublicKey) *RS256Verifier {
	return &RS256Verifier{pubKey: pubKey}
}

// Verify signingInput against the signature. It also validates that joseHeaders includes the right alg.
func (v RS256Verifier) Verify(joseHeaders jose.Headers, _, signingInput, signature []byte) error {
	alg, ok := joseHeaders.Algorithm()
	if !ok {
		return errors.New("alg is not defined")
	}

	if alg != "RS256" {
		return errors.New("alg is not RS256")
	}

	hash := crypto.SHA256.New()

	_, err := hash.Write(signingInput)
	if err != nil {
		return err
	}

	hashed := hash.Sum(nil)

	return rsa.VerifyPKCS1v15(v.pubKey, crypto.SHA256, hashed, signature)
}

func verifyEd25519(jws string, pubKey ed25519.PublicKey) error {
	v, err := NewEd25519Verifier(pubKey)
	if err != nil {
		return err
	}

	sVerifier := jose.NewCompositeAlgSigVerifier(jose.AlgSignatureVerifier{
		Alg:      "EdDSA",
		Verifier: v,
	})

	token, _, err := Parse(jws, WithSignatureVerifier(sVerifier))
	if err != nil {
		return err
	}

	if token == nil {
		return errors.New("nil token")
	}

	return nil
}

func verifyRS256(jws string, pubKey *rsa.PublicKey) error {
	v := NewRS256Verifier(pubKey)

	sVerifier := jose.NewCompositeAlgSigVerifier(jose.AlgSignatureVerifier{
		Alg:      "RS256",
		Verifier: v,
	})

	token, _, err := Parse(jws, WithSignatureVerifier(sVerifier))
	if err != nil {
		return err
	}

	if token == nil {
		return errors.New("nil token")
	}

	return nil
}

func prepareJWSHeaders(headers map[string]interface{}, alg string) map[string]interface{} {
	newHeaders := make(map[string]interface{})

	for k, v := range headers {
		newHeaders[k] = v
	}

	newHeaders[jose.HeaderAlgorithm] = alg

	return newHeaders
}
