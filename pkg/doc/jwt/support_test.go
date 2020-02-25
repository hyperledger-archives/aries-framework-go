/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwt

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
)

type ed25519Signer struct {
	privKey []byte
	headers map[string]interface{}
}

func (s ed25519Signer) Sign(data []byte) ([]byte, error) {
	return ed25519.Sign(s.privKey, data), nil
}

func (s ed25519Signer) Headers() jose.Headers {
	return s.headers
}

func newEd25519Signer(privKey []byte) *ed25519Signer {
	return &ed25519Signer{
		privKey: privKey,
		headers: prepareJWSHeaders(nil, signatureEdDSA),
	}
}

type ed25519Verifier struct {
	pubKey []byte
}

func (v ed25519Verifier) Verify(joseHeaders jose.Headers, _, signingInput, signature []byte) error {
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

func newEd25519Verifier(pubKey []byte) (*ed25519Verifier, error) {
	if l := len(pubKey); l != ed25519.PublicKeySize {
		return nil, errors.New("bad ed25519 public key length")
	}

	return &ed25519Verifier{pubKey: pubKey}, nil
}

type rs256Signer struct {
	privKey *rsa.PrivateKey
	headers map[string]interface{}
}

func newRS256Signer(privKey *rsa.PrivateKey, headers map[string]interface{}) *rs256Signer {
	return &rs256Signer{
		privKey: privKey,
		headers: prepareJWSHeaders(headers, signatureRS256),
	}
}

func (s rs256Signer) Sign(data []byte) ([]byte, error) {
	hash := crypto.SHA256.New()

	_, err := hash.Write(data)
	if err != nil {
		return nil, err
	}

	hashed := hash.Sum(nil)

	return rsa.SignPKCS1v15(rand.Reader, s.privKey, crypto.SHA256, hashed)
}

func (s rs256Signer) Headers() jose.Headers {
	return s.headers
}

type rs256Verifier struct {
	pubKey *rsa.PublicKey
}

func newRS256Verifier(pubKey *rsa.PublicKey) *rs256Verifier {
	return &rs256Verifier{pubKey: pubKey}
}

func (v rs256Verifier) Verify(joseHeaders jose.Headers, _, signingInput, signature []byte) error {
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
	verifier, err := newEd25519Verifier(pubKey)
	if err != nil {
		return err
	}

	sVerifier := jose.NewCompositeAlgSigVerifier(jose.AlgSignatureVerifier{
		Alg:      "EdDSA",
		Verifier: verifier,
	})

	token, err := Parse(jws, WithSignatureVerifier(sVerifier))
	if err != nil {
		return err
	}

	if token == nil {
		return errors.New("nil token")
	}

	return nil
}

func verifyRS256(jws string, pubKey *rsa.PublicKey) error {
	verifier := newRS256Verifier(pubKey)

	sVerifier := jose.NewCompositeAlgSigVerifier(jose.AlgSignatureVerifier{
		Alg:      "RS256",
		Verifier: verifier,
	})

	token, err := Parse(jws, WithSignatureVerifier(sVerifier))
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

	newHeaders[jose.HeaderType] = TypeJWT
	newHeaders[jose.HeaderAlgorithm] = alg

	return newHeaders
}
