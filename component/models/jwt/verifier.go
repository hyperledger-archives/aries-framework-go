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
	"strings"

	"golang.org/x/crypto/ed25519"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/hyperledger/aries-framework-go/component/models/signature/verifier"
	kmsapi "github.com/hyperledger/aries-framework-go/spi/kms"
)

const (
	// signatureEdDSA defines EdDSA alg.
	signatureEdDSA = "EdDSA"

	// signatureRS256 defines RS256 alg.
	signatureRS256 = "RS256"
)

// KeyResolver resolves public key based on what and kid.
type KeyResolver interface {

	// Resolve resolves public key.
	Resolve(what, kid string) (*verifier.PublicKey, error)
}

// KeyResolverFunc defines function.
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
	verifiers := []verifier.SignatureVerifier{
		verifier.NewECDSAES256SignatureVerifier(),
		verifier.NewECDSAES384SignatureVerifier(),
		verifier.NewECDSAES521SignatureVerifier(),
		verifier.NewEd25519SignatureVerifier(),
		verifier.NewECDSASecp256k1SignatureVerifier(),
		verifier.NewRSAPS256SignatureVerifier(),
		verifier.NewRSARS256SignatureVerifier(),
	}

	algVerifiers := make([]jose.AlgSignatureVerifier, 0, len(verifiers))
	for _, v := range verifiers {
		algVerifiers = append(algVerifiers, jose.AlgSignatureVerifier{
			Alg:      v.Algorithm(),
			Verifier: getVerifier(resolver, v.Verify),
		})
	}

	compositeVerifier := jose.NewCompositeAlgSigVerifier(algVerifiers[0], algVerifiers[1:]...)
	// TODO ECDSA to support NIST P256 curve
	//  https://github.com/hyperledger/aries-framework-go/issues/1266

	return &BasicVerifier{resolver: resolver, compositeVerifier: compositeVerifier}
}

// GetVerifier returns new BasicVerifier based on *verifier.PublicKey.
func GetVerifier(publicKey *verifier.PublicKey) (*BasicVerifier, error) {
	keyType, err := publicKey.JWK.KeyType()
	if err != nil {
		return nil, err
	}

	var v verifier.SignatureVerifier

	switch keyType {
	case kmsapi.ECDSAP256TypeDER, kmsapi.ECDSAP256TypeIEEEP1363:
		v = verifier.NewECDSAES256SignatureVerifier()
	case kmsapi.ECDSAP384TypeDER, kmsapi.ECDSAP384TypeIEEEP1363:
		v = verifier.NewECDSAES384SignatureVerifier()
	case kmsapi.ECDSAP521TypeDER, kmsapi.ECDSAP521TypeIEEEP1363:
		v = verifier.NewECDSAES521SignatureVerifier()
	case kmsapi.ED25519Type:
		v = verifier.NewEd25519SignatureVerifier()
	case kmsapi.ECDSASecp256k1DER, kmsapi.ECDSASecp256k1TypeIEEEP1363:
		v = verifier.NewECDSASecp256k1SignatureVerifier()
	case kmsapi.RSAPS256Type:
		v = verifier.NewRSAPS256SignatureVerifier()
	case kmsapi.RSARS256Type:
		v = verifier.NewRSARS256SignatureVerifier()

	default:
		return nil, errors.New("unsupported key type")
	}

	compositeVerifier := jose.NewCompositeAlgSigVerifier(
		jose.AlgSignatureVerifier{
			Alg:      v.Algorithm(),
			Verifier: getPublicKeyVerifier(publicKey, v),
		},
	)

	return &BasicVerifier{compositeVerifier: compositeVerifier}, nil
}

type signatureVerifier func(pubKey *verifier.PublicKey, message, signature []byte) error

func getVerifier(resolver KeyResolver, signatureVerifier signatureVerifier) jose.SignatureVerifier {
	return jose.SignatureVerifierFunc(func(joseHeaders jose.Headers, payload, signingInput, signature []byte) error {
		return verifySignature(resolver, signatureVerifier, joseHeaders, payload, signingInput, signature)
	})
}

func getPublicKeyVerifier(publicKey *verifier.PublicKey, v verifier.SignatureVerifier) jose.SignatureVerifier {
	return jose.SignatureVerifierFunc(func(joseHeaders jose.Headers, payload, signingInput, signature []byte) error {
		alg, ok := joseHeaders.Algorithm()
		if !ok {
			return errors.New("'alg' JOSE header is not present")
		}
		if alg != v.Algorithm() {
			return fmt.Errorf("alg is not %s", v.Algorithm())
		}

		return v.Verify(publicKey, signingInput, signature)
	})
}

func verifySignature(resolver KeyResolver, signatureVerifier signatureVerifier,
	joseHeaders jose.Headers, _, signingInput, signature []byte) error {
	kid, _ := joseHeaders.KeyID()

	if !strings.HasPrefix(kid, "did:") {
		return fmt.Errorf("kid %s is not DID", kid)
	}

	pubKey, err := resolver.Resolve(strings.Split(kid, "#")[0], strings.Split(kid, "#")[1])
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
		return errors.New("not *rsa.VerificationMethod public key")
	}

	hash := crypto.SHA256.New()

	_, err = hash.Write(message)
	if err != nil {
		return err
	}

	hashed := hash.Sum(nil)

	return rsa.VerifyPKCS1v15(pubKeyRsa, crypto.SHA256, hashed, signature)
}
