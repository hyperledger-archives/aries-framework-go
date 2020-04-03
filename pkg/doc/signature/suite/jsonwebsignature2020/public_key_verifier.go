/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jsonwebsignature2020

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec"

	sigverifier "github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
)

// PublicKeyVerifier verifies a Ed25519 / EC (P-256, P-384, P-521, secp256k1) / RSA signature
// taking public key bytes and / or JSON Web Key as input.
// The list of Supported JWS algorithms of JsonWebSignature2020 is defined here:
// https://github.com/transmute-industries/lds-jws2020#supported-jws-algs
// NOTE: this verifier is present for backward compatibility reasons and can be removed later.
// Please use CryptoVerifier or your own verifier.
type PublicKeyVerifier struct {
}

// Verify will verify a signature.
func (v *PublicKeyVerifier) Verify(pubKey *sigverifier.PublicKey, doc, signature []byte) error {
	// A presence of JSON Web Key is mandatory (due to JwsVerificationKey2020 type).
	if pubKey.JWK == nil {
		return ErrJWKNotPresent
	}

	if pubKey.Type != jwkType {
		return ErrTypeNotJwsVerificationKey2020
	}

	switch pubKey.JWK.Kty {
	case "EC":
		return v.verifyEllipticCurve(pubKey, signature, doc)
	case "OKP":
		return v.verifyEdDSA(pubKey, signature, doc)
	case "RSA":
		return v.verifyRSA(pubKey, signature, doc)
	default:
		return fmt.Errorf("unsupported key type: %s", pubKey.JWK.Kty)
	}
}

func (v *PublicKeyVerifier) verifyEllipticCurve(pubKey *sigverifier.PublicKey, signature, msg []byte) error {
	ec := parseEllipticCurve(pubKey.JWK.Crv)
	if ec == nil {
		return fmt.Errorf("ecdsa: unsupported elliptic curve '%s'", pubKey.JWK.Crv)
	}

	pubKeyBytes := pubKey.Value

	x, y := elliptic.Unmarshal(ec.Curve, pubKeyBytes)
	if x == nil {
		return errors.New("ecdsa: invalid public key")
	}

	ecdsaPubKey := &ecdsa.PublicKey{
		Curve: ec.Curve,
		X:     x,
		Y:     y,
	}

	if len(signature) != 2*ec.KeySize {
		return errors.New("ecdsa: invalid signature size")
	}

	hasher := crypto.SHA256.New()

	_, err := hasher.Write(msg)
	if err != nil {
		return errors.New("ecdsa: hash error")
	}

	hash := hasher.Sum(nil)

	r := big.NewInt(0).SetBytes(signature[:ec.KeySize])
	s := big.NewInt(0).SetBytes(signature[ec.KeySize:])

	verified := ecdsa.Verify(ecdsaPubKey, hash, r, s)
	if !verified {
		return errors.New("ecdsa: invalid signature")
	}

	return nil
}

type ellipticCurve struct {
	Curve   elliptic.Curve
	KeySize int
}

const (
	p256KeySize      = 32
	p384KeySize      = 48
	p521KeySize      = 66
	secp256k1KeySize = 32
)

func parseEllipticCurve(curve string) *ellipticCurve {
	switch curve {
	case "P-256":
		return &ellipticCurve{
			Curve:   elliptic.P256(),
			KeySize: p256KeySize,
		}
	case "P-384":
		return &ellipticCurve{
			Curve:   elliptic.P384(),
			KeySize: p384KeySize,
		}
	case "P-521":
		return &ellipticCurve{
			Curve:   elliptic.P521(),
			KeySize: p521KeySize,
		}
	case "secp256k1":
		return &ellipticCurve{
			Curve:   btcec.S256(),
			KeySize: secp256k1KeySize,
		}
	default:
		return nil
	}
}

func (v *PublicKeyVerifier) verifyEdDSA(pubKey *sigverifier.PublicKey, signature, msg []byte) error {
	if pubKey.JWK.Algorithm != "" && pubKey.JWK.Algorithm != "EdDSA" {
		return fmt.Errorf("unsupported OKP algorithm: %s", pubKey.JWK.Algorithm)
	}

	// Check the key size before calling ed25519.Verify() as it will panic in case of invalid key size.
	if len(pubKey.Value) != ed25519.PublicKeySize {
		return errors.New("ed25519: invalid key")
	}

	verified := ed25519.Verify(pubKey.Value, msg, signature)
	if !verified {
		return errors.New("ed25519: invalid signature")
	}

	return nil
}

func (v *PublicKeyVerifier) verifyRSA(key *sigverifier.PublicKey, signature, msg []byte) error {
	if key.JWK.Algorithm != "" && key.JWK.Algorithm != "PS256" {
		return fmt.Errorf("unsupported RSA algorithm: %s", key.JWK.Algorithm)
	}

	pubKey, err := x509.ParsePKCS1PublicKey(key.Value)
	if err != nil {
		return errors.New("rsa: invalid public key")
	}

	hash := crypto.SHA256
	hasher := hash.New()

	_, err = hasher.Write(msg)
	if err != nil {
		return errors.New("rsa: hash error")
	}

	hashed := hasher.Sum(nil)

	err = rsa.VerifyPSS(pubKey, hash, hashed, signature, nil)
	if err != nil {
		return errors.New("rsa: invalid signature")
	}

	return nil
}

var (
	// ErrJWKNotPresent is returned when no JWK is defined in a public key (must be defined for JwsVerificationKey2020).
	ErrJWKNotPresent = errors.New("JWK is not present")

	// ErrTypeNotJwsVerificationKey2020 is returned when a public key passed for signature verification has a type
	// different from JwsVerificationKey2020.
	ErrTypeNotJwsVerificationKey2020 = errors.New("a type of public key is not JwsVerificationKey2020")
)
