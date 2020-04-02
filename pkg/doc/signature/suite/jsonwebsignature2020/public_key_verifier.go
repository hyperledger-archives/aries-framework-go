/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jsonwebsignature2020

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec"

	sigverifier "github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
)

// PublicKeyVerifierEC verifies a ECDSA signature taking public key bytes as input.
// NOTE: this verifier is present for backward compatibility reasons and can be removed soon.
// Please use CryptoVerifier or your own verifier.
type PublicKeyVerifierEC struct {
}

// Verify will verify a signature.
func (v *PublicKeyVerifierEC) Verify(pubKey *sigverifier.PublicKey, doc, signature []byte) error {
	if pubKey.JWK == nil {
		return errors.New("JWK is not defined")
	}

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

	_, err := hasher.Write(doc)
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
