/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdsasecp256k1signature2019

import (
	"crypto"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec"

	sigverifier "github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
)

const (
	secp256k1KeySize = 32
)

// PublicKeyVerifier verifies a secp256k1 signature taking public key bytes and JSON Web Key as input.
// NOTE: this verifier is present for backward compatibility reasons and can be removed later.
// Please use CryptoVerifier or your own verifier.
type PublicKeyVerifier struct {
}

// Verify will verify a signature.
func (v *PublicKeyVerifier) Verify(pubKey *sigverifier.PublicKey, msg, signature []byte) error {
	err := v.validatePublicKey(pubKey)
	if err != nil {
		return err
	}

	if len(signature) != 2*secp256k1KeySize {
		return errors.New("ecdsa: invalid signature size")
	}

	curve := btcec.S256()

	btcecPubKey, err := btcec.ParsePubKey(pubKey.Value, curve)
	if err != nil {
		return errors.New("ecdsa: invalid public key")
	}

	ecdsaPubKey := btcecPubKey.ToECDSA()
	hasher := crypto.SHA256.New()

	_, err = hasher.Write(msg)
	if err != nil {
		return errors.New("ecdsa: hash error")
	}

	hash := hasher.Sum(nil)

	r := big.NewInt(0).SetBytes(signature[:secp256k1KeySize])
	s := big.NewInt(0).SetBytes(signature[secp256k1KeySize:])

	verified := ecdsa.Verify(ecdsaPubKey, hash, r, s)
	if !verified {
		return errors.New("ecdsa: invalid signature")
	}

	return nil
}

func (v *PublicKeyVerifier) validatePublicKey(pubKey *sigverifier.PublicKey) error {
	// A presence of JSON Web Key is mandatory (due to EcdsaSecp256k1VerificationKey2019 type).
	if pubKey.JWK == nil {
		return ErrJWKNotPresent
	}

	if pubKey.Type != jwkType {
		return ErrTypeNotEcdsaSecp256k1VerificationKey2019
	}

	if pubKey.JWK.Kty != "EC" {
		return fmt.Errorf("unsupported key type: '%s'", pubKey.JWK.Kty)
	}

	if pubKey.JWK.Crv != "secp256k1" {
		return fmt.Errorf("ecdsa: not secp256k1 curve: '%s'", pubKey.JWK.Crv)
	}

	if pubKey.JWK.Algorithm != "" && pubKey.JWK.Algorithm != "ES256K" {
		return fmt.Errorf("ecdsa: not ES256K EC algorithm: '%s'", pubKey.JWK.Algorithm)
	}

	return nil
}

var (
	// ErrJWKNotPresent is returned when no JWK is defined in a public key
	// (must be defined for EcdsaSecp256k1VerificationKey2019).
	ErrJWKNotPresent = errors.New("JWK is not present")

	// ErrTypeNotEcdsaSecp256k1VerificationKey2019 is returned when a public key passed for signature verification
	// has a type different from EcdsaSecp256k1VerificationKey2019.
	ErrTypeNotEcdsaSecp256k1VerificationKey2019 = errors.New("a type of public key is not EcdsaSecp256k1VerificationKey2019") //nolint:lll
)
