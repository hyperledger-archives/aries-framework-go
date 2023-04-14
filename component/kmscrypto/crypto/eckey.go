/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/hyperledger/aries-framework-go/spi/crypto"
)

// ToECKey converts key to an ecdsa public key. It returns an error if the curve is invalid.
func ToECKey(key *crypto.PublicKey) (*ecdsa.PublicKey, error) {
	crv, err := toCurve(key.Curve)
	if err != nil {
		return nil, err
	}

	return &ecdsa.PublicKey{
		Curve: crv,
		X:     new(big.Int).SetBytes(key.X),
		Y:     new(big.Int).SetBytes(key.Y),
	}, nil
}

func toCurve(crv string) (elliptic.Curve, error) {
	switch crv {
	case "P-256", "NIST_P256":
		return elliptic.P256(), nil
	case "P-384", "NIST_P384":
		return elliptic.P384(), nil
	case "P-521", "NIST_P521":
		return elliptic.P521(), nil
	}

	return nil, fmt.Errorf("invalid curve '%s'", crv)
}
