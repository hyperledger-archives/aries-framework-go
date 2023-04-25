/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto/elliptic"
	"errors"

	"github.com/btcsuite/btcd/btcec"

	kmsapi "github.com/hyperledger/aries-framework-go/spi/kms"
)

// MapECCurveToKeyType makes a mapping of Elliptic Curve to KeyType of kms.
func MapECCurveToKeyType(curve elliptic.Curve) (kmsapi.KeyType, error) {
	switch curve {
	case elliptic.P256():
		return kmsapi.ECDSAP256TypeIEEEP1363, nil

	case elliptic.P384():
		return kmsapi.ECDSAP384TypeIEEEP1363, nil

	case elliptic.P521():
		return kmsapi.ECDSAP521TypeIEEEP1363, nil

	case btcec.S256():
		return kmsapi.ECDSASecp256k1TypeIEEEP1363, nil

	default:
		return "", errors.New("unsupported curve")
	}
}
