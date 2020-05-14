/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdhes

import (
	"fmt"

	commonpb "github.com/google/tink/go/proto/common_go_proto"

	ecdhesaeadpb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdhes_aead_go_proto"
)

// GetCurveType is a utility function that converts a string EC curve name into an EC curve proto type
func GetCurveType(curve string) (commonpb.EllipticCurveType, error) {
	switch curve {
	case "secp256r1", "NIST_P256", "P-256", "EllipticCurveType_NIST_P256":
		return commonpb.EllipticCurveType_NIST_P256, nil
	case "secp384r1", "NIST_P384", "P-384", "EllipticCurveType_NIST_P384":
		return commonpb.EllipticCurveType_NIST_P384, nil
	case "secp521r1", "NIST_P521", "P-521", "EllipticCurveType_NIST_P521":
		return commonpb.EllipticCurveType_NIST_P521, nil
	default:
		return 0, fmt.Errorf("curve %s not supported", curve)
	}
}

// GetKeyType is a utility function that converts a string type value into an proto KeyType
func GetKeyType(keyType string) (ecdhesaeadpb.KeyType, error) {
	switch keyType {
	case "EC":
		return ecdhesaeadpb.KeyType_EC, nil
	case "OKP":
		return ecdhesaeadpb.KeyType_OKP, nil
	default:
		return 0, fmt.Errorf("key type %s not supported", keyType)
	}
}
