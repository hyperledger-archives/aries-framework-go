/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwkkid

import (
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/util/jwkkid"
	"github.com/hyperledger/aries-framework-go/spi/kms"
)

// CreateKID creates a KID value based on the marshalled keyBytes of type kt. This function should be called for
// asymmetric public keys only (ECDSA DER or IEEE-P1363, ED25519, X25519, BLS12381G2).
// returns:
//   - base64 raw (no padding) URL encoded KID
//   - error in case of error
func CreateKID(keyBytes []byte, kt kms.KeyType) (string, error) {
	return jwkkid.CreateKID(keyBytes, kt)
}

// BuildJWK builds a go jose JWK from keyBytes with key type kt.
func BuildJWK(keyBytes []byte, kt kms.KeyType) (*jwk.JWK, error) {
	return jwkkid.BuildJWK(keyBytes, kt)
}
