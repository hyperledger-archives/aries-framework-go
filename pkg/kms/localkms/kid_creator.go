/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/jwkkid"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

// CreateKID creates a KID value based on the marshalled keyBytes of type kt. This function should be called for
// asymmetric public keys only (ECDSA DER or IEEE1363, ED25519, BLS12-381).
// returns:
//  - base64 raw (no padding) URL encoded KID
//  - error in case of error
func CreateKID(keyBytes []byte, kt kms.KeyType) (string, error) {
	return jwkkid.CreateKID(keyBytes, kt)
}
