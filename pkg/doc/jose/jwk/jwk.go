/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwk

import (
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk"
)

// JWK (JSON Web Key) is a JSON data structure that represents a cryptographic key.
type JWK = jwk.JWK

// ErrInvalidKey is returned when passed JWK is invalid.
var ErrInvalidKey = jwk.ErrInvalidKey
