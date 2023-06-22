/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kmssigner

import (
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/util/kmssigner"
	"github.com/hyperledger/aries-framework-go/spi/kms"
)

// KMSSigner implements JWS Signer interface using a KMS key handle and a crypto.Crypto instance.
type KMSSigner = kmssigner.KMSSigner

// KeyTypeToJWA provides the JWA corresponding to keyType.
func KeyTypeToJWA(keyType kms.KeyType) string {
	return kmssigner.KeyTypeToJWA(keyType)
}
