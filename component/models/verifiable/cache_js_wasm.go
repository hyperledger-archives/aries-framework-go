/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import "time"

// NewExpirableSchemaCache creates new instance of ExpirableSchemaCache.
func NewExpirableSchemaCache(size int, expiration time.Duration) *ExpirableSchemaCache {
	// TODO Add cache implementation for VC wasm https://github.com/hyperledger/aries-framework-go/issues/1009
	return &ExpirableSchemaCache{
		cache:      nil,
		expiration: expiration,
	}
}
