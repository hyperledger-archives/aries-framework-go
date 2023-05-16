// +build !js,!wasm

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"time"

	"github.com/VictoriaMetrics/fastcache"
)

// NewExpirableSchemaCache creates new instance of ExpirableSchemaCache.
func NewExpirableSchemaCache(size int, expiration time.Duration) *ExpirableSchemaCache {
	return &ExpirableSchemaCache{
		cache:      fastcache.New(size),
		expiration: expiration,
	}
}
