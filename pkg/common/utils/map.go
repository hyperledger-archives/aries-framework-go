/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package utils

import "github.com/hyperledger/aries-framework-go/component/models/util/maphelpers"

// CopyMap performs shallow copy of map and nested maps.
func CopyMap(m map[string]interface{}) map[string]interface{} {
	return maphelpers.CopyMap(m)
}
