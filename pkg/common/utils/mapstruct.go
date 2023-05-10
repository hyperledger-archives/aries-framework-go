/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package utils

import (
	"github.com/mitchellh/mapstructure"

	"github.com/hyperledger/aries-framework-go/component/models/util/maphelpers"
)

// JSONNumberToJwtNumericDate hook for mapstructure library to decode json.Number to jwt.NumericDate.
func JSONNumberToJwtNumericDate() mapstructure.DecodeHookFuncType {
	return maphelpers.JSONNumberToJwtNumericDate()
}
