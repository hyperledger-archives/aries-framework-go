/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/kms"
)

// createKeySetRes model
//
// This is used for returning the create set response
//
// swagger:response createKeySetRes
type createKeySetRes struct {

	// in: body
	kms.CreateKeySetResponse
}
