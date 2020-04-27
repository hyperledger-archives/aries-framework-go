/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/kms"
)

// createKeySetReq model
//
// This is used for createKeySet request.
//
// swagger:parameters createKeySetReq
type createKeySetReq struct { // nolint: unused,deadcode
	// Params for createKeySey
	//
	// in: body
	kms.CreateKeySetRequest
}

// createKeySetRes model
//
// This is used for returning the create set response
//
// swagger:response createKeySetRes
type createKeySetRes struct { // nolint: unused,deadcode

	// in: body
	kms.CreateKeySetResponse
}
