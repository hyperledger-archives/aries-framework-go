/*
 *
 * Copyright SecureKey Technologies Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 *
 */

package vdri

import (
	vdricommand "github.com/hyperledger/aries-framework-go/pkg/controller/command/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

// createPublicDIDRequest model
//
// This is used for operation to create public DID
//
// swagger:parameters createPublicDID
type createPublicDIDRequest struct { // nolint: unused,deadcode
	// Params for creating public DID
	//
	// in: path
	vdricommand.CreatePublicDIDArgs
}

// createPublicDIDResponse model
//
// This is used for returning public DID created
//
// swagger:response createPublicDIDResponse
type createPublicDIDResponse struct {
	// in: body
	DID did.Doc `json:"did"`
}
