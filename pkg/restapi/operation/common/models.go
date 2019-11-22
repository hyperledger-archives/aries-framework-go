/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

// CreatePublicDIDRequest model
//
// This is used for operation to create public DID
//
// swagger:parameters createPublicDID
type CreatePublicDIDRequest struct {
	// Params for creating public DID
	//
	// in: path
	*CreatePublicDIDParams
}

// CreatePublicDIDParams contains parameters for creating new public DID
type CreatePublicDIDParams struct {
	// Params for creating public DID
	Method string `json:"method"`

	// RequestHeader to be included while submitting request to http binding URL
	RequestHeader string `json:"header"`
}

// CreatePublicDIDResponse model
//
// This is used for returning public DID created
//
// swagger:response createPublicDIDResponse
type CreatePublicDIDResponse struct {

	// in: body
	// TODO return base64-encoded raw bytes of the DID doc [Issue: #855]
	DID *did.Doc `json:"did"`
}
