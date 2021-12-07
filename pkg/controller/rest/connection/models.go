/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connection

// rotateDIDRequest model
//
// This is used for connection did rotation request
//
// swagger:parameters rotateDID
type rotateDIDRequest struct { // nolint: unused,deadcode
	// The ID of the connection record to rotate the DID of
	//
	// in: path
	// required: true
	ID string `json:"id"`
	// KID Key ID of the signing key in the connection's current DID, used to sign the DID rotation.
	KID string `json:"kid"`
	// NewDID DID that the given connection will rotate to.
	NewDID string `json:"new_did"`
}

// rotateDIDResponse model
//
// response of rotate DID action
//
// swagger:response rotateDIDResponse
type rotateDIDResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct{}
}

// createConnectionRequest model
//
// Request to create a didcomm v2 connection
//
// swagger:parameters createConnectionV2
type createConnectionRequest struct { // nolint: unused,deadcode
	MyDID    string `json:"my_did"`
	TheirDID string `json:"their_did"`
}

// createConnectionV2Response model
//
// response of create didcomm v2 connection action
//
// swagger:response createConnectionV2Response
type createConnectionV2Response struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		ID string `json:"id"`
	}
}
