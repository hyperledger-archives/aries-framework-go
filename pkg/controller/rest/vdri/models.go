/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdri

import (
	"encoding/json"

	vdricommand "github.com/hyperledger/aries-framework-go/pkg/controller/command/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	didstore "github.com/hyperledger/aries-framework-go/pkg/store/did"
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

// saveDIDReq model
//
// This is used to save the did with did document.
//
// swagger:parameters saveDIDReq
type saveDIDReq struct { // nolint: unused,deadcode
	// Params for saving the did document (pass the did document as json raw message)
	//
	// in: body
	Params vdricommand.DIDArgs
}

// getDIDReq model
//
// This is used to retrieve the did document.
//
// swagger:parameters getDIDReq
type getDIDReq struct { // nolint: unused,deadcode
	// DID ID - pass the did
	//
	// in: path
	// required: true
	ID string `json:"id"`
}

// resolveDIDReq model
//
// This is used to retrieve the did document.
//
// swagger:parameters resolveDIDReq
type resolveDIDReq struct { // nolint: unused,deadcode
	// DID ID - pass the did
	//
	// in: path
	// required: true
	ID string `json:"id"`
}

// documentRes model
//
// This is used for returning query connection result for single record search
//
// swagger:response documentRes
type documentRes struct { // nolint: unused,deadcode

	// in: body
	DID json.RawMessage `json:"did,omitempty"`
}

// didRecordResult model
//
// This is used to return did records.
//
// swagger:response didRecordResult
type didRecordResult struct {
	// in: body
	Result []*didstore.Record `json:"result,omitempty"`
}
