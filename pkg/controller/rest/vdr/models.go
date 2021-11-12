/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdr

import (
	"encoding/json"

	vdrcommand "github.com/hyperledger/aries-framework-go/pkg/controller/command/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	didstore "github.com/hyperledger/aries-framework-go/pkg/store/did"
)

// saveDIDReq model
//
// This is used to save the did with did document.
//
// swagger:parameters saveDIDReq
type saveDIDReq struct { // nolint: unused,deadcode
	// Params for saving the did document (pass the did document as json raw message)
	//
	// in: body
	Params vdrcommand.DIDArgs
}

// createDIDReq model
//
// This is used to create the did.
//
// swagger:parameters saveDIDReq
type createIDReq struct { // nolint: unused,deadcode
	// Params for creating the did document
	//
	// in: body
	Params vdrcommand.CreateDIDRequest
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
type documentRes struct {

	// in: body
	DID json.RawMessage `json:"did,omitempty"`
}

// resolveDIDRes model
//
// This is used for returning DID resolution response.
//
// swagger:response resolveDIDRes
type resolveDIDRes struct { // nolint: unused,deadcode

	// in: body
	Result json.RawMessage `json:"result,omitempty"`
}

// docResolutionResponse model
//
// This is used for returning DID document resolution response.
//
// swagger:response docResResponse
type docResolutionResponse struct { // nolint: unused,deadcode

	// in: body
	Result *did.DocResolution `json:"result,omitempty"`
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
