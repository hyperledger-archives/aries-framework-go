/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdr

import (
	"encoding/json"

	storeDID "github.com/hyperledger/aries-framework-go/pkg/store/did"
)

// Document is model for did document.
type Document struct {
	DID json.RawMessage `json:"did,omitempty"`
}

// DIDArgs is model for did doc with fields related to command features.
type DIDArgs struct {
	Document
	Name string `json:"name,omitempty"`
}

// IDArg model
//
// This is used for querying/removing by did ID from input json.
//
type IDArg struct {
	// DidID
	ID string `json:"id"`
}

// DIDRecordResult holds the did doc records.
type DIDRecordResult struct {
	// Result
	Result []*storeDID.Record `json:"result,omitempty"`
}

// NameArg model
//
// This is used for querying by did name from input json.
//
type NameArg struct {
	// Name
	Name string `json:"name"`
}

// CreateDIDRequest is model for create did request.
type CreateDIDRequest struct {
	Method string                 `json:"method,omitempty"`
	DID    json.RawMessage        `json:"did,omitempty"`
	Opts   map[string]interface{} `json:"opts,omitempty"`
}
