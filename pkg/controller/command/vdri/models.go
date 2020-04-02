/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdri

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	storeDID "github.com/hyperledger/aries-framework-go/pkg/store/did"
)

// CreatePublicDIDArgs contains parameters for creating new public DID
type CreatePublicDIDArgs struct {
	// Params for creating public DID
	Method string `json:"method"`

	// RequestHeader to be included while submitting request to http binding URL
	RequestHeader string `json:"header"`
}

// CreatePublicDIDResponse for returning public DID created
type CreatePublicDIDResponse struct {
	// TODO return base64-encoded raw bytes of the DID doc [Issue: #855]
	DID *did.Doc `json:"did"`
}

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
