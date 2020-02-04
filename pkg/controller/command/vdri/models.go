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
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
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
