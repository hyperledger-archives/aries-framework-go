/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import "github.com/hyperledger/aries-framework-go/pkg/doc/jsonld"

// addContextReq model
//
// This is used for adding new JSON-LD contexts.
//
// swagger:parameters addContextReq
type addContextReq struct { //nolint: unused,deadcode
	// in: body
	Documents []jsonld.ContextDocument `json:"documents"`
}
