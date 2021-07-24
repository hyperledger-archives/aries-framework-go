/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ld

import (
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext"
)

// addContextsReq model for adding new JSON-LD contexts.
//
// swagger:parameters addContextsReq
type addContextsReq struct { //nolint: unused,deadcode
	// in: body
	Documents []ldcontext.Document `json:"documents"`
}

// addRemoteProviderReq model for adding a new remote context provider.
//
// swagger:parameters addRemoteProviderReq
type addRemoteProviderReq struct { //nolint: unused,deadcode
	// in: body
	Body ld.AddRemoteProviderRequest
}

// refreshRemoteProviderReq model for updating JSON-LD contexts from the remote context provider.
//
// swagger:parameters refreshRemoteProviderReq
type refreshRemoteProviderReq struct { //nolint: unused,deadcode
	// in: path
	// required: true
	ID string `json:"id"`
}

// deleteRemoteProviderReq model for deleting remote provider and JSON-LD contexts from that provider.
//
// swagger:parameters deleteRemoteProviderReq
type deleteRemoteProviderReq struct { //nolint: unused,deadcode
	// in: path
	// required: true
	ID string `json:"id"`
}

// getAllRemoteProvidersResp model for getting list of all remote context providers from the underlying storage.
//
// swagger:response getAllRemoteProvidersResp
type getAllRemoteProvidersResp struct { //nolint: unused,deadcode
	// in: body
	Body ld.GetAllRemoteProvidersResponse
}

// getAllRemoteProvidersReq model is an empty model
//
// swagger:parameters getAllRemoteProvidersReq
type getAllRemoteProvidersReq struct { // nolint:unused,deadcode
	// in: body
	Body struct{}
}

// refreshAllRemoteProvidersReq model is an empty model
//
// swagger:parameters refreshAllRemoteProvidersReq
type refreshAllRemoteProvidersReq struct { // nolint:unused,deadcode
	// in: body
	Body struct{}
}
