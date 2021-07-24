/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ld

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext"
	"github.com/hyperledger/aries-framework-go/pkg/store/ld"
)

// ProviderID is a request/response model for operations that involve remote provider ID.
type ProviderID struct {
	ID string `json:"id"`
}

// AddContextsRequest is a request model for adding JSON-LD contexts.
type AddContextsRequest struct {
	Documents []ldcontext.Document `json:"documents"`
}

// AddRemoteProviderRequest is a request model for adding a new remote context provider.
type AddRemoteProviderRequest struct {
	Endpoint string `json:"endpoint"`
}

// GetAllRemoteProvidersResponse is a response model for listing all remote providers.
type GetAllRemoteProvidersResponse struct {
	Providers []ld.RemoteProviderRecord `json:"providers"`
}
