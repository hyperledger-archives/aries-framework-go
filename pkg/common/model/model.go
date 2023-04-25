/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

import (
	"github.com/hyperledger/aries-framework-go/component/models/did/endpoint"
)

// EndpointType endpoint type.
type EndpointType = endpoint.EndpointType

const (
	// DIDCommV1 type.
	DIDCommV1 = endpoint.DIDCommV1
	// DIDCommV2 type.
	DIDCommV2 = endpoint.DIDCommV2
	// Generic type.
	Generic = endpoint.Generic
)

// ServiceEndpoint api for fetching ServiceEndpoint content based off of a DIDComm V1, V2 or DIDCore format.
type ServiceEndpoint = endpoint.ServiceEndpoint

// Endpoint contains endpoint specific content. Content of ServiceEndpoint api above will be used by priority:
// 1- DIDcomm V2
// 2- DIDComm V1
// 3- DIDCore
// To force lower priority endpoint content, avoid setting higher priority data during Unmarshal() execution.
type Endpoint = endpoint.Endpoint

// DIDCommV2Endpoint contains ServiceEndpoint data specifically for DIDcommV2 and is wrapped in Endpoint as an array.
type DIDCommV2Endpoint = endpoint.DIDCommV2Endpoint

// NewDIDCommV2Endpoint creates a DIDCommV2 endpoint with the given array of endpoints. At the time of writing this
// comment, only the first endpoint is effective in the API. Additional logic is required to use a different index.
func NewDIDCommV2Endpoint(endpoints []DIDCommV2Endpoint) Endpoint {
	return endpoint.NewDIDCommV2Endpoint(endpoints)
}

// NewDIDCommV1Endpoint creates a DIDCommV1 endpoint.
func NewDIDCommV1Endpoint(uri string) Endpoint {
	return endpoint.NewDIDCommV1Endpoint(uri)
}

// NewDIDCoreEndpoint creates a generic DIDCore endpoint.
func NewDIDCoreEndpoint(genericEndpoint interface{}) Endpoint {
	return endpoint.NewDIDCoreEndpoint(genericEndpoint)
}
