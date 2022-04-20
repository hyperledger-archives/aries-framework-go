/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

// Endpoint contains endpoint specific content.
type Endpoint struct {
	// URI contains the endpoint URI.
	URI string `json:"uri"`
	// Accept contains the MediaType profiles accepted by this endpoint.
	Accept []string `json:"accept,omitempty"`
	// RoutingKeys contains the list of keys trusted as routing keys for the mediators/routers of this endpoint.
	RoutingKeys []string `json:"routingKeys,omitempty"`
}
