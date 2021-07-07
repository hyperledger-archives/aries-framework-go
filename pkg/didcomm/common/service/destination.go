/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package service

import (
	"fmt"

	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
)

// Destination provides the recipientKeys, routingKeys, and serviceEndpoint for an outbound message.
type Destination struct {
	RecipientKeys        []string
	ServiceEndpoint      string
	RoutingKeys          []string
	TransportReturnRoute string
	MediaTypeProfiles    []string
}

const (
	didCommServiceType = "did-communication"
)

// GetDestination constructs a Destination struct based on the given DID and parameters
// It resolves the DID using the given VDR, and uses CreateDestination under the hood.
func GetDestination(did string, vdr vdrapi.Registry) (*Destination, error) {
	docResolution, err := vdr.Resolve(did)
	if err != nil {
		return nil, fmt.Errorf("getDestination: failed to resolve did [%s] : %w", did, err)
	}

	return CreateDestination(docResolution.DIDDocument)
}
