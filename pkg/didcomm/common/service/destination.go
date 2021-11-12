/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package service

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
)

// Destination provides the recipientKeys, routingKeys, and serviceEndpoint for an outbound message.
type Destination struct {
	RecipientKeys        []string
	ServiceEndpoint      string
	RoutingKeys          []string
	TransportReturnRoute string
	MediaTypeProfiles    []string
	DIDDoc               *did.Doc
}

const (
	didCommServiceType      = "did-communication"
	didCommV2ServiceType    = "DIDCommMessaging"
	defaultDIDCommProfile   = "didcomm/aip2;env=rfc19"
	defaultDIDCommV2Profile = "didcomm/v2"
)

// GetDestination constructs a Destination struct based on the given DID and parameters
// It resolves the DID using the given VDR, and uses CreateDestination under the hood.
func GetDestination(didID string, vdr vdrapi.Registry) (*Destination, error) {
	docResolution, err := vdr.Resolve(didID)
	if err != nil {
		return nil, fmt.Errorf("getDestination: failed to resolve did [%s] : %w", didID, err)
	}

	return CreateDestination(docResolution.DIDDocument)
}
