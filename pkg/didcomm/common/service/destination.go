/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package service

import (
	"fmt"

	diddoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
)

// Destination provides the recipientKeys, routingKeys, and serviceEndpoint for an outbound message.
type Destination struct {
	RecipientKeys        []string
	ServiceEndpoint      string
	RoutingKeys          []string
	TransportReturnRoute string
}

const (
	didCommServiceType = "did-communication"
)

// GetDestination constructs a Destination struct based on the given DID and parameters
// It resolves the DID using the given VDR, and uses CreateDestination under the hood.
func GetDestination(did string, vdr vdri.Registry) (*Destination, error) {
	didDoc, err := vdr.Resolve(did)
	if err != nil {
		return nil, fmt.Errorf("getDestination: failed to resolve did [%s] : %w", did, err)
	}

	return CreateDestination(didDoc)
}

// CreateDestination makes a DIDComm Destination object from a DID Doc as per the DIDComm service conventions:
// https://github.com/hyperledger/aries-rfcs/blob/master/features/0067-didcomm-diddoc-conventions/README.md.
func CreateDestination(didDoc *diddoc.Doc) (*Destination, error) {
	didCommService, ok := diddoc.LookupService(didDoc, didCommServiceType)
	if !ok {
		return nil, fmt.Errorf("create destination: missing DID doc service")
	}

	if didCommService.ServiceEndpoint == "" {
		return nil, fmt.Errorf("create destination: no service endpoint on didcomm service block in diddoc: %+v", didDoc)
	}

	if len(didCommService.RecipientKeys) == 0 {
		return nil, fmt.Errorf("create destination: no recipient keys on didcomm service block in diddoc: %+v", didDoc)
	}

	// TODO ensure recipient keys are did:key's
	//  https://github.com/hyperledger/aries-framework-go/issues/1604

	return &Destination{
		RecipientKeys:   didCommService.RecipientKeys,
		ServiceEndpoint: didCommService.ServiceEndpoint,
		RoutingKeys:     didCommService.RoutingKeys,
	}, nil
}
