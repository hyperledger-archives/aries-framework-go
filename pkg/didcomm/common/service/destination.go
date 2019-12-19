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
// Can be populated from an Invitation or DIDDoc.
type Destination struct {
	RecipientKeys        []string
	ServiceEndpoint      string
	RoutingKeys          []string
	TransportReturnRoute string
}

const (
	didCommServiceType = "did-communication"
	ed25519KeyType     = "Ed25519VerificationKey2018"
)

// GetDestination constructs a Destination struct based on the given DID and parameters
// It resolves the DID using the given VDR, and collects relevant data from the resolved DIDDoc.
func GetDestination(did string, vdr vdri.Registry) (*Destination, error) {
	didDoc, err := vdr.Resolve(did)
	if err != nil {
		return nil, err
	}

	return CreateDestination(didDoc)
}

// CreateDestination makes a DIDComm Destination object from a DID Doc
func CreateDestination(didDoc *diddoc.Doc) (*Destination, error) {
	didCommService, ok := diddoc.LookupService(didDoc, didCommServiceType)
	if !ok {
		return nil, fmt.Errorf("create destination: missing DID doc service")
	}

	recipientKeys, ok := diddoc.LookupRecipientKeys(didDoc, didCommServiceType, ed25519KeyType)
	if !ok {
		return nil, fmt.Errorf("create destination: missing keys")
	}

	return &Destination{
		RecipientKeys:   recipientKeys,
		ServiceEndpoint: didCommService.ServiceEndpoint,
	}, nil
}
