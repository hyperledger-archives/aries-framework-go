/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package service

import (
	"fmt"

	"github.com/btcsuite/btcutil/base58"

	diddoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
)

// Destination provides the recipientKeys, routingKeys, and serviceEndpoint for an outbound message.
type Destination struct {
	RecipientKeys        []string
	ServiceEndpoint      string
	RoutingKeys          []string
	TransportReturnRoute string
	MediaTypes           []string
}

const (
	didCommServiceType = "did-communication"
	// legacyDIDCommServiceType is the non-spec service type used by legacy didcomm agent systems.
	legacyDIDCommServiceType = "IndyAgent"
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

// CreateDestination makes a DIDComm Destination object from a DID Doc as per the DIDComm service conventions:
// https://github.com/hyperledger/aries-rfcs/blob/master/features/0067-didcomm-diddoc-conventions/README.md.
func CreateDestination(didDoc *diddoc.Doc) (*Destination, error) {
	didCommService, ok := diddoc.LookupService(didDoc, didCommServiceType)
	if !ok {
		// Interop: legacy docs may use the IndyAgent service type for didcomm, with slightly different content format.
		return createDestinationFromIndy(didDoc)
	}

	if didCommService.ServiceEndpoint == "" {
		return nil, fmt.Errorf("create destination: no service endpoint on didcomm service block in diddoc: %+v", didDoc)
	}

	if len(didCommService.RecipientKeys) == 0 {
		return nil, fmt.Errorf("create destination: no recipient keys on didcomm service block in diddoc: %+v", didDoc)
	}

	return &Destination{
		RecipientKeys:   didCommService.RecipientKeys,
		ServiceEndpoint: didCommService.ServiceEndpoint,
		RoutingKeys:     didCommService.RoutingKeys,
		MediaTypes:      didCommService.Accept,
	}, nil
}

func createDestinationFromIndy(didDoc *diddoc.Doc) (*Destination, error) {
	didCommService, ok := diddoc.LookupService(didDoc, legacyDIDCommServiceType)
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

	// convert plain base58 keys to did:key
	recKeys := lookupIndyRecipientKeys(didDoc, didCommService.RecipientKeys)
	routeKeys := lookupIndyRecipientKeys(didDoc, didCommService.RoutingKeys)

	return &Destination{
		RecipientKeys:   recKeys,
		ServiceEndpoint: didCommService.ServiceEndpoint,
		RoutingKeys:     routeKeys,
	}, nil
}

func lookupIndyRecipientKeys(didDoc *diddoc.Doc, recipientKeys []string) []string {
	b58VMkeys := map[string]int{}

	for i, vm := range didDoc.VerificationMethod {
		b58Key := base58.Encode(vm.Value)
		b58VMkeys[b58Key] = i
	}

	var didKeys []string

	for _, key := range recipientKeys {
		vmIdx, ok := b58VMkeys[key]
		if !ok {
			continue
		}

		vm := didDoc.VerificationMethod[vmIdx]
		if vm.Type != "Ed25519VerificationKey2018" {
			// TODO: handle further key types
			continue
		}

		didKey, _ := fingerprint.CreateDIDKey(vm.Value)

		didKeys = append(didKeys, didKey)
	}

	return didKeys
}
