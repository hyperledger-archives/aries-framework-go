/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package service

import (
	"fmt"
	"strings"

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
	MediaTypeProfiles    []string
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
		// Interop: fallback to using IndyAgent service type
		didCommService, ok = diddoc.LookupService(didDoc, legacyDIDCommServiceType)
		if !ok {
			return nil, fmt.Errorf("create destination: missing DID doc service")
		}
	}

	if didCommService.ServiceEndpoint == "" {
		return nil, fmt.Errorf("create destination: no service endpoint on didcomm service block in diddoc: %+v", didDoc)
	}

	if len(didCommService.RecipientKeys) == 0 {
		return nil, fmt.Errorf("create destination: no recipient keys on didcomm service block in diddoc: %+v", didDoc)
	}

	// Interop: service keys that are raw base58 public keys should be converted to did:key format
	return &Destination{
		RecipientKeys:     convertAnyB58Keys(didCommService.RecipientKeys),
		ServiceEndpoint:   didCommService.ServiceEndpoint,
		RoutingKeys:       convertAnyB58Keys(didCommService.RoutingKeys),
		MediaTypeProfiles: didCommService.Accept,
	}, nil
}

func convertAnyB58Keys(keys []string) []string {
	var didKeys []string

	for _, key := range keys {
		if key == "" {
			didKeys = append(didKeys, key)
			continue
		}

		// skip if the key is a relative did-url (ie, it starts with ?, /, or #)
		if strings.Contains("?/#", string(key[0])) { // nolint:gocritic
			didKeys = append(didKeys, key)
			continue
		}

		// skip if the key is already a did
		if strings.HasPrefix(key, "did:") {
			didKeys = append(didKeys, key)
			continue
		}

		rawKey := base58.Decode(key)
		if len(rawKey) == 0 {
			didKeys = append(didKeys, key)
			continue
		}

		didKey, _ := fingerprint.CreateDIDKey(rawKey)

		didKeys = append(didKeys, didKey)
	}

	return didKeys
}
