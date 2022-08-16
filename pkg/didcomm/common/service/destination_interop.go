//go:build ACAPyInterop
// +build ACAPyInterop

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package service

import (
	"fmt"
	"strings"

	"github.com/btcsuite/btcutil/base58"

	"github.com/hyperledger/aries-framework-go/pkg/common/model"
	diddoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
)

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
	uri, err := didCommService.ServiceEndpoint.URI()
	if uri == "" || err != nil {
		return nil, fmt.Errorf("create destination: no service endpoint on didcomm service block in diddoc: %#v", didDoc)
	}

	if len(didCommService.RecipientKeys) == 0 {
		return nil, fmt.Errorf("create destination: no recipient keys on didcomm service block in diddoc: %#v", didDoc)
	}

	// Interop: service keys that are raw base58 public keys should be converted to did:key format
	return &Destination{
		RecipientKeys:     convertAnyB58Keys(didCommService.RecipientKeys),
		ServiceEndpoint:   model.NewDIDCommV1Endpoint(uri),
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
