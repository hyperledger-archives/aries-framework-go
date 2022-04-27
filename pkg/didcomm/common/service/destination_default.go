// +build !ACAPyInterop

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package service

import (
	"fmt"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/common/model"
	diddoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

// CreateDestination makes a DIDComm Destination object from a DID Doc as per the DIDComm service conventions:
// https://github.com/hyperledger/aries-rfcs/blob/master/features/0067-didcomm-diddoc-conventions/README.md.
//nolint:gocyclo,funlen
func CreateDestination(didDoc *diddoc.Doc) (*Destination, error) {
	// try DIDComm V2 and use it if found, else use default DIDComm v1 bloc.
	didCommService, ok := diddoc.LookupService(didDoc, didCommV2ServiceType)
	if ok { //nolint:nestif
		var recKeys []string

		for _, ka := range didDoc.KeyAgreement {
			keyID := ka.VerificationMethod.ID
			if strings.HasPrefix(keyID, "#") {
				keyID = didDoc.ID + keyID
			}

			recKeys = append(recKeys, keyID)
		}

		if len(recKeys) == 0 {
			return nil, fmt.Errorf("create destination: no keyAgreements in diddoc for didcomm v2 service bloc. "+
				"DIDDoc: %+v", didDoc)
		}

		// use keyAgreements as recipientKeys
		didCommService.RecipientKeys = recKeys

		// if Accept is missing, ensure DIDCommV2 is at least added for packer selection based on MediaTypeProfile.
		if len(didCommService.ServiceEndpoint.Accept) == 0 {
			didCommService.ServiceEndpoint.Accept = []string{defaultDIDCommV2Profile}
		}
	} else {
		didCommService, ok = diddoc.LookupService(didDoc, didCommServiceType)
		if !ok {
			return nil, fmt.Errorf("create destination: missing DID doc service")
		}

		if didCommService.ServiceEndpoint.URI == "" {
			return nil, fmt.Errorf("create destination: no service endpoint URI on didcomm service block in diddoc: %+v", didDoc)
		}

		if len(didCommService.RecipientKeys) == 0 {
			return nil, fmt.Errorf("create destination: no recipient keys on didcomm service block in diddoc: %+v", didDoc)
		}

		for i, k := range didCommService.RecipientKeys {
			if !strings.HasPrefix(k, "did:") {
				return nil, fmt.Errorf("create destination: recipient key %d:[%v] of didComm '%s' not a did:key", i+1,
					k, didCommService.ID)
			}
		}

		// if Accept is missing, ensure DIDCommV1 is at least added for packer selection based on MediaTypeProfile.
		if len(didCommService.ServiceEndpoint.Accept) == 0 {
			didCommService.ServiceEndpoint.Accept = []string{defaultDIDCommProfile}
		}
	}

	return &Destination{
		RecipientKeys: didCommService.RecipientKeys,
		ServiceEndpoint: model.Endpoint{
			URI:         didCommService.ServiceEndpoint.URI,
			RoutingKeys: didCommService.ServiceEndpoint.RoutingKeys,
			Accept:      didCommService.ServiceEndpoint.Accept,
		},
		DIDDoc: didDoc,
	}, nil
}
