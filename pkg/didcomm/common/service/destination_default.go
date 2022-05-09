//go:build !ACAPyInterop
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
//nolint:gocyclo,funlen,gocognit
func CreateDestination(didDoc *diddoc.Doc) (*Destination, error) {
	var (
		sp                  model.Endpoint
		accept, routingKeys []string
		uri                 string
		err                 error
	)

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
		if accept, err = didCommService.ServiceEndpoint.Accept(); len(accept) == 0 || err != nil {
			accept = []string{defaultDIDCommV2Profile}
		}

		uri, err = didCommService.ServiceEndpoint.URI()
		if err != nil { // uri is required.
			return nil, fmt.Errorf("create destination: service endpoint URI for didcomm v2 service block "+
				"error: %+v, %w", didDoc, err)
		}

		routingKeys, err = didCommService.ServiceEndpoint.RoutingKeys()
		if err != nil { // routingKeys can be optional.
			routingKeys = nil
		}

		sp = model.NewDIDCommV2Endpoint([]model.DIDCommV2Endpoint{{URI: uri, Accept: accept, RoutingKeys: routingKeys}})
	} else { // didcomm v1 service
		didCommService, ok = diddoc.LookupService(didDoc, didCommServiceType)
		if !ok {
			return nil, fmt.Errorf("create destination: missing DID doc service")
		}

		uri, err = didCommService.ServiceEndpoint.URI()
		if err != nil { // uri is required.
			return nil, fmt.Errorf("create destination: service endpoint URI on didcomm v1 service block "+
				"in diddoc error: %+v, %w", didDoc, err)
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
		if len(didCommService.Accept) == 0 {
			didCommService.Accept = []string{defaultDIDCommProfile}
		}

		sp = model.NewDIDCommV1Endpoint(uri)
	}

	return &Destination{
		RecipientKeys:     didCommService.RecipientKeys,
		ServiceEndpoint:   sp,
		RoutingKeys:       didCommService.RoutingKeys,
		MediaTypeProfiles: didCommService.Accept,
		DIDDoc:            didDoc,
	}, nil
}
