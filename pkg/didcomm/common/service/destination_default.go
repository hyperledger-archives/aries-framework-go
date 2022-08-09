//go:build !ACAPyInterop
// +build !ACAPyInterop

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package service

import (
	"fmt"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/common/model"
	diddoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/internal/didkeyutil"
)

// CreateDestination makes a DIDComm Destination object from a DID Doc as per the DIDComm service conventions:
// https://github.com/hyperledger/aries-rfcs/blob/master/features/0067-didcomm-diddoc-conventions/README.md.
func CreateDestination(didDoc *diddoc.Doc) (*Destination, error) {
	// try DIDComm v2 first
	if didCommService, ok := diddoc.LookupService(didDoc, didCommV2ServiceType); ok {
		return createDIDCommV2Destination(didDoc, didCommService)
	}
	// try DIDComm v1
	if didCommService, ok := diddoc.LookupService(didDoc, didCommServiceType); ok {
		return createDIDCommV1Destination(didDoc, didCommService)
	}
	// try DIDComm v1 legacy
	if didCommService, ok := diddoc.LookupService(didDoc, legacyDIDCommServiceType); ok {
		return createLegacyDestination(didDoc, didCommService)
	}

	return nil, fmt.Errorf("create destination: missing DID doc service")
}

func createDIDCommV2Destination(didDoc *diddoc.Doc, didCommService *diddoc.Service) (*Destination, error) {
	var (
		sp                  model.Endpoint
		accept, routingKeys []string
		uri                 string
		err                 error
		recKeys             []string
	)

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

	return &Destination{
		RecipientKeys:     recKeys,
		ServiceEndpoint:   sp,
		RoutingKeys:       didCommService.RoutingKeys,
		MediaTypeProfiles: didCommService.Accept,
		DIDDoc:            didDoc,
	}, nil
}

func createDIDCommV1Destination(didDoc *diddoc.Doc, didCommService *diddoc.Service) (*Destination, error) {
	uri, err := didCommService.ServiceEndpoint.URI()
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

	sp := model.NewDIDCommV1Endpoint(uri)

	return &Destination{
		RecipientKeys:     didCommService.RecipientKeys,
		ServiceEndpoint:   sp,
		RoutingKeys:       didCommService.RoutingKeys,
		MediaTypeProfiles: didCommService.Accept,
		DIDDoc:            didDoc,
	}, nil
}

func createLegacyDestination(didDoc *diddoc.Doc, didCommService *diddoc.Service) (*Destination, error) {
	uri, err := didCommService.ServiceEndpoint.URI()
	if uri == "" || err != nil {
		return nil, fmt.Errorf("create destination: no service endpoint on didcomm service block in diddoc: %#v", didDoc)
	}

	if len(didCommService.RecipientKeys) == 0 {
		return nil, fmt.Errorf("create destination: no recipient keys on didcomm service block in diddoc: %#v", didDoc)
	}

	// if Accept is missing, ensure IndyAgent is at least added for packer selection based on MediaTypeProfile.
	if len(didCommService.Accept) == 0 {
		didCommService.Accept = []string{legacyDIDCommServiceType}
	}

	return &Destination{
		RecipientKeys:     didkeyutil.ConvertBase58KeysToDIDKeys(didCommService.RecipientKeys),
		ServiceEndpoint:   model.NewDIDCommV1Endpoint(uri),
		RoutingKeys:       didkeyutil.ConvertBase58KeysToDIDKeys(didCommService.RoutingKeys),
		MediaTypeProfiles: didCommService.Accept,
	}, nil
}
