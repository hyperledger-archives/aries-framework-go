/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"github.com/btcsuite/btcutil/base58"
)

// LookupService returns the service from the given DIDDoc matching the given service type.
func LookupService(didDoc *Doc, serviceType string) (*Service, bool) {
	const notFound = -1
	index := notFound

	for i := range didDoc.Service {
		if didDoc.Service[i].Type == serviceType {
			if index == notFound || didDoc.Service[index].Priority > didDoc.Service[i].Priority {
				index = i
			}
		}
	}

	if index == notFound {
		return nil, false
	}

	return &didDoc.Service[index], true
}

// LookupRecipientKeys gets the recipient keys from the did doc which match the given parameters.
func LookupRecipientKeys(didDoc *Doc, serviceType, keyType string) ([]string, bool) {
	didCommService, ok := LookupService(didDoc, serviceType)
	if !ok {
		return nil, false
	}

	if len(didCommService.RecipientKeys) == 0 {
		return nil, false
	}

	var recipientKeys []string

	for _, keyID := range didCommService.RecipientKeys {
		key, ok := LookupPublicKey(keyID, didDoc)
		if !ok {
			return nil, false
		}

		if key.Type == keyType {
			// TODO fix hardcode base58 https://github.com/hyperledger/aries-framework-go/issues/1207
			recipientKeys = append(recipientKeys, base58.Encode(key.Value))
		}
	}

	if len(recipientKeys) == 0 {
		return nil, false
	}

	return recipientKeys, true
}

// LookupPublicKey returns the public key with the given id from the given DID Doc.
func LookupPublicKey(id string, didDoc *Doc) (*PublicKey, bool) {
	for _, key := range didDoc.PublicKey {
		if key.ID == id {
			return &key, true
		}
	}

	return nil, false
}
