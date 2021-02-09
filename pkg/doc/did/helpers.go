/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package did

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

// LookupDIDCommRecipientKeys gets the DIDComm recipient keys from the did doc which match the given parameters.
// DIDComm recipient keys are encoded as did:key identifiers.
// See:
// - https://github.com/hyperledger/aries-rfcs/blob/master/features/0067-didcomm-diddoc-conventions/README.md
// - https://github.com/hyperledger/aries-rfcs/blob/master/features/0360-use-did-key/README.md
func LookupDIDCommRecipientKeys(didDoc *Doc) ([]string, bool) {
	didCommService, ok := LookupService(didDoc, "did-communication")
	if !ok {
		return nil, false
	}

	if len(didCommService.RecipientKeys) == 0 {
		return nil, false
	}

	return didCommService.RecipientKeys, true
}

// LookupPublicKey returns the public key with the given id from the given DID Doc.
func LookupPublicKey(id string, didDoc *Doc) (*VerificationMethod, bool) {
	for _, key := range didDoc.VerificationMethod {
		if key.ID == id {
			return &key, true
		}
	}

	return nil, false
}
