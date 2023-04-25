/*
Copyright Avast Software. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"fmt"
)

// ToLegacyRawDoc converts document to raw doc.
func (doc *Doc) ToLegacyRawDoc() (interface{}, error) {
	context := ContextV1Old

	publicKey, err := populateRawVM(context, doc.ID, doc.processingMeta.baseURI, doc.VerificationMethod)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of Legacy Verification Method failed: %w", err)
	}

	auths := populateRawVerificationLegacy(doc.processingMeta.baseURI, doc.ID, doc.Authentication)

	assertionMethods := populateRawVerificationLegacy(doc.processingMeta.baseURI, doc.ID,
		doc.AssertionMethod)

	capabilityDelegations := populateRawVerificationLegacy(doc.processingMeta.baseURI, doc.ID,
		doc.CapabilityDelegation)

	capabilityInvocations := populateRawVerificationLegacy(doc.processingMeta.baseURI, doc.ID,
		doc.CapabilityInvocation)

	keyAgreements := populateRawVerificationLegacy(doc.processingMeta.baseURI, doc.ID, doc.KeyAgreement)

	services := populateRawServicesLegacy(doc.Service, doc.ID, doc.processingMeta.baseURI)

	raw := &rawDoc{
		Context: context, ID: doc.ID, PublicKey: publicKey,
		Authentication: auths, AssertionMethod: assertionMethods, CapabilityDelegation: capabilityDelegations,
		CapabilityInvocation: capabilityInvocations, KeyAgreement: keyAgreements,
		Service: services, Created: doc.Created,
		Proof: populateRawProofs(context, doc.ID, doc.processingMeta.baseURI, doc.Proof), Updated: doc.Updated,
	}

	return raw, nil
}

func populateRawVerificationLegacy(baseURI, didID string, verifications []Verification) []interface{} {
	var rawVerifications []interface{}

	for _, v := range verifications {
		keyRef := map[string]string{}

		if v.VerificationMethod.relativeURL {
			keyRef["publicKey"] = makeRelativeDIDURL(v.VerificationMethod.ID, baseURI, didID)
		} else {
			keyRef["publicKey"] = v.VerificationMethod.ID
		}

		keyRef["type"] = v.VerificationMethod.Type

		rawVerifications = append(rawVerifications, keyRef)
	}

	return rawVerifications
}

func populateRawServicesLegacy(services []Service, didID, baseURI string) []map[string]interface{} {
	var rawServices []map[string]interface{}

	for i := range services {
		rawService := make(map[string]interface{})

		for k, v := range services[i].Properties {
			rawService[k] = v
		}

		routingKeys := make([]string, 0)

		for _, v := range services[i].RoutingKeys {
			if services[i].routingKeysRelativeURL[v] {
				routingKeys = append(routingKeys, makeRelativeDIDURL(v, baseURI, didID))
				continue
			}

			routingKeys = append(routingKeys, v)
		}

		recipientKeys := make([]string, 0)

		for _, v := range services[i].RecipientKeys {
			if services[i].recipientKeysRelativeURL[v] {
				recipientKeys = append(recipientKeys, makeRelativeDIDURL(v, baseURI, didID))
				continue
			}

			recipientKeys = append(recipientKeys, v)
		}

		rawService[jsonldID] = services[i].ID
		if services[i].relativeURL {
			rawService[jsonldID] = makeRelativeDIDURL(services[i].ID, baseURI, didID)
		}

		uri, _ := services[i].ServiceEndpoint.URI() //nolint: errcheck

		rawService[jsonldType] = services[i].Type
		rawService[jsonldServicePoint] = uri
		rawService[jsonldRecipientKeys] = recipientKeys
		rawService[jsonldRoutingKeys] = routingKeys

		if services[i].Priority != nil {
			rawService[jsonldPriority] = services[i].Priority
		}

		rawServices = append(rawServices, rawService)
	}

	return rawServices
}
