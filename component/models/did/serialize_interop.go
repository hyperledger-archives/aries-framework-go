//go:build ACAPyInterop
// +build ACAPyInterop

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/btcsuite/btcutil/base58"
)

const doACAPYInterop = true

/*
This file contains interop fixes for DID doc serialization, that break compliance with the DID spec.
As interop partners continue their interop work, these fixes should stop being necessary.
*/

func populateRawVerificationInterop(context, baseURI, didID string, verifications []Verification) ([]interface{}, error) {
	var rawVerifications []interface{}

	for _, v := range verifications {
		if v.Embedded {
			vm, err := populateRawVerificationMethod(context, didID, baseURI, &v.VerificationMethod)
			if err != nil {
				return nil, err
			}

			rawVerifications = append(rawVerifications, vm)
		} else {
			// Interop: emit key reference as {"publicKey":<key reference>} instead of <key reference>
			// see aca-py issue https://github.com/hyperledger/aries-cloudagent-python/issues/1104
			keyRef := map[string]string{}

			if v.VerificationMethod.relativeURL {
				keyRef["publicKey"] = makeRelativeDIDURL(v.VerificationMethod.ID, baseURI, didID)
			} else {
				keyRef["publicKey"] = v.VerificationMethod.ID
			}

			rawVerifications = append(rawVerifications, keyRef)
		}
	}

	return rawVerifications, nil
}

func populateRawServicesInterop(services []Service, didID, baseURI string) []map[string]interface{} {
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

			// Interop: convert did:key to raw base58 key
			// aca-py issue: https://github.com/hyperledger/aries-cloudagent-python/issues/1106
			if strings.HasPrefix(v, "did:key:") {
				key, err := pubKeyFromDIDKey(v)
				if err != nil {
					return nil
				}

				routingKeys = append(routingKeys, base58.Encode(key))
			} else {
				routingKeys = append(routingKeys, v)
			}

		}

		recipientKeys := make([]string, 0)

		for _, v := range services[i].RecipientKeys {
			if services[i].recipientKeysRelativeURL[v] {
				recipientKeys = append(recipientKeys, makeRelativeDIDURL(v, baseURI, didID))
				continue
			}

			// Interop: convert did:key to raw base58 key
			// aca-py issue: https://github.com/hyperledger/aries-cloudagent-python/issues/1106
			if strings.HasPrefix(v, "did:key:") {
				key, err := pubKeyFromDIDKey(v)
				if err != nil {
					return nil
				}

				recipientKeys = append(recipientKeys, base58.Encode(key))
			} else {
				recipientKeys = append(recipientKeys, v)
			}
		}

		rawService[jsonldID] = services[i].ID
		if services[i].relativeURL {
			rawService[jsonldID] = makeRelativeDIDURL(services[i].ID, baseURI, didID)
		}

		uri, _ := services[i].ServiceEndpoint.URI()

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

// fingerprint.PubKeyFromDIDKey and fingerprint.PubKeyFromFingerprint are copied here to avoid an import cycle

func pubKeyFromDIDKey(didKey string) ([]byte, error) {
	id, err := Parse(didKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse did:key [%s]: %w", didKey, err)
	}

	fingerprint := id.MethodSpecificID

	const maxMulticodecBytes = 9

	if len(fingerprint) < 2 || fingerprint[0] != 'z' {
		return nil, errors.New("unknown key encoding")
	}

	mc := base58.Decode(fingerprint[1:]) // skip leading "z"

	_, br := binary.Uvarint(mc)
	if br == 0 {
		return nil, errors.New("unknown key encoding")
	}

	if br > maxMulticodecBytes {
		return nil, errors.New("code exceeds maximum size")
	}

	return mc[br:], nil
}

// SerializeInterop serializes the DID doc, using normal serialization unless the `interop` build flag is set.
// Verifications are serialized to accommodate aca-py issue #1104:
//
//	https://github.com/hyperledger/aries-cloudagent-python/issues/1104
//
// Services are serialized to accommodate aca-py issue #1106:
//
//	https://github.com/hyperledger/aries-cloudagent-python/issues/1106
func (doc *Doc) SerializeInterop() ([]byte, error) {
	context := ContextV1Old

	vm, err := populateRawVM(context, doc.ID, doc.processingMeta.baseURI, doc.VerificationMethod)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of Verification Method failed: %w", err)
	}

	auths, err := populateRawVerificationInterop(context, doc.processingMeta.baseURI, doc.ID, doc.Authentication)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of Authentication failed: %w", err)
	}

	assertionMethods, err := populateRawVerificationInterop(context, doc.processingMeta.baseURI, doc.ID,
		doc.AssertionMethod)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of AssertionMethod failed: %w", err)
	}

	capabilityDelegations, err := populateRawVerificationInterop(context, doc.processingMeta.baseURI, doc.ID,
		doc.CapabilityDelegation)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of CapabilityDelegation failed: %w", err)
	}

	capabilityInvocations, err := populateRawVerificationInterop(context, doc.processingMeta.baseURI, doc.ID,
		doc.CapabilityInvocation)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of CapabilityInvocation failed: %w", err)
	}

	keyAgreements, err := populateRawVerificationInterop(context, doc.processingMeta.baseURI, doc.ID, doc.KeyAgreement)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of KeyAgreement failed: %w", err)
	}

	// TODO: populate services using base58 raw key value instead of did:key
	services := populateRawServicesInterop(doc.Service, doc.ID, doc.processingMeta.baseURI)

	raw := &rawDoc{
		Context: []string{context}, ID: doc.ID, VerificationMethod: vm,
		Authentication: auths, AssertionMethod: assertionMethods, CapabilityDelegation: capabilityDelegations,
		CapabilityInvocation: capabilityInvocations, KeyAgreement: keyAgreements,
		Service: services, Created: doc.Created,
		Proof: populateRawProofs(context, doc.ID, doc.processingMeta.baseURI, doc.Proof), Updated: doc.Updated,
	}

	if doc.processingMeta.baseURI != "" {
		raw.Context = contextWithBase(doc)
	}

	byteDoc, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("JSON marshalling of document failed: %w", err)
	}

	return byteDoc, nil
}
