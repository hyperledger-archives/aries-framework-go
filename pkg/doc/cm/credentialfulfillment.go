/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cm

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/PaesslerAG/jsonpath"

	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

// CredentialFulfillment represents a Credential Fulfillment object as defined in
// https://identity.foundation/credential-manifest/#credential-fulfillment.
type CredentialFulfillment struct {
	ID                             string                `json:"id,omitempty"`
	ManifestID                     string                `json:"manifest_id,omitempty"`
	OutputDescriptorMappingObjects []OutputDescriptorMap `json:"descriptor_map,omitempty"`
}

// OutputDescriptorMap represents an Output Descriptor Mapping Object as defined in
// https://identity.foundation/credential-manifest/#credential-fulfillment.
// It has the same format as the InputDescriptorMapping object from the presexch package, but has a different meaning
// here.
type OutputDescriptorMap presexch.InputDescriptorMapping

// UnmarshalJSON is the custom unmarshal function gets called automatically when the standard json.Unmarshal is called.
// It also ensures that the given data is a valid CredentialFulfillment object per the specification.
func (cf *CredentialFulfillment) UnmarshalJSON(data []byte) error {
	err := cf.standardUnmarshal(data)
	if err != nil {
		return err
	}

	err = cf.validate()
	if err != nil {
		return fmt.Errorf("invalid Credential Fulfillment: %w", err)
	}

	return nil
}

// ResolveDescriptorMaps resolves Verifiable Credentials based on this Credential Fulfillment's descriptor maps.
// This function looks at each OutputDescriptorMap's path property and checks for that path in the given JSON data,
// which is expected to be from
// the attachment of an Issue Credential message (i.e. issuecredential.IssueCredentialV3.Attachments[i].Data.JSON).
// See the TestCredentialFulfillment_ResolveDescriptorMap method for examples.
// If a VC is found at that path's location, then it is added to the array of VCs that will be returned by this method.
// Once all OutputDescriptorMaps are done being scanned, the array of VCs will be returned.
func (cf *CredentialFulfillment) ResolveDescriptorMaps(jsonDataFromAttachment interface{},
	parseCredentialOpts ...verifiable.CredentialOpt) ([]verifiable.Credential, error) {
	// The jsonpath library needs a map[string]interface{}.
	// The issuecredential.IssueCredentialV3.Attachments[i].Data.JSON object (expected to be passed in here) is of type
	// interface{}, but the Go unmarshaler should have set it to a map[string]interface{}.
	jsonDataFromAttachmentAsMap, ok := jsonDataFromAttachment.(map[string]interface{})
	if !ok {
		return nil, errors.New("the given JSON data could not be asserted as a map[string]interface{}")
	}

	verifiableCredentials := make([]verifiable.Credential, len(cf.OutputDescriptorMappingObjects))

	for i, descriptorMap := range cf.OutputDescriptorMappingObjects {
		vc, err := resolveDescriptorMap(descriptorMap, jsonDataFromAttachmentAsMap, parseCredentialOpts)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve descriptor map at index %d: %w", i, err)
		}

		verifiableCredentials[i] = *vc
	}

	return verifiableCredentials, nil
}

func (cf *CredentialFulfillment) standardUnmarshal(data []byte) error {
	// The type alias below is used as to allow the standard json.Unmarshal to be called within a custom unmarshal
	// function without causing infinite recursion. See https://stackoverflow.com/a/43178272 for more information.
	type credentialFulfillmentWithoutMethods *CredentialFulfillment

	err := json.Unmarshal(data, credentialFulfillmentWithoutMethods(cf))
	if err != nil {
		return err
	}

	return nil
}

func (cf *CredentialFulfillment) validate() error {
	if cf.ID == "" {
		return errors.New("missing ID")
	}

	if cf.ManifestID == "" {
		return errors.New("missing manifest ID")
	}

	return nil
}

func resolveDescriptorMap(descriptorMap OutputDescriptorMap, jsonDataFromAttachmentAsMap map[string]interface{},
	parseCredentialOpts []verifiable.CredentialOpt) (*verifiable.Credential, error) {
	vcRaw, err := jsonpath.Get(descriptorMap.Path, jsonDataFromAttachmentAsMap)
	if err != nil {
		return nil, err
	}

	vcBytes, err := json.Marshal(vcRaw)
	if err != nil {
		return nil, err
	}

	vc, err := verifiable.ParseCredential(vcBytes, parseCredentialOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}

	return vc, nil
}
