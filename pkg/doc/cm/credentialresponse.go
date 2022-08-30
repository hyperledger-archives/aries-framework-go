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
	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

const (
	// CredentialResponseAttachmentFormat defines the format type of Credential Response when used as an
	// attachment in the WACI issuance flow.
	// Refer to https://identity.foundation/waci-presentation-exchange/#issuance-2 for more info.
	CredentialResponseAttachmentFormat = "dif/credential-manifest/response@v1.0"
	// CredentialResponsePresentationContext defines the context type of Credential Response when used as part of
	// a presentation attachment in the WACI issuance flow.
	// Refer to https://identity.foundation/waci-presentation-exchange/#issuance-2 for more info.
	CredentialResponsePresentationContext = "https://identity.foundation/credential-manifest/response/v1"
)

// CredentialResponse represents a Credential Response object as defined in
// https://identity.foundation/credential-manifest/#credential-response.
type CredentialResponse struct {
	ID                             string                `json:"id,omitempty"`          // mandatory property
	ManifestID                     string                `json:"manifest_id,omitempty"` // mandatory property
	ApplicationID                  string                `json:"application_id,omitempty"`
	OutputDescriptorMappingObjects []OutputDescriptorMap `json:"descriptor_map,omitempty"` // mandatory property
}

// OutputDescriptorMap represents an Output Descriptor Mapping Object as defined in
// https://identity.foundation/credential-manifest/#credential-response.
// It has the same format as the InputDescriptorMapping object from the presexch package, but has a different meaning
// here.
type OutputDescriptorMap presexch.InputDescriptorMapping

// UnmarshalJSON is the custom unmarshal function gets called automatically when the standard json.Unmarshal is called.
// It also ensures that the given data is a valid CredentialResponse object per the specification.
func (cf *CredentialResponse) UnmarshalJSON(data []byte) error {
	err := cf.standardUnmarshal(data)
	if err != nil {
		return err
	}

	err = cf.validate()
	if err != nil {
		return fmt.Errorf("invalid Credential Response: %w", err)
	}

	return nil
}

// ResolveDescriptorMaps resolves Verifiable Credentials based on this Credential Response's descriptor maps.
// This function looks at each OutputDescriptorMap's path property and checks for that path in the given JSON data,
// which is expected to be from
// the attachment of an Issue Credential message (i.e. issuecredential.IssueCredentialV3.Attachments[i].Data.JSON).
// See the TestCredentialResponse_ResolveDescriptorMap method for examples.
// If a VC is found at that path's location, then it is added to the array of VCs that will be returned by this method.
// Once all OutputDescriptorMaps are done being scanned, the array of VCs will be returned.
func (cf *CredentialResponse) ResolveDescriptorMaps(jsonDataFromAttachment interface{},
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

func (cf *CredentialResponse) standardUnmarshal(data []byte) error {
	// The type alias below is used as to allow the standard json.Unmarshal to be called within a custom unmarshal
	// function without causing infinite recursion. See https://stackoverflow.com/a/43178272 for more information.
	type credentialResponseWithoutMethods *CredentialResponse

	err := json.Unmarshal(data, credentialResponseWithoutMethods(cf))
	if err != nil {
		return err
	}

	return nil
}

func (cf *CredentialResponse) validate() error {
	if cf.ID == "" {
		return errors.New("missing ID")
	}

	if cf.ManifestID == "" {
		return errors.New("missing manifest ID")
	}

	return nil
}

// presentCredentialResponseOpts holds options for the PresentCredentialResponse method.
type presentCredentialResponseOpts struct {
	existingPresentation    verifiable.Presentation
	existingPresentationSet bool
}

// PresentCredentialResponseOpt is an option for the PresentCredentialResponse method.
type PresentCredentialResponseOpt func(opts *presentCredentialResponseOpts)

// WithExistingPresentationForPresentCredentialResponse is an option for the PresentCredentialResponse method
// that allows Credential Response data to be added to an existing Presentation. The existing Presentation
// should not already have Credential Response data.
func WithExistingPresentationForPresentCredentialResponse(
	presentation *verifiable.Presentation) PresentCredentialResponseOpt {
	return func(opts *presentCredentialResponseOpts) {
		opts.existingPresentation = *presentation
		opts.existingPresentationSet = true
	}
}

// PresentCredentialResponse creates a basic Presentation (without proofs) with Credential Response data based
// on credentialManifest. The WithExistingPresentationForPresentCredentialResponse can be used to add the Credential
// Response data to an existing Presentation object instead. Note that any existing proofs are not updated.
// Note also the following assumptions/limitations of this method:
// 1. The format of all credentials is assumed to be ldp_vc.
// 2. The location of the Verifiable Credentials is assumed to be an array at the root under a field called
//    "verifiableCredential".
// 3. The Verifiable Credentials in the presentation is assumed to be in the same order as the Output Descriptors in
//    the Credential Manifest.
func PresentCredentialResponse(credentialManifest *CredentialManifest,
	opts ...PresentCredentialResponseOpt) (*verifiable.Presentation, error) {
	if credentialManifest == nil {
		return nil, errors.New("credential manifest argument cannot be nil")
	}

	appliedOptions := getPresentCredentialResponseOpts(opts)

	var presentation verifiable.Presentation

	if appliedOptions.existingPresentationSet {
		presentation = appliedOptions.existingPresentation
	} else {
		newPresentation, err := verifiable.NewPresentation()
		if err != nil {
			return nil, err
		}

		presentation = *newPresentation
	}

	presentation.Context = append(presentation.Context,
		"https://identity.foundation/credential-manifest/response/v1")
	presentation.Type = append(presentation.Type, "CredentialResponse")

	outputDescriptorMappingObjects := make([]OutputDescriptorMap, len(credentialManifest.OutputDescriptors))

	for i := range credentialManifest.OutputDescriptors {
		outputDescriptorMappingObjects[i].ID = credentialManifest.OutputDescriptors[i].ID
		outputDescriptorMappingObjects[i].Format = "ldp_vc"
		outputDescriptorMappingObjects[i].Path = fmt.Sprintf("$.verifiableCredential[%d]", i)
	}

	response := CredentialResponse{
		ID:                             uuid.New().String(),
		ManifestID:                     credentialManifest.ID,
		OutputDescriptorMappingObjects: outputDescriptorMappingObjects,
	}

	if presentation.CustomFields == nil {
		presentation.CustomFields = make(map[string]interface{})
	}

	presentation.CustomFields["credential_response"] = response

	return &presentation, nil
}

func getPresentCredentialResponseOpts(opts []PresentCredentialResponseOpt) *presentCredentialResponseOpts {
	processedOptions := &presentCredentialResponseOpts{}

	for _, opt := range opts {
		opt(processedOptions)
	}

	return processedOptions
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
