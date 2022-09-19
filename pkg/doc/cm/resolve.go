/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cm

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/PaesslerAG/gval"
	"github.com/PaesslerAG/jsonpath"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

// ResolvedProperty contains resolved result for each resolved property.
type ResolvedProperty struct {
	Schema Schema      `json:"schema"`
	Label  string      `json:"label"`
	Value  interface{} `json:"value"`
}

// ResolvedDescriptor typically represents results of resolving manifests by credential response.
// Typically represents a DataDisplayDescriptor that's had its various "template" fields resolved
// into concrete values based on a Verifiable Credential.
type ResolvedDescriptor struct {
	DescriptorID string              `json:"descriptor_id"`
	Title        string              `json:"title,omitempty"`
	Subtitle     string              `json:"subtitle,omitempty"`
	Description  string              `json:"description,omitempty"`
	Styles       *Styles             `json:"styles,omitempty"`
	Properties   []*ResolvedProperty `json:"properties,omitempty"`
}

// resolveCredOpts contains options to provide credential to resolve manifest.
type resolveCredOpts struct {
	credential    *verifiable.Credential
	rawCredential json.RawMessage
}

// CredentialToResolveOption is an option to provide credential to resolve manifest.
type CredentialToResolveOption func(opts *resolveCredOpts)

// CredentialToResolve is an option to provide verifiable credential instance to resolve.
func CredentialToResolve(credential *verifiable.Credential) CredentialToResolveOption {
	return func(opts *resolveCredOpts) {
		opts.credential = credential
	}
}

// RawCredentialToResolve is an option to provide raw JSON bytes of verifiable credential to resolve.
func RawCredentialToResolve(raw json.RawMessage) CredentialToResolveOption {
	return func(opts *resolveCredOpts) {
		opts.rawCredential = raw
	}
}

// ResolveResponse resolves given credential response and returns results.
// Currently supports only 'ldp_vc' format of response credentials.
func (cm *CredentialManifest) ResolveResponse(response *verifiable.Presentation) ([]*ResolvedDescriptor, error) { //nolint:funlen,gocyclo,lll
	var results []*ResolvedDescriptor

	credentialResponseMap, ok := lookUpMap(response.CustomFields, "credential_response")
	if !ok {
		return nil, errors.New("invalid credential response")
	}

	if manifestID, k := credentialResponseMap["manifest_id"]; !k || cm.ID != manifestID {
		return nil, errors.New("credential response not matching")
	}

	descriptorMaps, ok := lookUpArray(credentialResponseMap, "descriptor_map")
	if !ok {
		return nil, errors.New("invalid descriptor map")
	}

	if len(descriptorMaps) == 0 {
		return results, nil
	}

	outputDescriptors := mapDescriptors(cm)

	builder := gval.Full(jsonpath.PlaceholderExtension())

	vpBits, err := response.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal vp: %w", err)
	}

	typelessVP := interface{}(nil)

	err = json.Unmarshal(vpBits, &typelessVP)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal vp: %w", err)
	}

	for _, descriptorMap := range descriptorMaps {
		descriptor, ok := descriptorMap.(map[string]interface{})
		if !ok {
			return nil, errors.New("invalid descriptor format")
		}

		id, ok := lookUpString(descriptor, "id")
		if !ok {
			return nil, errors.New("invalid descriptor ID")
		}

		outputDescriptor, ok := outputDescriptors[id]
		if !ok {
			return nil, errors.New("unable to find matching output descriptor from manifest")
		}

		if format, k := lookUpString(descriptor, "format"); !k || format != "ldp_vc" {
			// currently, only ldp_vc format is supported
			continue
		}

		path, ok := lookUpString(descriptor, "path")
		if !ok {
			return nil, fmt.Errorf("invalid credential path in descriptor '%s'", id)
		}

		credential, err := selectVCByPath(builder, typelessVP, path)
		if err != nil {
			return nil, fmt.Errorf("failed to select vc from descriptor: %w", err)
		}

		resolved, err := resolveOutputDescriptor(outputDescriptor, credential)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve credential by descriptor: %w", err)
		}

		results = append(results, resolved)
	}

	return results, nil
}

// ResolveCredential resolves given credential and returns results.
func (cm *CredentialManifest) ResolveCredential(descriptorID string, credential CredentialToResolveOption) (*ResolvedDescriptor, error) { //nolint:lll
	opts := &resolveCredOpts{}

	if credential != nil {
		credential(opts)
	}

	var err error

	var vcmap map[string]interface{}

	switch {
	case opts.credential != nil:
		opts.rawCredential, err = opts.credential.MarshalJSON()
		if err != nil {
			return nil, err
		}

		fallthrough
	case len(opts.rawCredential) > 0:
		if opts.rawCredential[0] != '{' {
			// try to parse as jwt vc
			var jwtCred []byte

			jwtCred, err = verifiable.JWTVCToJSON(opts.rawCredential)
			if err == nil {
				opts.rawCredential = jwtCred
			}
		}

		err = json.Unmarshal(opts.rawCredential, &vcmap)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("credential to resolve is not provided")
	}

	// find matching descriptor and resolve.
	for _, descriptor := range cm.OutputDescriptors {
		if descriptor.ID == descriptorID {
			return resolveOutputDescriptor(descriptor, vcmap)
		}
	}

	return nil, errors.New("unable to find matching descriptor")
}

func resolveOutputDescriptor(outputDescriptor *OutputDescriptor,
	vc map[string]interface{}) (*ResolvedDescriptor, error) {
	var resolved ResolvedDescriptor

	staticDisplayMappings, err := resolveStaticDisplayMappingObjects(outputDescriptor, vc)
	if err != nil {
		return nil, err
	}

	resolved.DescriptorID = outputDescriptor.ID
	resolved.Title = staticDisplayMappings.title
	resolved.Subtitle = staticDisplayMappings.subtitle
	resolved.Description = staticDisplayMappings.description
	resolved.Styles = outputDescriptor.Styles

	resolved.Properties, err =
		resolveDescriptorProperties(outputDescriptor.Display.Properties, vc)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve properties: %w", err)
	}

	return &resolved, nil
}

func resolveStaticDisplayMappingObjects(outputDescriptor *OutputDescriptor,
	vc map[string]interface{}) (staticDisplayMappingObjects, error) {
	title, err := resolveDisplayMappingObject(outputDescriptor.Display.Title, vc)
	if err != nil {
		return staticDisplayMappingObjects{}, fmt.Errorf("failed to resolve title display mapping object: %w", err)
	}

	subtitle, err := resolveDisplayMappingObject(outputDescriptor.Display.Subtitle, vc)
	if err != nil {
		return staticDisplayMappingObjects{}, fmt.Errorf("failed to resolve subtitle display mapping object: %w", err)
	}

	description, err := resolveDisplayMappingObject(outputDescriptor.Display.Description, vc)
	if err != nil {
		return staticDisplayMappingObjects{}, fmt.Errorf("failed to resolve description display mapping object: %w", err)
	}

	return staticDisplayMappingObjects{
		title:       fmt.Sprintf("%v", title),
		subtitle:    fmt.Sprintf("%v", subtitle),
		description: fmt.Sprintf("%v", description),
	}, nil
}

func resolveDescriptorProperties(properties []*LabeledDisplayMappingObject,
	vc map[string]interface{}) ([]*ResolvedProperty, error) {
	var resolvedProperties []*ResolvedProperty

	for i := range properties {
		var err error

		value, err := resolveDisplayMappingObject(&properties[i].DisplayMappingObject, vc)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve the display mapping object for the property with label '%s': %w", properties[i].Label, err) // nolint:lll
		}

		resolvedProperties = append(resolvedProperties, &ResolvedProperty{
			Label:  properties[i].Label,
			Schema: properties[i].Schema,
			Value:  value,
		})
	}

	return resolvedProperties, nil
}

func resolveDisplayMappingObject(displayMappingObject *DisplayMappingObject,
	vc map[string]interface{}) (interface{}, error) {
	if len(displayMappingObject.Paths) > 0 {
		resolvedValue, err := resolveJSONPathsUsingVC(displayMappingObject.Paths, displayMappingObject.Fallback, vc)
		return resolvedValue, err
	}

	return displayMappingObject.Text, nil
}

func resolveJSONPathsUsingVC(paths []string, fallback string, vc map[string]interface{}) (interface{}, error) {
	for _, path := range paths {
		resolvedValue, err := jsonpath.Get(path, vc)
		if err != nil {
			if strings.HasPrefix(err.Error(), "unknown key") {
				continue
			}

			return nil, err
		}

		return resolvedValue, nil
	}

	return fallback, nil
}
