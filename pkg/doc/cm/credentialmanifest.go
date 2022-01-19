/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package cm contains methods that are useful for parsing and validating the objects defined in the Credential Manifest
// spec: https://identity.foundation/credential-manifest.
package cm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/PaesslerAG/gval"
	"github.com/PaesslerAG/jsonpath"

	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

// CredentialManifest represents a Credential Manifest object as defined in
// https://identity.foundation/credential-manifest/#credential-manifest-2.
type CredentialManifest struct {
	ID                     string                           `json:"id,omitempty"`
	Version                string                           `json:"version,omitempty"`
	Issuer                 Issuer                           `json:"issuer,omitempty"`
	OutputDescriptors      []*OutputDescriptor              `json:"output_descriptors,omitempty"`
	Format                 presexch.Format                  `json:"format,omitempty"`
	PresentationDefinition *presexch.PresentationDefinition `json:"presentation_definition,omitempty"`
}

// Issuer represents the issuer object defined in https://identity.foundation/credential-manifest/#general-composition.
type Issuer struct {
	ID     string `json:"id,omitempty"` // Must be a valid URI
	Name   string `json:"name,omitempty"`
	Styles Styles `json:"styles,omitempty"`
}

// Styles represents an Entity Styles object as defined in
// https://identity.foundation/credential-manifest/wallet-rendering/#entity-styles.
type Styles struct {
	Thumbnail  ImageURIWithAltText `json:"thumbnail,omitempty"`
	Hero       ImageURIWithAltText `json:"hero,omitempty"`
	Background Color               `json:"background,omitempty"`
	Text       Color               `json:"text,omitempty"`
}

// Color represents a single color in RGB hex code format.
type Color struct {
	Color string `json:"color"` // RGB hex code
}

// OutputDescriptor represents an Output Descriptor object as defined in
// https://identity.foundation/credential-manifest/#output-descriptor.
type OutputDescriptor struct {
	ID          string                `json:"id,omitempty"`
	Schema      string                `json:"schema,omitempty"`
	Name        string                `json:"name,omitempty"`
	Description string                `json:"description,omitempty"`
	Display     DataDisplayDescriptor `json:"display,omitempty"`
	Styles      Styles                `json:"styles,omitempty"`
}

// ImageURIWithAltText represents a URI that points to an image along with the alt text for it.
type ImageURIWithAltText struct {
	URI string `json:"uri,omitempty"`
	Alt string `json:"alt,omitempty"`
}

// DataDisplayDescriptor represents a Data Display Descriptor as defined in
// https://identity.foundation/credential-manifest/wallet-rendering/#data-display.
type DataDisplayDescriptor struct {
	Title       DisplayMappingObject          `json:"title,omitempty"`
	Subtitle    DisplayMappingObject          `json:"subtitle,omitempty"`
	Description DisplayMappingObject          `json:"description,omitempty"`
	Properties  []LabeledDisplayMappingObject `json:"properties,omitempty"`
}

// DisplayMappingObject represents a Display Mapping Object as defined in
// https://identity.foundation/credential-manifest/wallet-rendering/#display-mapping-object
// There are two possibilities here:
// If the text field is used, then schema is not needed.
// If the path field is used, then schema is required.
// TODO (#3045) Support for JSONPath bracket notation.
type DisplayMappingObject struct {
	Text     string   `json:"text,omitempty"`
	Paths    []string `json:"path,omitempty"`
	Schema   Schema   `json:"schema,omitempty"`
	Fallback string   `json:"fallback,omitempty"`
}

// LabeledDisplayMappingObject is a DisplayMappingObject with an additional Label field.
// They are used for the dynamic Properties array in a DataDisplayDescriptor.
type LabeledDisplayMappingObject struct {
	DisplayMappingObject
	Label string `json:"label,omitempty"`
}

// Schema represents Type and (optional) Format information for a DisplayMappingObject that uses the Paths field,
// as defined in https://identity.foundation/credential-manifest/wallet-rendering/#using-path.
type Schema struct {
	Type   string `json:"type,omitempty"`   // MUST be here
	Format string `json:"format,omitempty"` // MAY be here if the Type is "string".
}

// ResolvedDataDisplayDescriptor represents a DataDisplayDescriptor that's had its various "template" fields resolved
// into concrete values based on a Verifiable Credential.
// Technically Title, Subtitle and Description could be a non-string type, as the spec doesn't enforce the type of
// those Display Mapping Objects, but it seems unreasonable to expect anything other than a string.
// The ResolveOutputDescriptors method will return an error if any of the resolved values of those three fields are
// not strings.
type ResolvedDataDisplayDescriptor struct {
	Title       string
	Subtitle    string
	Description string
	Properties  map[string]interface{}
}

// ResolvedDescriptor typically represents results of resolving manifests by credential fulfillment.
type ResolvedDescriptor struct {
	DescriptorID string
	Resolved     *ResolvedDataDisplayDescriptor
}

type staticDisplayMappingObjects struct {
	title       string
	subtitle    string
	description string
}

// UnmarshalJSON is the custom unmarshal function gets called automatically when the standard json.Unmarshal is called.
// It also ensures that the given data is a valid CredentialManifest object per the specification.
func (cm *CredentialManifest) UnmarshalJSON(data []byte) error {
	err := cm.standardUnmarshal(data)
	if err != nil {
		return err
	}

	err = cm.Validate()
	if err != nil {
		return fmt.Errorf("invalid credential manifest: %w", err)
	}

	return nil
}

// Validate ensures that this CredentialManifest is valid per the spec.
// Note that this function is automatically called when unmarshalling a []byte into a CredentialManifest.
func (cm *CredentialManifest) Validate() error {
	if cm.Issuer.ID == "" {
		return errors.New("issuer ID missing")
	}

	if len(cm.OutputDescriptors) == 0 {
		return errors.New("no output descriptors found")
	}

	err := Validate(cm.OutputDescriptors)
	if err != nil {
		return err
	}

	return nil
}

// ResolveFulfillment resolves given credential fulfillment and returns results.
// Currently supporting only 'ldp_vc' format of fulfillment credentials.
func (cm *CredentialManifest) ResolveFulfillment(fulfillment *verifiable.Presentation) ([]*ResolvedDescriptor, error) { //nolint:funlen,gocyclo,lll
	var results []*ResolvedDescriptor

	credentialFulfillmentMap, ok := lookupMap(fulfillment.CustomFields, "credential_fulfillment")
	if !ok {
		return nil, errors.New("invalid credential fulfillment")
	}

	if manifestID, k := credentialFulfillmentMap["manifest_id"]; !k || cm.ID != manifestID {
		return nil, errors.New("credential fulfillment not matching")
	}

	descriptorMaps, ok := lookupArray(credentialFulfillmentMap, "descriptor_map")
	if !ok {
		return nil, errors.New("invalid descriptor map")
	}

	if len(descriptorMaps) == 0 {
		return results, nil
	}

	outputDescriptors := mapDescriptors(cm)

	builder := gval.Full(jsonpath.PlaceholderExtension())

	vpBits, err := fulfillment.MarshalJSON()
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

		id, ok := lookupString(descriptor, "id")
		if !ok {
			return nil, errors.New("invalid descriptor ID")
		}

		outputDescriptor, ok := outputDescriptors[id]
		if !ok {
			return nil, errors.New("unable to find matching output descriptor from manifest")
		}

		if format, k := lookupString(descriptor, "format"); !k || format != "ldp_vc" {
			// currently, only ldp_vc format is supported
			continue
		}

		path, ok := lookupString(descriptor, "path")
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

		results = append(results, &ResolvedDescriptor{
			DescriptorID: id,
			Resolved:     resolved,
		})
	}

	return results, nil
}

// ResolveCredential resolved given credential and returns results.
func (cm *CredentialManifest) ResolveCredential(descriptorID string, credential *verifiable.Credential) (*ResolvedDataDisplayDescriptor, error) { //nolint:lll
	credBytes, err := credential.MarshalJSON()
	if err != nil {
		return nil, err
	}

	var vcmap map[string]interface{}

	err = json.Unmarshal(credBytes, &vcmap)
	if err != nil {
		return nil, err
	}

	// find matching descriptor and resolve.
	for _, descriptor := range cm.OutputDescriptors {
		if descriptor.ID == descriptorID {
			return resolveOutputDescriptor(descriptor, vcmap)
		}
	}

	return nil, errors.New("unable to find matching descriptor")
}

// Validate checks the given slice of OutputDescriptors to ensure that they are valid (per the spec) when placed
// together within a single Credential Manifest. To pass validation, the following two conditions must be satisfied:
// 1. Each OutputDescriptor must have a unique ID.
// 2. Each OutputDescriptor must also have valid contents. See the validateOutputDescriptor function for details.
func Validate(outputDescriptors []*OutputDescriptor) error {
	allOutputDescriptorIDs := make(map[string]struct{})

	for i := range outputDescriptors {
		if outputDescriptors[i].ID == "" {
			return fmt.Errorf("missing ID for output descriptor at index %d", i)
		}

		_, foundDuplicateID := allOutputDescriptorIDs[outputDescriptors[i].ID]
		if foundDuplicateID {
			return fmt.Errorf("the ID %s appears in multiple output descriptors", outputDescriptors[i].ID)
		}

		allOutputDescriptorIDs[outputDescriptors[i].ID] = struct{}{}

		if outputDescriptors[i].Schema == "" {
			return fmt.Errorf("missing schema for output descriptor at index %d", i)
		}

		err := validateOutputDescriptor(outputDescriptors[i], i)
		if err != nil {
			return err
		}
	}

	return nil
}

func (cm *CredentialManifest) hasFormat() bool {
	return hasAnyAlgorithmsOrProofTypes(cm.Format)
}

func resolveOutputDescriptor(outputDescriptor *OutputDescriptor,
	vc map[string]interface{}) (*ResolvedDataDisplayDescriptor, error) {
	var resolvedDataDisplayDescriptor ResolvedDataDisplayDescriptor

	staticDisplayMappings, err := resolveStaticDisplayMappingObjects(outputDescriptor, vc)
	if err != nil {
		return nil, err
	}

	resolvedDataDisplayDescriptor.Title = staticDisplayMappings.title
	resolvedDataDisplayDescriptor.Subtitle = staticDisplayMappings.subtitle
	resolvedDataDisplayDescriptor.Description = staticDisplayMappings.description

	resolvedDataDisplayDescriptor.Properties, err =
		resolveDynamicDisplayMappingObjects(outputDescriptor.Display.Properties, vc)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve properties: %w", err)
	}

	return &resolvedDataDisplayDescriptor, nil
}

func resolveStaticDisplayMappingObjects(outputDescriptor *OutputDescriptor,
	vc map[string]interface{}) (staticDisplayMappingObjects, error) {
	title, err := resolveDisplayMappingObject(&outputDescriptor.Display.Title, vc)
	if err != nil {
		return staticDisplayMappingObjects{}, fmt.Errorf("failed to resolve title display mapping object: %w", err)
	}

	subtitle, err := resolveDisplayMappingObject(&outputDescriptor.Display.Subtitle, vc)
	if err != nil {
		return staticDisplayMappingObjects{}, fmt.Errorf("failed to resolve subtitle display mapping object: %w", err)
	}

	description, err := resolveDisplayMappingObject(&outputDescriptor.Display.Description, vc)
	if err != nil {
		return staticDisplayMappingObjects{}, fmt.Errorf("failed to resolve description display mapping object: %w", err)
	}

	return staticDisplayMappingObjects{
		title:       fmt.Sprintf("%v", title),
		subtitle:    fmt.Sprintf("%v", subtitle),
		description: fmt.Sprintf("%v", description),
	}, nil
}

func resolveDynamicDisplayMappingObjects(properties []LabeledDisplayMappingObject,
	vc map[string]interface{}) (map[string]interface{}, error) {
	resolvedProperties := make(map[string]interface{}, len(properties))

	for i, property := range properties {
		var err error

		resolvedProperties[property.Label], err = resolveDisplayMappingObject(&property.DisplayMappingObject, vc)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve the display mapping object for the property at index %d: %w", i, err) // nolint:lll
		}
	}

	return resolvedProperties, nil
}

// TODO should resolve data by schema.
func resolveDisplayMappingObject(displayMappingObject *DisplayMappingObject,
	vc map[string]interface{}) (interface{}, error) {
	if len(displayMappingObject.Paths) > 0 {
		resolvedValue, err := resolveJSONPathsUsingVC(displayMappingObject.Paths, displayMappingObject.Fallback, vc)
		if err != nil {
			return "", err
		}

		return resolvedValue, nil
	}

	return displayMappingObject.Fallback, nil
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

func (cm *CredentialManifest) standardUnmarshal(data []byte) error {
	// The type alias below is used as to allow the standard json.Unmarshal to be called within a custom unmarshal
	// function without causing infinite recursion. See https://stackoverflow.com/a/43178272 for more information.
	type credentialManifestAliasWithoutMethods *CredentialManifest

	err := json.Unmarshal(data, credentialManifestAliasWithoutMethods(cm))
	if err != nil {
		return err
	}

	return nil
}

func validateOutputDescriptor(outputDescriptor *OutputDescriptor, outputDescriptorIndex int) error {
	err := validateDisplayMappingObject(&outputDescriptor.Display.Title)
	if err != nil {
		return fmt.Errorf("display title for output descriptor at index %d is invalid: %w",
			outputDescriptorIndex, err)
	}

	err = validateDisplayMappingObject(&outputDescriptor.Display.Subtitle)
	if err != nil {
		return fmt.Errorf("display subtitle for output descriptor at index %d is invalid: %w",
			outputDescriptorIndex, err)
	}

	err = validateDisplayMappingObject(&outputDescriptor.Display.Description)
	if err != nil {
		return fmt.Errorf("display description for output descriptor at index %d is invalid: %w",
			outputDescriptorIndex, err)
	}

	for propertyIndex, property := range outputDescriptor.Display.Properties {
		err := validateDisplayMappingObject(&property.DisplayMappingObject)
		if err != nil {
			return fmt.Errorf("display property at index %d for output descriptor at index %d is invalid: %w",
				outputDescriptorIndex, propertyIndex, err)
		}
	}

	return nil
}

func validateDisplayMappingObject(displayMappingObject *DisplayMappingObject) error {
	if len(displayMappingObject.Paths) > 0 {
		for i, path := range displayMappingObject.Paths {
			_, err := jsonpath.New(path) // Just using this to Validate the JSONPath.
			if err != nil {
				return fmt.Errorf(`path "%s" at index %d is not a valid JSONPath: %w`, path, i, err)
			}
		}

		return validateSchema(displayMappingObject)
	}

	return nil
}

func validateSchema(displayMappingObject *DisplayMappingObject) error {
	schemaType := displayMappingObject.Schema.Type

	if schemaType == "string" {
		if schemaFormatIsValid(displayMappingObject.Schema.Format) {
			return nil
		}

		return fmt.Errorf("%s is not a valid string schema format", displayMappingObject.Schema.Format)
	}

	if schemaType == "boolean" || schemaType == "number" || schemaType == "integer" {
		return nil
	}

	return fmt.Errorf("%s is not a valid schema type", schemaType)
}

// Implemented per http://localhost:3000/wallet-rendering/#type-specific-configuration.
// This is only checked when the schema type is set to "string". In that case, format is optional (hence the "" check
// below).
func schemaFormatIsValid(format string) bool {
	validFormats := []string{
		"", "date-time", "time", "date", "email", "idn-email", "hostname", "idn-hostname",
		"ipv4", "ipv6", "uri", "uri-reference", "iri", "iri-reference",
	}

	var isValidFormat bool

	for _, validFormat := range validFormats {
		if format == validFormat {
			isValidFormat = true
			break
		}
	}

	return isValidFormat
}

func lookupString(model map[string]interface{}, key string) (string, bool) {
	raw, ok := model[key]
	if !ok {
		return "", false
	}

	val, ok := raw.(string)

	return val, ok
}

func lookupMap(model map[string]interface{}, key string) (map[string]interface{}, bool) {
	raw, ok := model[key]
	if !ok {
		return nil, false
	}

	val, ok := raw.(map[string]interface{})

	return val, ok
}

func lookupArray(model map[string]interface{}, key string) ([]interface{}, bool) {
	raw, ok := model[key]
	if !ok {
		return nil, false
	}

	val, ok := raw.([]interface{})

	return val, ok
}

func mapDescriptors(manifest *CredentialManifest) map[string]*OutputDescriptor {
	result := make(map[string]*OutputDescriptor, len(manifest.OutputDescriptors))

	for _, outputDescr := range manifest.OutputDescriptors {
		result[outputDescr.ID] = outputDescr
	}

	return result
}

func selectVCByPath(builder gval.Language, vp interface{}, jsonPath string) (map[string]interface{}, error) {
	path, err := builder.NewEvaluable(jsonPath)
	if err != nil {
		return nil, fmt.Errorf("failed to build new json path evaluator: %w", err)
	}

	cred, err := path(context.TODO(), vp)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate json path [%s]: %w", jsonPath, err)
	}

	if credMap, ok := cred.(map[string]interface{}); ok {
		return credMap, nil
	}

	return nil, fmt.Errorf("unexpected credential evaluation result")
}
