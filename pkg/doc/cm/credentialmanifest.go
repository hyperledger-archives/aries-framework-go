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

	"github.com/PaesslerAG/gval"
	"github.com/PaesslerAG/jsonpath"

	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
)

// CredentialManifestAttachmentFormat defines the format type of Credential Manifest when used as an attachment in the
// WACI issuance flow. Refer to https://identity.foundation/waci-presentation-exchange/#issuance-2 for more info.
const CredentialManifestAttachmentFormat = "dif/credential-manifest/manifest@v1.0"

// CredentialManifest represents a Credential Manifest object as defined in
// https://identity.foundation/credential-manifest/#credential-manifest-2.
type CredentialManifest struct {
	ID                     string                           `json:"id,omitempty"`                 // mandatory property
	Issuer                 Issuer                           `json:"issuer,omitempty"`             // mandatory property
	OutputDescriptors      []*OutputDescriptor              `json:"output_descriptors,omitempty"` // mandatory property
	Format                 *presexch.Format                 `json:"format,omitempty"`
	PresentationDefinition *presexch.PresentationDefinition `json:"presentation_definition,omitempty"`
}

// Issuer represents the issuer object defined in https://identity.foundation/credential-manifest/#general-composition.
type Issuer struct {
	ID     string  `json:"id,omitempty"` // mandatory, must be a valid URI
	Name   string  `json:"name,omitempty"`
	Styles *Styles `json:"styles,omitempty"`
}

// Styles represents an Entity Styles object as defined in
// https://identity.foundation/wallet-rendering/#entity-styles.
type Styles struct {
	Thumbnail  *ImageURIWithAltText `json:"thumbnail,omitempty"`
	Hero       *ImageURIWithAltText `json:"hero,omitempty"`
	Background *Color               `json:"background,omitempty"`
	Text       *Color               `json:"text,omitempty"`
}

// Color represents a single color in RGB hex code format.
type Color struct {
	Color string `json:"color"` // RGB hex code
}

// OutputDescriptor represents an Output Descriptor object as defined in
// https://identity.foundation/credential-manifest/#output-descriptor.
type OutputDescriptor struct {
	ID          string                 `json:"id,omitempty"`     // mandatory property
	Schema      string                 `json:"schema,omitempty"` // mandatory property
	Name        string                 `json:"name,omitempty"`
	Description string                 `json:"description,omitempty"`
	Display     *DataDisplayDescriptor `json:"display,omitempty"`
	Styles      *Styles                `json:"styles,omitempty"`
}

// ImageURIWithAltText represents a URI that points to an image along with the alt text for it.
type ImageURIWithAltText struct {
	URI string `json:"uri,omitempty"` // mandatory property
	Alt string `json:"alt,omitempty"`
}

// DataDisplayDescriptor represents a Data Display Descriptor as defined in
// https://identity.foundation/credential-manifest/wallet-rendering/#data-display.
type DataDisplayDescriptor struct {
	Title       *DisplayMappingObject          `json:"title,omitempty"`
	Subtitle    *DisplayMappingObject          `json:"subtitle,omitempty"`
	Description *DisplayMappingObject          `json:"description,omitempty"`
	Properties  []*LabeledDisplayMappingObject `json:"properties,omitempty"`
}

// DisplayMappingObject represents a Display Mapping Object as defined in
// https://identity.foundation/wallet-rendering/#display-mapping-object
// There are two possibilities here:
// 1. If the text field is used, schema is not required. The text field will contain display
// information about the target Claim.
// 2. If the path field is used, schema is required. Data will be pulled from the target Claim using the path.
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
	Label string `json:"label,omitempty"` // mandatory property
}

// Schema represents Type and (optional) Format information for a DisplayMappingObject that uses the Paths field,
// as defined in https://identity.foundation/wallet-rendering/#using-path.
type Schema struct {
	Type             string `json:"type"`                       // MUST be here
	Format           string `json:"format,omitempty"`           // MAY be here if the Type is "string".
	ContentMediaType string `json:"contentMediaType,omitempty"` // MAY be here if the Type is "string".
	ContentEncoding  string `json:"contentEncoding,omitempty"`  // MAY be here if the Type is "string".
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

// Validate ensures that this CredentialManifest is valid as per the spec.
// Note that this function is automatically called when unmarshalling a []byte into a CredentialManifest.
func (cm *CredentialManifest) Validate() error {
	if cm.ID == "" {
		return errors.New("ID missing")
	}

	err := validateIssuer(cm.Issuer)
	if err != nil {
		return err
	}

	if len(cm.OutputDescriptors) == 0 {
		return errors.New("no output descriptors found")
	}

	err = ValidateOutputDescriptors(cm.OutputDescriptors)
	if err != nil {
		return err
	}

	return nil
}

func validateIssuer(issuer Issuer) error {
	if issuer.ID == "" {
		return errors.New("issuer ID missing")
	}

	if issuer.Styles != nil {
		return validateStyles(*issuer.Styles)
	}

	return nil
}

func validateStyles(styles Styles) error {
	if styles.Thumbnail != nil {
		return validateImage(*styles.Thumbnail)
	}

	if styles.Hero != nil {
		return validateImage(*styles.Hero)
	}

	return nil
}

func validateImage(image ImageURIWithAltText) error {
	if image.URI == "" {
		return errors.New("uri missing for image")
	}

	return nil
}

// ValidateOutputDescriptors checks the given slice of OutputDescriptors to ensure that they are valid (per the spec)
// when placed together within a single Credential Manifest.
// To pass validation, the following two conditions must be satisfied:
// 1. Each OutputDescriptor must have a unique ID.
// 2. Each OutputDescriptor must also have valid contents. See the validateOutputDescriptorDisplay function for details.
func ValidateOutputDescriptors(descriptors []*OutputDescriptor) error {
	allOutputDescriptorIDs := make(map[string]struct{})

	for i := range descriptors {
		if descriptors[i].ID == "" {
			return fmt.Errorf("missing ID for output descriptor at index %d", i)
		}

		_, foundDuplicateID := allOutputDescriptorIDs[descriptors[i].ID]
		if foundDuplicateID {
			return fmt.Errorf("the ID %s appears in multiple output descriptors", descriptors[i].ID)
		}

		allOutputDescriptorIDs[descriptors[i].ID] = struct{}{}

		if descriptors[i].Schema == "" {
			return fmt.Errorf("missing schema for output descriptor at index %d", i)
		}

		err := validateOutputDescriptorDisplay(descriptors[i], i)
		if err != nil {
			return err
		}

		if descriptors[i].Styles != nil {
			err = validateStyles(*descriptors[i].Styles)
			if err != nil {
				return fmt.Errorf("%w at index %d", err, i)
			}
		}
	}

	return nil
}

func (cm *CredentialManifest) hasFormat() bool {
	if cm.Format == nil {
		return false
	}

	return hasAnyAlgorithmsOrProofTypes(*cm.Format)
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

func validateOutputDescriptorDisplay(outputDescriptor *OutputDescriptor, outputDescriptorIndex int) error {
	if outputDescriptor.Display == nil {
		return nil
	}

	if outputDescriptor.Display.Title != nil {
		err := validateDisplayMappingObject(outputDescriptor.Display.Title)
		if err != nil {
			return fmt.Errorf("display title for output descriptor at index %d is invalid: %w",
				outputDescriptorIndex, err)
		}
	}

	if outputDescriptor.Display.Subtitle != nil {
		err := validateDisplayMappingObject(outputDescriptor.Display.Subtitle)
		if err != nil {
			return fmt.Errorf("display subtitle for output descriptor at index %d is invalid: %w",
				outputDescriptorIndex, err)
		}
	}

	if outputDescriptor.Display.Description != nil {
		err := validateDisplayMappingObject(outputDescriptor.Display.Description)
		if err != nil {
			return fmt.Errorf("display description for output descriptor at index %d is invalid: %w",
				outputDescriptorIndex, err)
		}
	}

	for i := range outputDescriptor.Display.Properties {
		err := validateDisplayMappingObject(&outputDescriptor.Display.Properties[i].DisplayMappingObject)
		if err != nil {
			return fmt.Errorf("display property at index %d for output descriptor at index %d is invalid: %w",
				outputDescriptorIndex, i, err)
		}
	}

	return nil
}

func validateDisplayMappingObject(displayMappingObject *DisplayMappingObject) error {
	if len(displayMappingObject.Paths) > 0 {
		for i, path := range displayMappingObject.Paths {
			_, err := jsonpath.New(path) // Just using this to ValidateOutputDescriptors the JSONPath.
			if err != nil {
				return fmt.Errorf(`path "%s" at index %d is not a valid JSONPath: %w`, path, i, err)
			}
		}

		return validateSchema(displayMappingObject)
	} else if displayMappingObject.Text == "" {
		return fmt.Errorf(`display mapping object must contain either a paths or a text property`)
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
