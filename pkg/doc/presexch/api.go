/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presexch

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/PaesslerAG/gval"
	"github.com/PaesslerAG/jsonpath"
	"github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

const (
	// PresentationSubmissionJSONLDContext is the JSONLD context of presentation submissions.
	PresentationSubmissionJSONLDContext = "https://identity.foundation/presentation-exchange/submission/v1"
	// PresentationSubmissionJSONLDType is the JSONLD type of presentation submissions.
	PresentationSubmissionJSONLDType = "PresentationSubmission"

	submissionProperty    = "presentation_submission"
	descriptorMapProperty = "descriptor_map"
)

// SubmissionRequirement describes input that must be submitted via a Presentation Submission
// to satisfy Verifier demands.
type SubmissionRequirement struct {
	Name       string                  `json:"name,omitempty"`
	Purpose    string                  `json:"purpose,omitempty"`
	Rule       string                  `json:"rule,omitempty"`
	Count      int                     `json:"count,omitempty"`
	Min        int                     `json:"min,omitempty"`
	Max        int                     `json:"max,omitempty"`
	From       string                  `json:"from,omitempty"`
	FromNested []SubmissionRequirement `json:"from_nested,omitempty"`
}

// Field describes Constraint`s Fields field.
type Field struct {
	Path    []string `json:"path,omitempty"`
	ID      string   `json:"id,omitempty"`
	Purpose string   `json:"purpose,omitempty"`
	// TODO: define all fields for Filter if it possible
	Filter    map[string]interface{} `json:"filter,omitempty"`
	Predicate string                 `json:"predicate,omitempty"`
}

// Holder describes Constraint`s IsHolder field.
type Holder struct {
	FieldID   []string `json:"field_id,omitempty"`
	Directive string   `json:"directive,omitempty"`
}

// Constraint describes InputDescriptor`s Constraints field.
type Constraint struct {
	LimitDisclosure bool     `json:"limit_disclosure,omitempty"`
	SubjectIsIssuer string   `json:"subject_is_issuer,omitempty"`
	IsHolder        []Holder `json:"is_holder,omitempty"`
	Fields          []Field  `json:"fields,omitempty"`
}

// InputDescriptor input descriptors.
type InputDescriptor struct {
	ID      string   `json:"id,omitempty"`
	Group   []string `json:"group,omitempty"`
	Name    string   `json:"name,omitempty"`
	Purpose string   `json:"purpose,omitempty"`
	// TODO: need to figure out what metadata is. According to
	// https://identity.foundation/presentation-exchange/#json-schema-2 metadata is "metadata": { "type": "string" },
	// but spec says "value MUST be an object with metadata properties" which means {} != ""
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Schema      *Schema                `json:"schema,omitempty"`
	Constraints Constraint             `json:"constraints,omitempty"`
}

// Schema input descriptor schema.
type Schema struct {
	URI      string `json:"uri,omitempty"`
	Required bool   `json:"required,omitempty"`
}

// PresentationDefinition presentation definitions (https://identity.foundation/presentation-exchange/).
type PresentationDefinition struct {
	// ID unique resource identifier.
	ID string `json:"id,omitempty"`
	// Name human-friendly name that describes what the Presentation Definition pertains to.
	Name string `json:"name,omitempty"`
	// Purpose describes the purpose for which the Presentation Definition’s inputs are being requested.
	Purpose string `json:"purpose,omitempty"`
	// Format is an object with one or more properties matching the registered Claim Format Designations
	// (jwt, jwt_vc, jwt_vp, etc.) to inform the Holder of the claim format configurations the Verifier can process.
	Format map[string]map[string][]string `json:"format,omitempty"`
	// SubmissionRequirements must conform to the Submission Requirement Format.
	// If not present, all inputs listed in the InputDescriptors array are required for submission.
	SubmissionRequirements []SubmissionRequirement `json:"submission_requirements,omitempty"`
	InputDescriptors       []*InputDescriptor      `json:"input_descriptors,omitempty"`
}

// PresentationSubmission is the container for the descriptor_map:
// https://identity.foundation/presentation-exchange/#presentation-submission.
type PresentationSubmission struct {
	DescriptorMap []*InputDescriptorMapping `json:"descriptor_map"`
}

// InputDescriptorMapping maps an InputDescriptor to a verifiable credential pointed to by the JSONPath in `Path`.
type InputDescriptorMapping struct {
	ID   string `json:"id"`
	Path string `json:"path"`
}

// MatchOptions is a holder of options that can set when matching a submission against definitions.
type MatchOptions struct {
	JSONLDDocumentLoader ld.DocumentLoader
}

// MatchOption is an option that sets an option for when matching.
type MatchOption func(*MatchOptions)

// WithJSONLDDocumentLoader sets the loader to use when parsing the embedded verifiable credentials.
func WithJSONLDDocumentLoader(l ld.DocumentLoader) MatchOption {
	return func(m *MatchOptions) {
		m.JSONLDDocumentLoader = l
	}
}

// Match returns the credentials matched against the InputDescriptors ids.
func (p *PresentationDefinition) Match(vp *verifiable.Presentation, // nolint:gocyclo,funlen
	options ...MatchOption) (map[string]*verifiable.Credential, error) {
	opts := &MatchOptions{}

	for i := range options {
		options[i](opts)
	}

	err := checkJSONLDContextType(vp)
	if err != nil {
		return nil, err
	}

	vpBits, err := vp.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal vp: %w", err)
	}

	typelessVP := interface{}(nil)

	err = json.Unmarshal(vpBits, &typelessVP)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal vp: %w", err)
	}

	descriptorIDs := descriptorIDs(p.InputDescriptors)

	descriptorMap, err := parseDescriptorMap(vp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse descriptor map: %w", err)
	}

	builder := gval.Full(jsonpath.PlaceholderExtension())
	result := make(map[string]*verifiable.Credential)

	for i := range descriptorMap {
		mapping := descriptorMap[i]
		// The object MUST include an id property, and its value MUST be a string matching the id property of
		// the Input Descriptor in the Presentation Definition the submission is related to.
		if !stringsContain(descriptorIDs, mapping.ID) {
			return nil, fmt.Errorf(
				"an %s ID was found that did not match the `id` property of any input descriptor: %s",
				descriptorMapProperty, mapping.ID)
		}

		vc, selectErr := selectByPath(builder, typelessVP, mapping.Path, opts.JSONLDDocumentLoader)
		if selectErr != nil {
			return nil, fmt.Errorf("failed to select vc from submission: %w", selectErr)
		}

		inputDescriptor := p.inputDescriptor(mapping.ID)

		// The schema of the candidate input must match one of the Input Descriptor schema object uri values exactly.
		if !stringsContain(vc.Context, inputDescriptor.Schema.URI) {
			return nil, fmt.Errorf(
				"input descriptor id [%s] requires schema uri [%s] which is not in vc context [%+v]",
				inputDescriptor.ID, inputDescriptor.Schema.URI, vc.Types,
			)
		}

		// TODO add support for constraints: https://github.com/hyperledger/aries-framework-go/issues/2108

		result[mapping.ID] = vc
	}

	err = p.evalSubmissionRequirements(result)
	if err != nil {
		return nil, fmt.Errorf("failed submission requirements: %w", err)
	}

	return result, nil
}

// Ensures the matched credentials meet the submission requirements.
func (p *PresentationDefinition) evalSubmissionRequirements(matched map[string]*verifiable.Credential) error {
	// TODO support submission requirement rules: https://github.com/hyperledger/aries-framework-go/issues/2109
	descriptorIDs := descriptorIDs(p.InputDescriptors)

	for i := range descriptorIDs {
		_, found := matched[descriptorIDs[i]]
		if !found {
			return fmt.Errorf("no credential provided for input descriptor %s", descriptorIDs[i])
		}
	}

	return nil
}

func (p *PresentationDefinition) inputDescriptor(id string) *InputDescriptor {
	for i := range p.InputDescriptors {
		if p.InputDescriptors[i].ID == id {
			return p.InputDescriptors[i]
		}
	}

	return nil
}

func checkJSONLDContextType(vp *verifiable.Presentation) error {
	if !stringsContain(vp.Context, PresentationSubmissionJSONLDContext) {
		return fmt.Errorf("input verifiable presentation must have json-ld context %s", PresentationSubmissionJSONLDContext)
	}

	if !stringsContain(vp.Type, PresentationSubmissionJSONLDType) {
		return fmt.Errorf("input verifiable presentation must have json-ld type %s", PresentationSubmissionJSONLDType)
	}

	return nil
}

func parseDescriptorMap(vp *verifiable.Presentation) ([]*InputDescriptorMapping, error) {
	submission, ok := vp.CustomFields[submissionProperty].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("missing '%s' on verifiable presentation", submissionProperty)
	}

	descriptorMap, ok := submission[descriptorMapProperty].([]interface{})
	if !ok {
		return nil, fmt.Errorf("missing '%s' on verifiable presentation", descriptorMapProperty)
	}

	bits, err := json.Marshal(descriptorMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal descriptor map: %w", err)
	}

	typedDescriptorMap := make([]*InputDescriptorMapping, len(descriptorMap))

	err = json.Unmarshal(bits, &typedDescriptorMap)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal descriptor map: %w", err)
	}

	return typedDescriptorMap, nil
}

func descriptorIDs(input []*InputDescriptor) []string {
	ids := make([]string, len(input))

	for i := range input {
		ids[i] = input[i].ID
	}

	return ids
}

// [The Input Descriptor Mapping Object] MUST include a path property, and its value MUST be a JSONPath
// string expression that selects the credential to be submit in relation to the identified Input Descriptor
// identified, when executed against the top-level of the object the Presentation Submission is embedded within.
func selectByPath(builder gval.Language, vp interface{}, jsonPath string,
	loader ld.DocumentLoader) (*verifiable.Credential, error) {
	path, err := builder.NewEvaluable(jsonPath)
	if err != nil {
		return nil, fmt.Errorf("failed to build new json path evaluator: %w", err)
	}

	cred, err := path(context.TODO(), vp)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate json path [%s]: %w", jsonPath, err)
	}

	credBits, err := json.Marshal(cred)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential: %w", err)
	}

	vcOpts := make([]verifiable.CredentialOpt, 0)

	if loader != nil {
		vcOpts = append(vcOpts, verifiable.WithJSONLDDocumentLoader(loader))
	}

	vc, err := verifiable.ParseCredential(credBits, vcOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}

	return vc, nil
}

func stringsContain(s []string, val string) bool {
	for i := range s {
		if s[i] == val {
			return true
		}
	}

	return false
}
