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

// PresentationSubmission is the container for the descriptor_map:
// https://identity.foundation/presentation-exchange/#presentation-submission.
type PresentationSubmission struct {
	// ID unique resource identifier.
	ID     string `json:"id,omitempty"`
	Locale string `json:"locale,omitempty"`
	// DefinitionID links the submission to its definition and must be the id value of a valid Presentation Definition.
	DefinitionID  string                    `json:"definition_id,omitempty"`
	DescriptorMap []*InputDescriptorMapping `json:"descriptor_map"`
}

// InputDescriptorMapping maps an InputDescriptor to a verifiable credential pointed to by the JSONPath in `Path`.
type InputDescriptorMapping struct {
	ID         string                  `json:"id,omitempty"`
	Format     string                  `json:"format,omitempty"`
	Path       string                  `json:"path,omitempty"`
	PathNested *InputDescriptorMapping `json:"path_nested,omitempty"`
}

// MatchOptions is a holder of options that can set when matching a submission against definitions.
type MatchOptions struct {
	CredentialOptions []verifiable.CredentialOpt
}

// MatchOption is an option that sets an option for when matching.
type MatchOption func(*MatchOptions)

// WithCredentialOptions used when parsing the embedded credentials.
func WithCredentialOptions(options ...verifiable.CredentialOpt) MatchOption {
	return func(m *MatchOptions) {
		m.CredentialOptions = options
	}
}

// Match returns the credentials matched against the InputDescriptors ids.
func (pd *PresentationDefinition) Match(vp *verifiable.Presentation, // nolint:gocyclo,funlen
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

	descriptorIDs := descriptorIDs(pd.InputDescriptors)

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

		vc, selectErr := selectByPath(builder, typelessVP, mapping.Path, opts)
		if selectErr != nil {
			return nil, fmt.Errorf("failed to select vc from submission: %w", selectErr)
		}

		inputDescriptor := pd.inputDescriptor(mapping.ID)

		var found bool
		// The schema of the candidate input must match one of the Input Descriptor schema object uri values exactly.
		for _, schema := range inputDescriptor.Schema {
			if stringsContain(vc.Context, schema.URI) {
				found = true
			}
		}

		if !found {
			return nil, fmt.Errorf(
				"input descriptor id [%s] requires schema uri %+v which is not in vc context [%+v]",
				inputDescriptor.ID, inputDescriptor.Schema, vc.Types)
		}

		// TODO add support for constraints: https://github.com/hyperledger/aries-framework-go/issues/2108

		result[mapping.ID] = vc
	}

	err = pd.evalSubmissionRequirements(result)
	if err != nil {
		return nil, fmt.Errorf("failed submission requirements: %w", err)
	}

	return result, nil
}

// Ensures the matched credentials meet the submission requirements.
func (pd *PresentationDefinition) evalSubmissionRequirements(matched map[string]*verifiable.Credential) error {
	// TODO support submission requirement rules: https://github.com/hyperledger/aries-framework-go/issues/2109
	descriptorIDs := descriptorIDs(pd.InputDescriptors)

	for i := range descriptorIDs {
		_, found := matched[descriptorIDs[i]]
		if !found {
			return fmt.Errorf("no credential provided for input descriptor %s", descriptorIDs[i])
		}
	}

	return nil
}

func (pd *PresentationDefinition) inputDescriptor(id string) *InputDescriptor {
	for i := range pd.InputDescriptors {
		if pd.InputDescriptors[i].ID == id {
			return pd.InputDescriptors[i]
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
	options *MatchOptions) (*verifiable.Credential, error) {
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

	vc, err := verifiable.ParseCredential(credBits, options.CredentialOptions...)
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
