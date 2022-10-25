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
	// PresentationSubmissionJSONLDContextIRI is the JSONLD context of presentation submissions.
	PresentationSubmissionJSONLDContextIRI = "https://identity.foundation/presentation-exchange/submission/v1"
	// CredentialApplicationJSONLDContextIRI is the JSONLD context of credential application
	// which also contains presentation submission details.
	CredentialApplicationJSONLDContextIRI = "https://identity.foundation/credential-manifest/application/v1"
	// PresentationSubmissionJSONLDType is the JSONLD type of presentation submissions.
	PresentationSubmissionJSONLDType = "PresentationSubmission"
	// CredentialApplicationJSONLDType is the JSONLD type of credential application.
	CredentialApplicationJSONLDType = "CredentialApplication"

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
	CredentialOptions       []verifiable.CredentialOpt
	DisableSchemaValidation bool
}

// MatchOption is an option that sets an option for when matching.
type MatchOption func(*MatchOptions)

// WithCredentialOptions used when parsing the embedded credentials.
func WithCredentialOptions(options ...verifiable.CredentialOpt) MatchOption {
	return func(m *MatchOptions) {
		m.CredentialOptions = options
	}
}

// WithDisableSchemaValidation used to disable schema validation.
func WithDisableSchemaValidation() MatchOption {
	return func(m *MatchOptions) {
		m.DisableSchemaValidation = true
	}
}

// Match returns the credentials matched against the InputDescriptors ids.
func (pd *PresentationDefinition) Match(vp *verifiable.Presentation, // nolint:gocyclo,funlen
	contextLoader ld.DocumentLoader, options ...MatchOption) (map[string]*verifiable.Credential, error) {
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

		vc, selectErr := selectVC(typelessVP, mapping, opts)
		if selectErr != nil {
			return nil, selectErr
		}

		inputDescriptor := pd.inputDescriptor(mapping.ID)

		passed := filterSchema(inputDescriptor.Schema, []*verifiable.Credential{vc}, contextLoader)
		if len(passed) == 0 && !opts.DisableSchemaValidation {
			return nil, fmt.Errorf(
				"input descriptor id [%s] requires schemas %+v which do not match vc with @context [%+v] and types [%+v] selected by path [%s]", // nolint:lll
				inputDescriptor.ID, inputDescriptor.Schema, vc.Context, vc.Types, mapping.Path)
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

func selectVC(typelessVerifiable interface{},
	mapping *InputDescriptorMapping, opts *MatchOptions) (*verifiable.Credential, error) {
	builder := gval.Full(jsonpath.PlaceholderExtension())

	var vc *verifiable.Credential

	var err error

	for {
		vc, err = selectByPath(builder, typelessVerifiable, mapping.Path, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to select vc from submission: %w", err)
		}

		if mapping.PathNested == nil {
			break
		}

		mapping = mapping.PathNested

		var vcBytes []byte

		vcBytes, err = vc.MarshalJSON()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal vc: %w", err)
		}

		err = json.Unmarshal(vcBytes, &typelessVerifiable)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal vc: %w", err)
		}
	}

	return vc, nil
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
	if !stringsContain(vp.Context, PresentationSubmissionJSONLDContextIRI) &&
		!stringsContain(vp.Context, CredentialApplicationJSONLDContextIRI) {
		return fmt.Errorf("input verifiable presentation must have json-ld context %s or %s",
			PresentationSubmissionJSONLDContextIRI, CredentialApplicationJSONLDContextIRI)
	}

	if !stringsContain(vp.Type, PresentationSubmissionJSONLDType) &&
		!stringsContain(vp.Type, CredentialApplicationJSONLDType) {
		return fmt.Errorf("input verifiable presentation must have json-ld type %s or %s",
			PresentationSubmissionJSONLDType, CredentialApplicationJSONLDType)
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
