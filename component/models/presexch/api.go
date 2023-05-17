/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presexch

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/PaesslerAG/gval"
	"github.com/PaesslerAG/jsonpath"
	"github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/component/models/verifiable"
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

// MatchValue holds a matched credential from PresentationDefinition.Match, along with the ID of the
// presentation that held the matched credential.
type MatchValue struct {
	PresentationID string
	Credential     *verifiable.Credential
}

// MatchOptions is a holder of options that can set when matching a submission against definitions.
type MatchOptions struct {
	CredentialOptions       []verifiable.CredentialOpt
	DisableSchemaValidation bool
	MergedSubmission        *PresentationSubmission
	MergedSubmissionMap     map[string]interface{}
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

// WithMergedSubmission provides a presentation submission that's external to the Presentations being matched,
// which contains the descriptor mapping for each Presentation.
//
// If there are multiple Presentations, this merged submission should use the Presentation array as the JSON Path root
// when referencing the contained Presentations and the Credentials within.
func WithMergedSubmission(submission *PresentationSubmission) MatchOption {
	return func(m *MatchOptions) {
		m.MergedSubmission = submission
	}
}

// WithMergedSubmissionMap provides a presentation submission that's external to the Presentations being matched,
// which contains the descriptor mapping for each Presentation. This submission is expected to be in the
// map[string]interface{} format used by json.Unmarshal.
//
// If there are multiple Presentations, this merged submission should use the Presentation array as the JSON Path root
// when referencing the contained Presentations and the Credentials within.
func WithMergedSubmissionMap(submissionMap map[string]interface{}) MatchOption {
	return func(m *MatchOptions) {
		m.MergedSubmissionMap = submissionMap
	}
}

// Match returns the credentials matched against the InputDescriptors ids.
func (pd *PresentationDefinition) Match(vpList []*verifiable.Presentation,
	contextLoader ld.DocumentLoader, options ...MatchOption) (map[string]MatchValue, error) {
	opts := &MatchOptions{}

	for i := range options {
		options[i](opts)
	}

	result, err := getMatchedCreds(pd, vpList, contextLoader, opts)
	if err != nil {
		return nil, err
	}

	err = pd.evalSubmissionRequirements(result)
	if err != nil {
		return nil, fmt.Errorf("failed submission requirements: %w", err)
	}

	return result, nil
}

func getMatchedCreds( //nolint:gocyclo,funlen
	pd *PresentationDefinition,
	vpList []*verifiable.Presentation,
	contextLoader ld.DocumentLoader,
	opts *MatchOptions,
) (map[string]MatchValue, error) {
	result := make(map[string]MatchValue)

	descriptorIDs := descriptorIDs(pd.InputDescriptors)

	useMergedSubmission := opts.MergedSubmission != nil || len(opts.MergedSubmissionMap) != 0

	var mappingsByVPIndex map[int][]*InputDescriptorMapping

	if opts.MergedSubmission != nil {
		mappingsByVPIndex = descriptorsByPresentationIndex(opts.MergedSubmission.DescriptorMap)
	} else if len(opts.MergedSubmissionMap) != 0 {
		useMergedSubmission = true

		descs, err := getDescriptorMapping(opts.MergedSubmissionMap)
		if err != nil {
			return nil, fmt.Errorf("failed to parse descriptor map: %w", err)
		}

		mappingsByVPIndex = descriptorsByPresentationIndex(descs)
	}

	rawVPs := make([]interface{}, len(vpList))

	for vpIdx, vp := range vpList {
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

		rawVPs[vpIdx] = typelessVP

		var descriptorMap []*InputDescriptorMapping

		if useMergedSubmission {
			descriptorMap = mappingsByVPIndex[vpIdx]
		} else {
			descriptorMap, err = parseDescriptorMap(vp)
			if err != nil {
				return nil, fmt.Errorf("failed to parse descriptor map: %w", err)
			}
		}

		for _, mapping := range descriptorMap {
			// The object MUST include an id property, and its value MUST be a string matching the id property of
			// the Input Descriptor in the Presentation Definition the submission is related to.
			if _, ok := descriptorIDs[mapping.ID]; !ok {
				return nil, fmt.Errorf(
					"an %s ID was found that did not match the `id` property of any input descriptor: %s",
					descriptorMapProperty, mapping.ID)
			}

			var (
				vc        *verifiable.Credential
				selectErr error
			)

			if descriptorMappingExpectsVPList(mapping) {
				vc, selectErr = selectVC(rawVPs, mapping, opts)
			} else if len(vpList) == 1 || !useMergedSubmission {
				vc, selectErr = selectVC(typelessVP, mapping, opts)
			} else {
				return nil, fmt.Errorf("presentation submission has invalid path for matching a list of presentations")
			}

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

			result[mapping.ID] = MatchValue{
				PresentationID: vp.ID,
				Credential:     vc,
			}
		}
	}

	return result, nil
}

func selectVC(typelessVerifiable interface{},
	mapping *InputDescriptorMapping, opts *MatchOptions) (*verifiable.Credential, error) {
	builder := gval.Full(jsonpath.PlaceholderExtension())

	var vc *verifiable.Credential

	var err error

	for {
		typelessVerifiable, err = selectByPath(builder, typelessVerifiable, mapping.Path)
		if err != nil {
			return nil, fmt.Errorf("failed to select vc from submission: %w", err)
		}

		if mapping.PathNested != nil {
			mapping = mapping.PathNested
			continue
		}

		var credBits []byte

		credBits, err = json.Marshal(typelessVerifiable)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal credential: %w", err)
		}

		vc, err = verifiable.ParseCredential(credBits, opts.CredentialOptions...)
		if err != nil {
			return nil, fmt.Errorf("failed to parse credential: %w", err)
		}

		break
	}

	return vc, nil
}

// Ensures the matched credentials meet the submission requirements.
func (pd *PresentationDefinition) evalSubmissionRequirements(matched map[string]MatchValue) error {
	// TODO support submission requirement rules: https://github.com/hyperledger/aries-framework-go/issues/2109
	descriptorIDs := descriptorIDs(pd.InputDescriptors)

	for i := range descriptorIDs {
		_, found := matched[i]
		if !found {
			return fmt.Errorf("no credential provided for input descriptor %s", i)
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
	untypedSubmission, ok := vp.CustomFields[submissionProperty]
	if !ok {
		return nil, fmt.Errorf("missing '%s' on verifiable presentation", submissionProperty)
	}

	switch submission := untypedSubmission.(type) {
	case map[string]interface{}:
		return getDescriptorMapping(submission)
	case *PresentationSubmission:
		return submission.DescriptorMap, nil
	case PresentationSubmission:
		return submission.DescriptorMap, nil
	default:
		return nil, fmt.Errorf("missing '%s' on verifiable presentation", submissionProperty)
	}
}

func getDescriptorMapping(submission map[string]interface{}) ([]*InputDescriptorMapping, error) {
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

func descriptorIDs(input []*InputDescriptor) map[string]bool {
	ids := make(map[string]bool)

	for _, id := range input {
		ids[id.ID] = true
	}

	return ids
}

func descriptorMappingExpectsVPList(idm *InputDescriptorMapping) bool {
	if strings.HasPrefix(idm.Path, "$[") {
		return true
	}

	if idm.PathNested == nil {
		return false
	}

	return descriptorMappingExpectsVPList(idm.PathNested)
}

func descriptorsByPresentationIndex(idm []*InputDescriptorMapping) map[int][]*InputDescriptorMapping {
	results := map[int][]*InputDescriptorMapping{}

	for _, mapping := range idm {
		idx := presentationIndex(mapping)

		results[idx] = append(results[idx], mapping)
	}

	return results
}

func presentationIndex(idm *InputDescriptorMapping) int {
	if idm == nil {
		return 0
	}

	idx := rootIndex(idm.Path)
	if idx != -1 {
		return idx
	}

	// check the nested path, if the root path stays at root.
	if idm.Path == "$" {
		return presentationIndex(idm.PathNested)
	}

	return 0
}

// rootIndex takes a jsonpath, and if the path indexes the root as an array, this returns the index.
// Otherwise, this returns -1.
func rootIndex(jsonPathStr string) int {
	if !strings.HasPrefix(jsonPathStr, "$[") {
		return -1
	}

	split := strings.SplitN(jsonPathStr[2:], "]", 2)

	if len(split) == 0 || split[0] == "" {
		return -1
	}

	result, err := strconv.Atoi(split[0])
	if err != nil {
		return -1
	}

	return result
}

// [The Input Descriptor Mapping Object] MUST include a path property, and its value MUST be a JSONPath
// string expression that selects the credential to be submit in relation to the identified Input Descriptor
// identified, when executed against the top-level of the object the Presentation Submission is embedded within.
func selectByPath(builder gval.Language, vp interface{}, jsonPath string) (interface{}, error) {
	path, err := builder.NewEvaluable(jsonPath)
	if err != nil {
		return nil, fmt.Errorf("failed to build new json path evaluator: %w", err)
	}

	cred, err := path(context.TODO(), vp)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate json path [%s]: %w", jsonPath, err)
	}

	return cred, nil
}

func stringsContain(s []string, val string) bool {
	for i := range s {
		if s[i] == val {
			return true
		}
	}

	return false
}
