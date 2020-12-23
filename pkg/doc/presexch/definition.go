/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presexch

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/PaesslerAG/jsonpath"
	"github.com/google/uuid"
	jsonpathkeys "github.com/kawamuray/jsonpath"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"github.com/xeipuuv/gojsonschema"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

const (
	// All rule`s value.
	All Selection = "all"
	// Pick rule`s value.
	Pick Selection = "pick"

	// Required predicate`s value.
	Required Preference = "required"
	// Preferred predicate`s value.
	Preferred Preference = "preferred"
)

// nolint: gochecknoglobals
var (
	defaultVPContext = []string{
		CredentialsJSONLDContext,
		PresentationSubmissionJSONLDContext,
	}
	defaultVPType = []string{
		VerifiablePresentationJSONLDType,
		PresentationSubmissionJSONLDType,
	}

	errPathNotApplicable = errors.New("path not applicable")
)

type (
	// Selection can be "all" or "pick".
	Selection string
	// Preference can be "required" or "preferred".
	Preference string
	// StrOrInt type that defines string or integer.
	StrOrInt interface{}
)

// Format describes PresentationDefinition`s Format field.
type Format struct {
	Jwt   *JwtType `json:"jwt,omitempty"`
	JwtVC *JwtType `json:"jwt_vc,omitempty"`
	JwtVP *JwtType `json:"jwt_vp,omitempty"`
	Ldp   *LdpType `json:"ldp,omitempty"`
	LdpVC *LdpType `json:"ldp_vc,omitempty"`
	LdpVP *LdpType `json:"ldp_vp,omitempty"`
}

// JwtType contains alg.
type JwtType struct {
	Alg []string `json:"alg,omitempty"`
}

// LdpType contains proof_type.
type LdpType struct {
	ProofType []string `json:"proof_type,omitempty"`
}

// PresentationDefinition presentation definitions (https://identity.foundation/presentation-exchange/).
type PresentationDefinition struct {
	// ID unique resource identifier.
	ID string `json:"id,omitempty"`
	// Name human-friendly name that describes what the Presentation Definition pertains to.
	Name string `json:"name,omitempty"`
	// Purpose describes the purpose for which the Presentation Definition’s inputs are being requested.
	Purpose string `json:"purpose,omitempty"`
	Locale  string `json:"locale,omitempty"`
	// Format is an object with one or more properties matching the registered Claim Format Designations
	// (jwt, jwt_vc, jwt_vp, etc.) to inform the Holder of the claim format configurations the Verifier can process.
	Format *Format `json:"format,omitempty"`
	// SubmissionRequirements must conform to the Submission Requirement Format.
	// If not present, all inputs listed in the InputDescriptors array are required for submission.
	SubmissionRequirements []*SubmissionRequirement `json:"submission_requirements,omitempty"`
	InputDescriptors       []*InputDescriptor       `json:"input_descriptors,omitempty"`
}

// SubmissionRequirement describes input that must be submitted via a Presentation Submission
// to satisfy Verifier demands.
type SubmissionRequirement struct {
	Name       string                   `json:"name,omitempty"`
	Purpose    string                   `json:"purpose,omitempty"`
	Rule       Selection                `json:"rule,omitempty"`
	Count      int                      `json:"count,omitempty"`
	Min        int                      `json:"min,omitempty"`
	Max        int                      `json:"max,omitempty"`
	From       string                   `json:"from,omitempty"`
	FromNested []*SubmissionRequirement `json:"from_nested,omitempty"`
}

// InputDescriptor input descriptors.
type InputDescriptor struct {
	ID          string                 `json:"id,omitempty"`
	Group       []string               `json:"group,omitempty"`
	Name        string                 `json:"name,omitempty"`
	Purpose     string                 `json:"purpose,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Schema      []*Schema              `json:"schema,omitempty"`
	Constraints *Constraints           `json:"constraints,omitempty"`
}

// Schema input descriptor schema.
type Schema struct {
	URI      string `json:"uri,omitempty"`
	Required bool   `json:"required,omitempty"`
}

// Holder describes Constraints`s  holder object.
type Holder struct {
	FieldID   []string    `json:"field_id,omitempty"`
	Directive *Preference `json:"directive,omitempty"`
}

// Constraints describes InputDescriptor`s Constraints field.
type Constraints struct {
	LimitDisclosure bool        `json:"limit_disclosure,omitempty"`
	SubjectIsIssuer *Preference `json:"subject_is_issuer,omitempty"`
	IsHolder        []*Holder   `json:"is_holder,omitempty"`
	Fields          []*Field    `json:"fields,omitempty"`
}

// Field describes Constraints`s Fields field.
type Field struct {
	Path      []string    `json:"path,omitempty"`
	ID        string      `json:"id,omitempty"`
	Purpose   string      `json:"purpose,omitempty"`
	Filter    *Filter     `json:"filter,omitempty"`
	Predicate *Preference `json:"predicate,omitempty"`
}

// Filter describes filter.
type Filter struct {
	Type             *string                `json:"type,omitempty"`
	Format           string                 `json:"format,omitempty"`
	Pattern          string                 `json:"pattern,omitempty"`
	Minimum          StrOrInt               `json:"minimum,omitempty"`
	Maximum          StrOrInt               `json:"maximum,omitempty"`
	MinLength        int                    `json:"minLength,omitempty"`
	MaxLength        int                    `json:"maxLength,omitempty"`
	ExclusiveMinimum StrOrInt               `json:"exclusiveMinimum,omitempty"`
	ExclusiveMaximum StrOrInt               `json:"exclusiveMaximum,omitempty"`
	Const            StrOrInt               `json:"const,omitempty"`
	Enum             []StrOrInt             `json:"enum,omitempty"`
	Not              map[string]interface{} `json:"not,omitempty"`
}

// ValidateSchema validates presentation definition.
func (pd *PresentationDefinition) ValidateSchema() error {
	result, err := gojsonschema.Validate(
		gojsonschema.NewStringLoader(definitionSchema),
		gojsonschema.NewGoLoader(struct {
			PD *PresentationDefinition `json:"presentation_definition"`
		}{PD: pd}),
	)
	if err != nil {
		return err
	}

	if result.Valid() {
		return nil
	}

	resultErrors := result.Errors()

	errs := make([]string, len(resultErrors))
	for i := range resultErrors {
		errs[i] = resultErrors[i].String()
	}

	return errors.New(strings.Join(errs, ","))
}

type requirement struct {
	Count            int
	Min              int
	Max              int
	InputDescriptors []*InputDescriptor
	Nested           []*requirement
}

func (r *requirement) isLenApplicable(val int) bool {
	if r.Count > 0 && val != r.Count {
		return false
	}

	if r.Min > 0 && r.Min > val {
		return false
	}

	if r.Max > 0 && r.Max < val {
		return false
	}

	return true
}

func contains(data []string, e string) bool {
	for _, el := range data {
		if el == e {
			return true
		}
	}

	return false
}

func toRequirement(sr *SubmissionRequirement, descriptors []*InputDescriptor) (*requirement, error) {
	var (
		inputDescriptors []*InputDescriptor
		nested           []*requirement
	)

	var totalCount int

	if sr.From != "" {
		for _, descriptor := range descriptors {
			if contains(descriptor.Group, sr.From) {
				inputDescriptors = append(inputDescriptors, descriptor)
			}
		}

		totalCount = len(inputDescriptors)
		if totalCount == 0 {
			return nil, fmt.Errorf("no descriptors for from: %s", sr.From)
		}
	} else {
		for _, sReq := range sr.FromNested {
			req, err := toRequirement(sReq, descriptors)
			if err != nil {
				return nil, err
			}
			nested = append(nested, req)
		}

		totalCount = len(nested)
	}

	count := sr.Count

	if sr.Rule == All {
		sr.Count = totalCount
	}

	return &requirement{
		Count:            count,
		Min:              sr.Min,
		Max:              sr.Max,
		InputDescriptors: inputDescriptors,
		Nested:           nested,
	}, nil
}

func makeRequirement(requirements []*SubmissionRequirement, descriptors []*InputDescriptor) (*requirement, error) {
	if len(requirements) == 0 {
		return &requirement{
			Count:            len(descriptors),
			InputDescriptors: descriptors,
		}, nil
	}

	req := &requirement{
		Count: len(requirements),
	}

	for _, submissionRequirement := range requirements {
		r, err := toRequirement(submissionRequirement, descriptors)
		if err != nil {
			return nil, err
		}

		req.Nested = append(req.Nested, r)
	}

	return req, nil
}

// CreateVP creates verifiable presentation.
func (pd *PresentationDefinition) CreateVP(credentials ...*verifiable.Credential) (*verifiable.Presentation, error) {
	if err := pd.ValidateSchema(); err != nil {
		return nil, err
	}

	req, err := makeRequirement(pd.SubmissionRequirements, pd.InputDescriptors)
	if err != nil {
		return nil, err
	}

	result, err := applyRequirement(req, credentials...)
	if err != nil {
		return nil, err
	}

	vp := &verifiable.Presentation{
		Context: defaultVPContext,
		Type:    defaultVPType,
	}

	credentials, descriptors := merge(result)
	vp.CustomFields = verifiable.CustomFields{
		submissionProperty: PresentationSubmission{
			ID:            uuid.New().String(),
			DefinitionID:  pd.ID,
			DescriptorMap: descriptors,
		},
	}

	err = vp.SetCredentials(credentialsToInterface(credentials)...)
	if err != nil {
		return nil, err
	}

	return vp, nil
}

var errNoCredentials = errors.New("credentials do not satisfy requirements")

// nolint: gocyclo
func applyRequirement(req *requirement, creds ...*verifiable.Credential) (map[string][]*verifiable.Credential, error) {
	result := make(map[string][]*verifiable.Credential)

	for _, descriptor := range req.InputDescriptors {
		filtered := filterSchema(descriptor.Schema, creds)

		filtered, err := filterConstraints(descriptor.Constraints, filtered)
		if err != nil {
			return nil, err
		}

		if len(filtered) != 0 {
			result[descriptor.ID] = filtered
		}
	}

	if len(req.InputDescriptors) != 0 {
		if req.isLenApplicable(len(result)) {
			return result, nil
		}

		return nil, errNoCredentials
	}

	var nestedResult []map[string][]*verifiable.Credential

	for _, r := range req.Nested {
		res, err := applyRequirement(r, creds...)
		if errors.Is(err, errNoCredentials) {
			continue
		}

		if err != nil {
			return nil, err
		}

		if len(res) != 0 {
			nestedResult = append(nestedResult, res)
		}
	}

	if req.isLenApplicable(len(nestedResult)) {
		return mergeNestedResult(nestedResult), nil
	}

	return nil, errNoCredentials
}

func mergeNestedResult(nr []map[string][]*verifiable.Credential) map[string][]*verifiable.Credential {
	result := make(map[string][]*verifiable.Credential)

	for _, res := range nr {
		for key, credentials := range res {
			set := map[string]struct{}{}

			var mergedCredentials []*verifiable.Credential

			for _, credential := range result[key] {
				if _, ok := set[credential.ID]; !ok {
					mergedCredentials = append(mergedCredentials, credential)
					set[credential.ID] = struct{}{}
				}
			}

			for _, credential := range credentials {
				if _, ok := set[credential.ID]; !ok {
					mergedCredentials = append(mergedCredentials, credential)
					set[credential.ID] = struct{}{}
				}
			}

			result[key] = mergedCredentials
		}
	}

	return result
}

func getSubjectIDs(subject interface{}) []string { // nolint: gocyclo
	switch s := subject.(type) {
	case string:
		return []string{s}
	case []map[string]interface{}:
		var res []string

		for i := range s {
			v, ok := s[i]["id"]
			if !ok {
				continue
			}

			sID, ok := v.(string)
			if !ok {
				continue
			}

			res = append(res, sID)
		}

		return res
	case map[string]interface{}:
		v, ok := s["id"]
		if !ok {
			return nil
		}

		sID, ok := v.(string)
		if !ok {
			return nil
		}

		return []string{sID}
	case verifiable.Subject:
		return []string{s.ID}

	case []verifiable.Subject:
		var res []string
		for i := range s {
			res = append(res, s[i].ID)
		}

		return res
	}

	return nil
}

func subjectIsIssuer(credential *verifiable.Credential) bool {
	for _, ID := range getSubjectIDs(credential.Subject) {
		if ID != "" && ID == credential.Issuer.ID {
			return true
		}
	}

	return false
}

// nolint: gocyclo,funlen,gocognit
func filterConstraints(constraints *Constraints, creds []*verifiable.Credential) ([]*verifiable.Credential, error) {
	if constraints == nil {
		return creds, nil
	}

	var result []*verifiable.Credential

	for _, credential := range creds {
		if constraints.SubjectIsIssuer != nil && *constraints.SubjectIsIssuer == Required && !subjectIsIssuer(credential) {
			continue
		}

		var applicable bool

		credentialSrc, err := json.Marshal(credential)
		if err != nil {
			continue
		}

		var credentialMap map[string]interface{}

		err = json.Unmarshal(credentialSrc, &credentialMap)
		if err != nil {
			return nil, err
		}

		var predicate bool

		for i, field := range constraints.Fields {
			err = filterField(field, credentialMap)
			if errors.Is(err, errPathNotApplicable) {
				applicable = false

				break
			}

			if err != nil {
				return nil, fmt.Errorf("filter field.%d: %w", i, err)
			}

			if field.Predicate != nil && *field.Predicate == Required {
				predicate = true
			}

			applicable = true
		}

		if !applicable {
			continue
		}

		if constraints.LimitDisclosure || predicate {
			template := credentialSrc

			if constraints.LimitDisclosure {
				template, err = json.Marshal(map[string]interface{}{
					"id":                credential.ID,
					"credentialSchema":  credential.Schemas,
					"type":              credential.Types,
					"@context":          credential.Context,
					"issuer":            credential.Issuer,
					"credentialSubject": credential.Subject,
					"issuanceDate":      credential.Issued,
				})
				if err != nil {
					return nil, err
				}
			}

			var err error

			credential, err = createNewCredential(constraints.Fields, credentialSrc, template)
			if err != nil {
				return nil, fmt.Errorf("create new credential: %w", err)
			}
		}

		result = append(result, credential)
	}

	return result, nil
}

func createNewCredential(fs []*Field, src, limitedCred []byte) (*verifiable.Credential, error) {
	for _, f := range fs {
		paths, err := jsonpathkeys.ParsePaths(f.Path...)
		if err != nil {
			return nil, err
		}

		eval, err := jsonpathkeys.EvalPathsInReader(bytes.NewReader(src), paths)
		if err != nil {
			return nil, err
		}

		var jPaths [][2]string

		set := map[string]int{}

		for {
			result, ok := eval.Next()
			if !ok {
				break
			}

			jPaths = append(jPaths, getPath(result.Keys, set))
		}

		for _, path := range jPaths {
			var val interface{} = true

			if f.Predicate == nil || *f.Predicate != Required {
				val = gjson.GetBytes(src, path[1]).Value()
			}

			limitedCred, err = sjson.SetBytes(limitedCred, path[0], val)
			if err != nil {
				return nil, err
			}
		}
	}

	return verifiable.ParseUnverifiedCredential(limitedCred)
}

func filterField(f *Field, credential map[string]interface{}) error {
	var schema gojsonschema.JSONLoader

	if f.Filter != nil {
		schema = gojsonschema.NewGoLoader(*f.Filter)
	}

	for _, path := range f.Path {
		patch, err := jsonpath.Get(path, credential)
		if err != nil {
			return errPathNotApplicable
		}

		err = validatePatch(schema, patch)
		if err != nil {
			return err
		}
	}

	return nil
}

func validatePatch(schema gojsonschema.JSONLoader, patch interface{}) error {
	if schema == nil {
		return nil
	}

	raw, err := json.Marshal(patch)
	if err != nil {
		return err
	}

	result, err := gojsonschema.Validate(schema, gojsonschema.NewBytesLoader(raw))
	if err != nil || !result.Valid() {
		return errPathNotApplicable
	}

	return nil
}

func getPath(keys []interface{}, set map[string]int) [2]string {
	var (
		newPath      []string
		originalPath []string
	)

	for _, k := range keys {
		switch v := k.(type) {
		case int:
			counterKey := strings.Join(originalPath, ".")
			originalPath = append(originalPath, fmt.Sprintf("%d", v))
			mapperKey := strings.Join(originalPath, ".")

			if _, ok := set[mapperKey]; !ok {
				set[mapperKey] = set[counterKey]
				set[counterKey]++
			}

			newPath = append(newPath, fmt.Sprintf("%d", set[mapperKey]))
		default:
			originalPath = append(originalPath, fmt.Sprintf("%s", v))
			newPath = append(newPath, fmt.Sprintf("%s", v))
		}
	}

	return [...]string{strings.Join(newPath, "."), strings.Join(originalPath, ".")}
}

func merge(setOfCredentials map[string][]*verifiable.Credential) ([]*verifiable.Credential, []*InputDescriptorMapping) {
	setOfCreds := make(map[string]int)
	setOfDescriptors := make(map[string]struct{})

	var (
		result      []*verifiable.Credential
		descriptors []*InputDescriptorMapping
	)

	for descriptorID, credentials := range setOfCredentials {
		for _, credential := range credentials {
			if _, ok := setOfCreds[credential.ID]; !ok {
				result = append(result, credential)
				setOfCreds[credential.ID] = len(descriptors)
			}

			if _, ok := setOfDescriptors[fmt.Sprintf("%s-%s", credential.ID, credential.ID)]; !ok {
				descriptors = append(descriptors, &InputDescriptorMapping{
					ID: descriptorID,
					// TODO: what format should be here?
					Format: "ldp_vp",
					Path:   fmt.Sprintf("$.verifiableCredential[%d]", setOfCreds[credential.ID]),
				})
			}
		}
	}

	return result, descriptors
}

func credentialsToInterface(credentials []*verifiable.Credential) []interface{} {
	var result []interface{}
	for i := range credentials {
		result = append(result, credentials[i])
	}

	return result
}

func filterSchema(schemas []*Schema, credentials []*verifiable.Credential) []*verifiable.Credential {
	var result []*verifiable.Credential

	for _, cred := range credentials {
		var applicable bool

		for _, schema := range schemas {
			applicable = credentialMatchSchema(cred, schema.URI)
			if schema.Required && !applicable {
				break
			}
		}

		if applicable {
			result = append(result, cred)
		}
	}

	return result
}

func credentialMatchSchema(cred *verifiable.Credential, schemaID string) bool {
	for i := range cred.Schemas {
		if cred.Schemas[i].ID == schemaID {
			return true
		}
	}

	return false
}
