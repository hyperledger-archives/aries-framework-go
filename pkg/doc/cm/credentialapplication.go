/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cm

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

const (
	credentialApplicationPresentationContext = "https://identity.foundation/credential-manifest/application/v1"
	credentialApplicationPresentationType    = "CredentialApplication"
)

// CredentialApplication represents a credential_application object as defined in
// https://identity.foundation/credential-manifest/#credential-application.
// Note that the term "Credential Application" is overloaded in the spec - a "Credential Application" may be referring
// to one of two different, but related, concepts. A "Credential Application" can be the object defined below, which is
// intended to be embedded in an envelope like a Verifiable Presentation. Additionally, when that envelope contains
// the object defined below under a field named "credential_application", then that envelope itself can be called
// a "Credential Application". The larger "envelope version" of a Credential Application may also have a sibling
// presentation_submission object within the envelope, as demonstrated by the PresentCredentialApplication method.
// See https://github.com/decentralized-identity/credential-manifest/issues/73 for more information about this name
// overloading.
type CredentialApplication struct {
	ID string `json:"id,omitempty"`
	// The value of this property MUST be the ID of a valid Credential Manifest.
	ManifestID string `json:"manifest_id,omitempty"`
	// Must be a subset of the format property of the CredentialManifest that this CredentialApplication is related to
	Format presexch.Format `json:"format,omitempty"`
}

// UnmarshalAndValidateAgainstCredentialManifest unmarshals the credentialApplicationBytes into a CredentialApplication
// object (performing verification in the process), and after that verifies that the Credential Application is valid
// against the given Credential Manifest. It's simply a convenience method that allows you to unmarshal and perform
// validation against a Credential Manifest in one call.
func UnmarshalAndValidateAgainstCredentialManifest(credentialApplicationBytes []byte,
	cm *CredentialManifest) (CredentialApplication, error) {
	var credentialApplication CredentialApplication

	err := json.Unmarshal(credentialApplicationBytes, &credentialApplication)
	if err != nil {
		return CredentialApplication{}, err
	}

	err = credentialApplication.ValidateAgainstCredentialManifest(cm)
	if err != nil {
		return CredentialApplication{}, err
	}

	return credentialApplication, nil
}

// UnmarshalJSON is the custom unmarshal function gets called automatically when the standard json.Unmarshal is called.
// It also ensures that the given data is a valid CredentialApplication object per the specification.
func (ca *CredentialApplication) UnmarshalJSON(data []byte) error {
	err := ca.standardUnmarshal(data)
	if err != nil {
		return err
	}

	err = ca.validate()
	if err != nil {
		return fmt.Errorf("invalid Credential Application: %w", err)
	}

	return nil
}

// ValidateAgainstCredentialManifest verifies that the Credential Application is valid against the given
// Credential Manifest.
func (ca *CredentialApplication) ValidateAgainstCredentialManifest(cm *CredentialManifest) error {
	if ca.ManifestID != cm.ID {
		return fmt.Errorf("the Manifest ID of the Credential Application (%s) does not match the given "+
			"Credential Manifest's ID (%s)", ca.ManifestID, cm.ID)
	}

	if cm.hasFormat() {
		err := ca.validateFormatAgainstCredManifestFormat(cm.Format)
		if err != nil {
			return fmt.Errorf("invalid format for the given Credential Manifest: %w", err)
		}
	}

	return nil
}

func (ca *CredentialApplication) standardUnmarshal(data []byte) error {
	// The type alias below is used as to allow the standard json.Unmarshal to be called within a custom unmarshal
	// function without causing infinite recursion. See https://stackoverflow.com/a/43178272 for more information.
	type credentialApplicationWithoutMethods *CredentialApplication

	err := json.Unmarshal(data, credentialApplicationWithoutMethods(ca))
	if err != nil {
		return err
	}

	return nil
}

func (ca *CredentialApplication) validate() error {
	if ca.ID == "" {
		return errors.New("missing ID")
	}

	if ca.ManifestID == "" {
		return errors.New("missing manifest ID")
	}

	return nil
}

func (ca *CredentialApplication) validateFormatAgainstCredManifestFormat(credManifestFormat presexch.Format) error {
	if !ca.hasFormat() {
		return errors.New("the Credential Manifest specifies a format but the Credential Application does not")
	}

	err := ca.ensureFormatIsSubsetOfCredManifestFormat(credManifestFormat)
	if err != nil {
		return fmt.Errorf("invalid format request: %w", err)
	}

	return nil
}

func (ca *CredentialApplication) hasFormat() bool {
	return hasAnyAlgorithmsOrProofTypes(ca.Format)
}

func (ca *CredentialApplication) ensureFormatIsSubsetOfCredManifestFormat(credManiFmt presexch.Format) error {
	err := ensureCredAppJWTAlgsAreSubsetOfCredManiJWTAlgs("JWT", ca.Format.Jwt, credManiFmt.Jwt)
	if err != nil {
		return err
	}

	err = ensureCredAppJWTAlgsAreSubsetOfCredManiJWTAlgs("JWT VC", ca.Format.JwtVC, credManiFmt.JwtVC)
	if err != nil {
		return err
	}

	err = ensureCredAppJWTAlgsAreSubsetOfCredManiJWTAlgs("JWT VP", ca.Format.JwtVP, credManiFmt.JwtVP)
	if err != nil {
		return err
	}

	err = ensureCredAppLDPProofTypesAreSubsetOfCredManiProofTypes("LDP", ca.Format.Ldp, credManiFmt.Ldp)
	if err != nil {
		return err
	}

	err = ensureCredAppLDPProofTypesAreSubsetOfCredManiProofTypes("LDP VC", ca.Format.LdpVC, credManiFmt.LdpVC)
	if err != nil {
		return err
	}

	err = ensureCredAppLDPProofTypesAreSubsetOfCredManiProofTypes("LDP VP", ca.Format.LdpVP, credManiFmt.LdpVP)
	if err != nil {
		return err
	}

	return nil
}

// presentCredentialApplicationOpts holds options for the PresentCredentialApplication method.
type presentCredentialApplicationOpts struct {
	existingPresentation    verifiable.Presentation
	existingPresentationSet bool
}

// PresentCredentialApplicationOpt is an option for the PresentCredentialApplication method.
type PresentCredentialApplicationOpt func(opts *presentCredentialApplicationOpts)

// WithExistingPresentationForPresentCredentialApplication is an option for the PresentCredentialApplication method
// that allows Credential Application data to be added to an existing Presentation
// (turning it into a Credential Application in the process). The existing Presentation should not already have
// Credential Application data.
func WithExistingPresentationForPresentCredentialApplication(
	presentation *verifiable.Presentation) PresentCredentialApplicationOpt {
	return func(opts *presentCredentialApplicationOpts) {
		opts.existingPresentation = *presentation
		opts.existingPresentationSet = true
	}
}

// PresentCredentialApplication creates a minimal Presentation (without proofs) with Credential Application data based
// on credentialManifest. The WithExistingPresentationForPresentCredentialFulfillment can be used to add the Credential
// Application data to an existing Presentation object instead. If the
// "https://identity.foundation/presentation-exchange/submission/v1" context is found, it will be replaced with
// the "https://identity.foundation/credential-manifest/application/v1" context. Note that any existing proofs are
// not updated. Note also the following assumptions/limitations of this method:
// 1. The format of all claims in the Presentation Submission are assumed to be ldp_vp and will be set as such.
// 2. The format for the Credential Application object will be set to match the format from the Credential Manifest
//    exactly. If a caller wants to use a smaller subset of the Credential Manifest's format, then they will have to
//    set it manually.
// 2. The location of the Verifiable Credentials is assumed to be an array at the root under a field called
//    "verifiableCredential".
// 3. The Verifiable Credentials in the presentation is assumed to be in the same order as the Output Descriptors in
//    the Credential Manifest.
func PresentCredentialApplication(credentialManifest *CredentialManifest,
	opts ...PresentCredentialApplicationOpt) (*verifiable.Presentation, error) {
	if credentialManifest == nil {
		return nil, errors.New("credential manifest argument cannot be nil")
	}

	appliedOptions := getPresentCredentialApplicationOpts(opts)

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

	setCredentialApplicationContext(&presentation)

	presentation.Type = append(presentation.Type, credentialApplicationPresentationType)

	setCustomFields(&presentation, credentialManifest)

	return &presentation, nil
}

func getPresentCredentialApplicationOpts(opts []PresentCredentialApplicationOpt) *presentCredentialApplicationOpts {
	processedOptions := &presentCredentialApplicationOpts{}

	for _, opt := range opts {
		if opt != nil {
			opt(processedOptions)
		}
	}

	return processedOptions
}

func setCredentialApplicationContext(presentation *verifiable.Presentation) {
	var newContextSet bool

	for i := range presentation.Context {
		if presentation.Context[i] == presexch.PresentationSubmissionJSONLDContextIRI {
			presentation.Context[i] = credentialApplicationPresentationContext
			newContextSet = true

			break
		}
	}

	if !newContextSet {
		presentation.Context = append(presentation.Context, credentialApplicationPresentationContext)
	}
}

func setCustomFields(presentation *verifiable.Presentation, credentialManifest *CredentialManifest) {
	application := CredentialApplication{
		ID:         uuid.New().String(),
		ManifestID: credentialManifest.ID,
		Format:     credentialManifest.Format,
	}

	if presentation.CustomFields == nil {
		presentation.CustomFields = make(map[string]interface{})
	}

	presentation.CustomFields["credential_application"] = application

	if credentialManifest.PresentationDefinition != nil {
		submission := makePresentationSubmission(credentialManifest.PresentationDefinition)

		presentation.CustomFields["presentation_submission"] = submission
	}
}

func makePresentationSubmission(presentationDef *presexch.PresentationDefinition) presexch.PresentationSubmission {
	descriptorMap := make([]*presexch.InputDescriptorMapping,
		len(presentationDef.InputDescriptors))

	for i := range presentationDef.InputDescriptors {
		descriptorMap[i] = &presexch.InputDescriptorMapping{
			ID:     presentationDef.InputDescriptors[i].ID,
			Format: "ldp_vp",
			Path:   fmt.Sprintf("$.verifiableCredential[%d]", i),
		}
	}

	submission := presexch.PresentationSubmission{
		ID:            uuid.New().String(),
		DefinitionID:  presentationDef.ID,
		DescriptorMap: descriptorMap,
	}

	return submission
}

func ensureCredAppJWTAlgsAreSubsetOfCredManiJWTAlgs(algType string,
	credAppJWTType, credManifestJWTType *presexch.JwtType) error {
	if credAppJWTType != nil { //nolint:nestif // hard to resolve without creating a worse issue
		if credManifestJWTType != nil {
			if !arrayIsSubsetOfAnother(credAppJWTType.Alg, credManifestJWTType.Alg) {
				return makeAlgorithmsSubsetError(algType, credAppJWTType.Alg, credManifestJWTType.Alg)
			}
		} else {
			if len(credAppJWTType.Alg) > 0 {
				return makeAlgorithmsSubsetError(algType, credAppJWTType.Alg, nil)
			}
		}
	}

	return nil
}

func ensureCredAppLDPProofTypesAreSubsetOfCredManiProofTypes(ldpType string,
	credAppLDPType, credManifestLDPType *presexch.LdpType) error {
	if credAppLDPType != nil { //nolint:nestif // hard to resolve without creating a worse issue
		if credManifestLDPType != nil {
			if !arrayIsSubsetOfAnother(credAppLDPType.ProofType, credManifestLDPType.ProofType) {
				return makeProofTypesSubsetError(ldpType, credAppLDPType.ProofType, credManifestLDPType.ProofType)
			}
		} else {
			if len(credAppLDPType.ProofType) > 0 {
				return makeProofTypesSubsetError(ldpType, credAppLDPType.ProofType, nil)
			}
		}
	}

	return nil
}

func makeAlgorithmsSubsetError(algType string, credAppJWTTypeAlgs, credManifestJWTTypeAlgs []string) error {
	return makeSubsetError(algType, "algorithms", credAppJWTTypeAlgs, credManifestJWTTypeAlgs)
}

func makeProofTypesSubsetError(ldpType string, credAppLDPTypeProofTypes, credManifestLDPTypeProofTypes []string) error {
	return makeSubsetError(ldpType, "proof types", credAppLDPTypeProofTypes, credManifestLDPTypeProofTypes)
}

func makeSubsetError(typeInCategory, category string, credAppJWTTypeAlgs, credManifestJWTTypeAlgs []string) error {
	return fmt.Errorf("the Credential Application lists the following %s %s: %v. "+
		"One or more of these are not in the Credential Manifest's supported %s %s: %v",
		typeInCategory, category, credAppJWTTypeAlgs, typeInCategory, category, credManifestJWTTypeAlgs)
}

func arrayIsSubsetOfAnother(array1, array2 []string) bool {
	for _, element := range array1 {
		if !contains(array2, element) {
			return false
		}
	}

	return true
}

func contains(array []string, element string) bool {
	for _, arrayElement := range array {
		if arrayElement == element {
			return true
		}
	}

	return false
}
