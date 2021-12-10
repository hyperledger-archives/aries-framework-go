/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cm

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
)

// CredentialApplication represents a credential_application object as defined in
// https://identity.foundation/credential-manifest/#credential-application.
// When used in an envelope like a Verifiable Presentation (under a field named "credential_application", that
// envelope then becomes a Credential Application.
// This object may also have a sibling presentation_submission object within the envelope.
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
