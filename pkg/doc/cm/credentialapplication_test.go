/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cm_test

import (
	_ "embed"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/doc/cm"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

const unknownFormatName = "SomeUnknownFormat"

// Note that the term "Credential Application" can refer to two different, but related, concepts. See the
// documentation above the cm.CredentialApplication type definition for more information.

// Sample Credential Applications for a university degree.
// Here, "Credential Application" refers to the "credential_application" object that gets embedded within a larger
// envelope.
var (
	//go:embed testdata/credential_application_university_degree.json
	credentialApplicationUniversityDegree []byte //nolint:gochecknoglobals
	//go:embed testdata/credential_application_university_degree_with_format.json
	credentialApplicationUniversityDegreeWithFormat []byte //nolint:gochecknoglobals
)

// Sample "minimal" Verifiable Presentations. These are VPs that were created by a call to verifiable.NewPresentation()
// with no arguments/options, which is how the cm.PresentCredentialApplication method generates a VP if the
// WithExistingPresentationForPresentCredentialApplication option is not used. Additional data
// (like Credential Application and Credential Submission) was then added to it.
var (
	//go:embed testdata/VP_minimal_with_credential_application.json
	vpMinimalWithCredentialApplication []byte //nolint:gochecknoglobals
	//go:embed testdata/VP_minimal_with_credential_application_and_presentation_submission.json
	vpMinimalWithCredentialApplicationAndPresentationSubmission []byte //nolint:gochecknoglobals
	//go:embed testdata/VP_minimal_with_credential_application_and_presentation_submission_and_format.json
	vpMinimalWithCredentialApplicationAndPresentationSubmissionAndFormat []byte //nolint:gochecknoglobals
)

// Sample Verifiable Presentations that contain a PR card VC.
var (
	//go:embed testdata/VP_with_PR_Card_VC.json
	vpWithPRCardVC []byte //nolint:gochecknoglobals
	//go:embed testdata/VP_with_PR_card_VC_and_credential_application.json
	vpWithPRCardVCAndCredentialApplication []byte //nolint:gochecknoglobals
	//go:embed testdata/VP_with_PR_card_VC_and_credential_application_and_presentation_submission.json
	vpWithPRCardVCAndCredentialApplicationAndPresentationSubmission []byte //nolint:gochecknoglobals
	//go:embed testdata/VP_with_PR_card_VC_and_credential_application_and_presentation_submission_and_format.json
	vpWithPRCardVCAndCredentialApplicationAndPresentationSubmissionAndFormat []byte //nolint:gochecknoglobals
	//go:embed testdata/VP_with_PR_Card_VC_using_presentation_exchange_context.json
	vpWithPRCardVCUsingPresentationExchangeContext []byte //nolint:gochecknoglobals
)

// Sample Credential Application attachment.
//go:embed testdata/credential_application_attachment_drivers_license.json
var credentialApplicationAttachmentDriversLicense []byte //nolint:gochecknoglobals

func TestUnmarshalAndValidateAgainstCredentialManifest(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		credentialManifest := makeCredentialManifestFromBytes(t, credentialManifestUniversityDegree)

		credentialApplication, err := cm.UnmarshalAndValidateAgainstCredentialManifest(
			credentialApplicationUniversityDegree, &credentialManifest)
		require.NoError(t, err)
		require.Equal(t, "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d", credentialApplication.ID)
	})
	t.Run("Failure during validation", func(t *testing.T) {
		credentialManifest := makeCredentialManifestFromBytes(t, credentialManifestUniversityDegreeWithFormat)

		_, err := cm.UnmarshalAndValidateAgainstCredentialManifest(
			credentialApplicationUniversityDegree, &credentialManifest)
		require.EqualError(t, err, "invalid format for the given Credential Manifest: the Credential "+
			"Manifest specifies a format but the Credential Application does not")
	})
}

func TestValidateCredentialApplicationAttachment(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		credentialManifest := makeCredentialManifestFromBytes(t,
			credentialManifestDriversLicenseWithPresentationDefinitionAndFormat)

		credentialApplicationAttachment := makeAttachmentFromBytes(t)

		err := cm.ValidateCredentialApplicationAttachment(credentialApplicationAttachment, &credentialManifest)
		require.NoError(t, err)
	})
	t.Run("Missing credential_application field", func(t *testing.T) {
		credentialManifest := makeCredentialManifestFromBytes(t,
			credentialManifestDriversLicenseWithPresentationDefinitionAndFormat)

		credentialApplicationAttachment := makeAttachmentWithoutCredentialApplicationField(t)

		err := cm.ValidateCredentialApplicationAttachment(credentialApplicationAttachment, &credentialManifest)
		require.EqualError(t, err, "missing credential_application field")
	})
	t.Run("Fail to assert attachment data as a map", func(t *testing.T) {
		credentialManifest := makeCredentialManifestFromBytes(t,
			credentialManifestDriversLicenseWithPresentationDefinitionAndFormat)

		credentialApplicationAttachment := makeAttachmentWithUnexpectedDataJSONType(t)

		err := cm.ValidateCredentialApplicationAttachment(credentialApplicationAttachment, &credentialManifest)
		require.EqualError(t, err, "couldn't assert attachment data as a map")
	})
	t.Run("Fail to marshal Credential Application", func(t *testing.T) {
		credentialManifest := makeCredentialManifestFromBytes(t,
			credentialManifestDriversLicenseWithPresentationDefinitionAndFormat)

		credentialApplicationAttachment := makeAttachmentWithUnmarshallableCredentialAttachment(t)

		err := cm.ValidateCredentialApplicationAttachment(credentialApplicationAttachment, &credentialManifest)
		require.EqualError(t, err, "failed to marshal credential_application object: "+
			"json: unsupported type: func()")
	})
	t.Run("Invalid Credential Application", func(t *testing.T) {
		credentialManifest := makeCredentialManifestFromBytes(t,
			credentialManifestDriversLicenseWithPresentationDefinitionAndFormat)

		credentialApplicationAttachment := makeAttachmentWithInvalidCredentialApplication(t)

		err := cm.ValidateCredentialApplicationAttachment(credentialApplicationAttachment, &credentialManifest)
		require.EqualError(t, err, "the Manifest ID of the Credential Application (SomeUnknownManifestID) "+
			"does not match the given Credential Manifest's ID (dcc75a16-19f5-4273-84ce-4da69ee2b7fe)")
	})
	t.Run("Credential Manifest has a Presentation Definition but the a doesn't have a "+
		"Presentation Submission", func(t *testing.T) {
		credentialManifest := makeCredentialManifestFromBytes(t,
			credentialManifestDriversLicenseWithPresentationDefinitionAndFormat)

		credentialApplicationAttachment := makeAttachmentWithoutPresentationSubmission(t)

		err := cm.ValidateCredentialApplicationAttachment(credentialApplicationAttachment, &credentialManifest)
		require.EqualError(t, err, "the Credential Manifest contains a Presentation Definition but the "+
			"Credential Application attachment is missing a corresponding Presentation Submission")
	})
	t.Run("Presentation Submission's Definition ID does not match the "+
		"Presentation Definition's ID", func(t *testing.T) {
		credentialManifest := makeCredentialManifestFromBytes(t,
			credentialManifestDriversLicenseWithPresentationDefinitionAndFormat)

		credentialApplicationAttachment := makeAttachmentWithPresentationSubmissionWithIncorrectDefinitionID(t)

		err := cm.ValidateCredentialApplicationAttachment(credentialApplicationAttachment, &credentialManifest)
		require.EqualError(t, err, "the Definition ID of the Credential Submission (UnknownID) does "+
			"not match the given Presentation Definition's ID (8246867e-fdce-48de-a825-9d84ec16c6c9)")
	})
	t.Run("Number of descriptors in Presentation Submission does not match number of input descriptors in "+
		"Presentation Definition", func(t *testing.T) {
		credentialManifest := makeCredentialManifestFromBytes(t,
			credentialManifestDriversLicenseWithPresentationDefinitionAndFormat)

		credentialApplicationAttachment := makeAttachmentWithPresentationSubmissionWithIncorrectNumberOfDescriptors(t)

		err := cm.ValidateCredentialApplicationAttachment(credentialApplicationAttachment, &credentialManifest)
		require.EqualError(t, err, "the number of descriptors in the Presentation Submission (2) "+
			"does not match the number of input descriptors in the Presentation Definition (1)")
	})
	t.Run("Descriptor ID in Presentation Submission does not match input descriptor in Presentation Definition "+
		"Presentation Definition", func(t *testing.T) {
		credentialManifest := makeCredentialManifestFromBytes(t,
			credentialManifestDriversLicenseWithPresentationDefinitionAndFormat)

		credentialApplicationAttachment := makeAttachmentWithPresentationSubmissionWithIncorrectDescriptorID(t)

		err := cm.ValidateCredentialApplicationAttachment(credentialApplicationAttachment, &credentialManifest)
		require.EqualError(t, err, "the descriptor ID at index 0 (WrongID) in the Presentation Submission "+
			"does not match the input descriptor at index 0 (prc_input) in the Presentation Definition")
	})
}

func TestCredentialApplication_Unmarshal(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		makeCredentialApplicationFromBytes(t, credentialApplicationUniversityDegree)
	})
	t.Run("Missing ID", func(t *testing.T) {
		credentialApplicationBytes := makeCredentialApplicationWithMissingID(t)

		var credentialApplication cm.CredentialApplication

		err := json.Unmarshal(credentialApplicationBytes, &credentialApplication)
		require.EqualError(t, err, "invalid Credential Application: missing ID")
	})
	t.Run("Missing Manifest ID", func(t *testing.T) {
		credentialApplicationBytes := makeCredentialApplicationWithMissingManifestID(t)

		var credentialApplication cm.CredentialApplication

		err := json.Unmarshal(credentialApplicationBytes, &credentialApplication)
		require.EqualError(t, err, "invalid Credential Application: missing manifest ID")
	})
}

func TestCredentialApplication_ValidateAgainstCredentialManifest(t *testing.T) {
	t.Run("Credential Manifest has no format and no presentation definition", func(t *testing.T) {
		t.Run("Credential Application has no format and no presentation definition", func(t *testing.T) {
			credentialApplication := makeCredentialApplicationFromBytes(t, credentialApplicationUniversityDegree)

			credentialManifest := makeCredentialManifestFromBytes(t, credentialManifestUniversityDegree)

			err := credentialApplication.ValidateAgainstCredentialManifest(&credentialManifest)
			require.NoError(t, err)
		})
	})
	t.Run("Credential Manifest has a format", func(t *testing.T) {
		t.Run("Credential Application has no format", func(t *testing.T) {
			credentialApplication := makeCredentialApplicationFromBytes(t, credentialApplicationUniversityDegree)

			credentialManifest := makeCredentialManifestFromBytes(t, credentialManifestUniversityDegreeWithFormat)

			err := credentialApplication.ValidateAgainstCredentialManifest(&credentialManifest)
			require.EqualError(t, err, "invalid format for the given Credential Manifest: the Credential "+
				"Manifest specifies a format but the Credential Application does not")
		})
		t.Run("Credential App requests a JWT format not allowed by the Credential Manifest", func(t *testing.T) {
			credentialApplication := makeCredentialApplicationWithUnknownJWTAlg(t)

			credentialManifest := makeCredentialManifestFromBytes(t, credentialManifestUniversityDegreeWithFormat)

			err := credentialApplication.ValidateAgainstCredentialManifest(&credentialManifest)
			require.EqualError(t, err, "invalid format for the given Credential Manifest: invalid format "+
				"request: the Credential Application lists the following JWT algorithms: [SomeUnknownFormat ES256K "+
				"ES384]. One or more of these are not in the Credential Manifest's supported JWT algorithms: [EdDSA "+
				"ES256K ES384]")
		})
		t.Run("Cred App requests a JWT VC format not allowed by the Cred Manifest", func(t *testing.T) {
			credentialApplication := makeCredentialApplicationWithUnknownJWTVCAlg(t)

			credentialManifest := makeCredentialManifestFromBytes(t, credentialManifestUniversityDegreeWithFormat)

			err := credentialApplication.ValidateAgainstCredentialManifest(&credentialManifest)
			require.EqualError(t, err, "invalid format for the given Credential Manifest: invalid format "+
				"request: the Credential Application lists the following JWT VC algorithms: [SomeUnknownFormat "+
				"ES384]. One or more of these are not in the Credential Manifest's supported JWT VC algorithms: "+
				"[ES256K ES384]")
		})
		t.Run("Cred App requests a JWT VP format not allowed by the Cred Manifest", func(t *testing.T) {
			credentialApplication := makeCredentialApplicationWithUnknownJWTVPAlg(t)

			credentialManifest := makeCredentialManifestFromBytes(t, credentialManifestUniversityDegreeWithFormat)

			err := credentialApplication.ValidateAgainstCredentialManifest(&credentialManifest)
			require.EqualError(t, err, "invalid format for the given Credential Manifest: invalid format "+
				"request: the Credential Application lists the following JWT VP algorithms: [SomeUnknownFormat "+
				"ES256K]. One or more of these are not in the Credential Manifest's supported JWT VP algorithms: "+
				"[EdDSA ES256K]")
		})
		t.Run("Cred App requests an LDP proof type not allowed by the Cred Manifest", func(t *testing.T) {
			credentialApplication := makeCredentialApplicationWithUnknownLDPProofType(t)

			credentialManifest := makeCredentialManifestFromBytes(t, credentialManifestUniversityDegreeWithFormat)

			err := credentialApplication.ValidateAgainstCredentialManifest(&credentialManifest)
			require.EqualError(t, err, "invalid format for the given Credential Manifest: invalid format "+
				"request: the Credential Application lists the following LDP proof types: [SomeUnknownFormat]. "+
				"One or more of these are not in the Credential Manifest's supported LDP proof types: "+
				"[RsaSignature2018]")
		})
		t.Run("Cred App requests an LDP VC proof type not allowed by the Cred Manifest", func(t *testing.T) {
			credentialApplication := makeCredentialApplicationWithUnknownLDPVCProofType(t)

			credentialManifest := makeCredentialManifestFromBytes(t, credentialManifestUniversityDegreeWithFormat)

			err := credentialApplication.ValidateAgainstCredentialManifest(&credentialManifest)
			require.EqualError(t, err, "invalid format for the given Credential Manifest: invalid format "+
				"request: the Credential Application lists the following LDP VC proof types: [SomeUnknownFormat "+
				"EcdsaSecp256k1Signature2019 Ed25519Signature2018]. One or more of these are not in the "+
				"Credential Manifest's supported LDP VC proof types: [JsonWebSignature2020 Ed25519Signature2018 "+
				"EcdsaSecp256k1Signature2019 RsaSignature2018]")
		})
		t.Run("Cred App requests an LDP VC proof type not allowed by the Cred Manifest", func(t *testing.T) {
			credentialApplication := makeCredentialApplicationWithUnknownLDPVPProofType(t)

			credentialManifest := makeCredentialManifestFromBytes(t, credentialManifestUniversityDegreeWithFormat)

			err := credentialApplication.ValidateAgainstCredentialManifest(&credentialManifest)
			require.EqualError(t, err, "invalid format for the given Credential Manifest: invalid format "+
				"request: the Credential Application lists the following LDP VP proof types: [SomeUnknownFormat]. "+
				"One or more of these are not in the Credential Manifest's supported LDP VP proof types: "+
				"[Ed25519Signature2018]")
		})
		t.Run("Cred App requests JWT formats but the Cred Manifest's JWT format is nil", func(t *testing.T) {
			credentialApplication := makeCredentialApplicationFromBytes(t, credentialApplicationUniversityDegreeWithFormat)

			credentialManifest := createCredentialManifestWithNilJWTFormat(t)

			err := credentialApplication.ValidateAgainstCredentialManifest(&credentialManifest)
			require.EqualError(t, err, "invalid format for the given Credential Manifest: invalid format "+
				"request: the Credential Application lists the following JWT algorithms: [EdDSA ES256K ES384]. "+
				"One or more of these are not in the Credential Manifest's supported JWT algorithms: []")
		})
		t.Run("Cred App requests JWT formats but the Cred Manifest's LDP format is nil", func(t *testing.T) {
			credentialApplication := makeCredentialApplicationFromBytes(t, credentialApplicationUniversityDegreeWithFormat)

			credentialManifest := createCredentialManifestWithNilLDPFormat(t)

			err := credentialApplication.ValidateAgainstCredentialManifest(&credentialManifest)
			require.EqualError(t, err, "invalid format for the given Credential Manifest: invalid format "+
				"request: the Credential Application lists the following LDP proof types: [RsaSignature2018]. One "+
				"or more of these are not in the Credential Manifest's supported LDP proof types: []")
		})
		t.Run("Credential Application has a valid format", func(t *testing.T) {
			credentialApplication := makeCredentialApplicationFromBytes(t, credentialApplicationUniversityDegreeWithFormat)

			credentialManifest := makeCredentialManifestFromBytes(t, credentialManifestUniversityDegreeWithFormat)

			err := credentialApplication.ValidateAgainstCredentialManifest(&credentialManifest)
			require.NoError(t, err)
		})
	})
	t.Run("Credential App's manifest ID does not match the given Credential Manifest", func(t *testing.T) {
		credentialApplication := makeCredentialApplicationWithUnknownManifestID(t)

		credentialManifest := makeCredentialManifestFromBytes(t, credentialManifestUniversityDegree)

		err := credentialApplication.ValidateAgainstCredentialManifest(&credentialManifest)
		require.EqualError(t, err, "the Manifest ID of the Credential Application (SomeUnknownManifestID) "+
			"does not match the given Credential Manifest's ID (university_degree)")
	})
}

func TestPresentCredentialApplication(t *testing.T) {
	t.Run("Successes", func(t *testing.T) {
		testTable := map[string]struct {
			existingPresentation []byte
			credentialManifest   []byte
			expectedPresentation []byte
		}{
			"Without existing presentation, Credential Manifest has no Presentation Definition and no format": {
				existingPresentation: nil,
				credentialManifest:   credentialManifestDriversLicense,
				expectedPresentation: vpMinimalWithCredentialApplication,
			},
			"With existing presentation, Credential Manifest has no Presentation Definition and no format": {
				existingPresentation: vpWithPRCardVC,
				credentialManifest:   credentialManifestDriversLicense,
				expectedPresentation: vpWithPRCardVCAndCredentialApplication,
			},
			"Without existing presentation, Credential Manifest has a Presentation Definition but no format": {
				existingPresentation: nil,
				credentialManifest:   credentialManifestDriversLicenseWithPresentationDefinition,
				expectedPresentation: vpMinimalWithCredentialApplicationAndPresentationSubmission,
			},
			"With existing presentation, Credential Manifest has a Presentation Definition but no format": {
				existingPresentation: vpWithPRCardVC,
				credentialManifest:   credentialManifestDriversLicenseWithPresentationDefinition,
				expectedPresentation: vpWithPRCardVCAndCredentialApplicationAndPresentationSubmission,
			},
			"Without existing presentation, Credential Manifest has a Presentation Definition and format": {
				existingPresentation: nil,
				credentialManifest:   credentialManifestDriversLicenseWithPresentationDefinitionAndFormat,
				expectedPresentation: vpMinimalWithCredentialApplicationAndPresentationSubmissionAndFormat,
			},
			"With existing presentation, Credential Manifest has a Presentation Definition and format": {
				existingPresentation: vpWithPRCardVC,
				credentialManifest:   credentialManifestDriversLicenseWithPresentationDefinitionAndFormat,
				expectedPresentation: vpWithPRCardVCAndCredentialApplicationAndPresentationSubmissionAndFormat,
			},
			"With existing presentation that uses Presentation Exchange context, " +
				"Credential Manifest has no Presentation Definition and no format": {
				existingPresentation: vpWithPRCardVCUsingPresentationExchangeContext,
				credentialManifest:   credentialManifestDriversLicense,
				expectedPresentation: vpWithPRCardVCAndCredentialApplication,
			},
		}

		for testName, testData := range testTable {
			credentialManifest := makeCredentialManifestFromBytes(t, testData.credentialManifest)

			var option cm.PresentCredentialApplicationOpt

			if testData.existingPresentation != nil {
				existingPresentation := makePresentationFromBytes(t, testData.existingPresentation, testName)

				option = cm.WithExistingPresentationForPresentCredentialApplication(existingPresentation)
			}

			presentation, err := cm.PresentCredentialApplication(&credentialManifest, option)
			require.NoError(t, err, errorMessageTestNameFormat, testName)
			require.NotNil(t, presentation, errorMessageTestNameFormat, testName)

			reunmarshalledPresentation := marshalThenUnmarshalAgain(t, presentation, testName)

			expectedPresentation := makePresentationFromBytes(t, testData.expectedPresentation, testName)

			makeCredentialApplicationIDsTheSame(t, reunmarshalledPresentation, expectedPresentation, testName)
			makePresentationSubmissionIDsTheSame(reunmarshalledPresentation, expectedPresentation)

			require.True(t, reflect.DeepEqual(reunmarshalledPresentation, expectedPresentation), errorMessageTestNameFormat+
				" the presentation with a Credential Fulfillment added to it differs from what was expected", testName)
		}
	})
	t.Run("Nil Credential Manifest argument", func(t *testing.T) {
		presentation, err := cm.PresentCredentialApplication(nil)
		require.EqualError(t, err, "credential manifest argument cannot be nil")
		require.Nil(t, presentation)
	})
}

func makeCredentialApplicationIDsTheSame(t *testing.T, presentation1,
	presentation2 *verifiable.Presentation, testName string) {
	credentialApplicationFromPresentation1, ok :=
		presentation1.CustomFields["credential_application"].(map[string]interface{})
	require.True(t, ok, errorMessageTestNameFormat, testName)

	credentialApplicationFromPresentation2, ok :=
		presentation2.CustomFields["credential_application"].(map[string]interface{})
	require.True(t, ok, errorMessageTestNameFormat, testName)

	credentialApplicationFromPresentation2["id"] = credentialApplicationFromPresentation1["id"]
}

// If either presentation is missing a presentation_submission field, then this function returns without
// changing anything.
func makePresentationSubmissionIDsTheSame(presentation1, presentation2 *verifiable.Presentation) {
	credentialSubmissionFromPresentation1, ok :=
		presentation1.CustomFields["presentation_submission"].(map[string]interface{})
	if !ok {
		return
	}

	credentialSubmissionFromPresentation2, ok :=
		presentation2.CustomFields["presentation_submission"].(map[string]interface{})
	if !ok {
		return
	}

	credentialSubmissionFromPresentation2["id"] = credentialSubmissionFromPresentation1["id"]
}

func makeCredentialApplicationFromBytes(t *testing.T,
	credentialApplicationBytes []byte) cm.CredentialApplication {
	var credentialApplication cm.CredentialApplication

	err := json.Unmarshal(credentialApplicationBytes, &credentialApplication)
	require.NoError(t, err)

	return credentialApplication
}

func makeCredentialApplicationWithMissingID(t *testing.T) []byte {
	credentialApplication := makeCredentialApplicationFromBytes(t, credentialApplicationUniversityDegree)

	credentialApplication.ID = ""

	credentialApplicationBytes, err := json.Marshal(credentialApplication)
	require.NoError(t, err)

	return credentialApplicationBytes
}

func makeCredentialApplicationWithMissingManifestID(t *testing.T) []byte {
	credentialApplication := makeCredentialApplicationFromBytes(t, credentialApplicationUniversityDegree)

	credentialApplication.ManifestID = ""

	credentialApplicationBytes, err := json.Marshal(credentialApplication)
	require.NoError(t, err)

	return credentialApplicationBytes
}

func makeCredentialApplicationWithUnknownJWTAlg(t *testing.T) cm.CredentialApplication {
	credentialApplication := makeCredentialApplicationFromBytes(t, credentialApplicationUniversityDegreeWithFormat)

	credentialApplication.Format.Jwt.Alg[0] = unknownFormatName

	return credentialApplication
}

func makeCredentialApplicationWithUnknownJWTVCAlg(t *testing.T) cm.CredentialApplication {
	credentialApplication := makeCredentialApplicationFromBytes(t, credentialApplicationUniversityDegreeWithFormat)

	credentialApplication.Format.JwtVC.Alg[0] = unknownFormatName

	return credentialApplication
}

func makeCredentialApplicationWithUnknownJWTVPAlg(t *testing.T) cm.CredentialApplication {
	credentialApplication := makeCredentialApplicationFromBytes(t, credentialApplicationUniversityDegreeWithFormat)

	credentialApplication.Format.JwtVP.Alg[0] = unknownFormatName

	return credentialApplication
}

func makeCredentialApplicationWithUnknownLDPProofType(t *testing.T) cm.CredentialApplication {
	credentialApplication := makeCredentialApplicationFromBytes(t, credentialApplicationUniversityDegreeWithFormat)

	credentialApplication.Format.Ldp.ProofType[0] = unknownFormatName

	return credentialApplication
}

func makeCredentialApplicationWithUnknownLDPVCProofType(t *testing.T) cm.CredentialApplication {
	credentialApplication := makeCredentialApplicationFromBytes(t, credentialApplicationUniversityDegreeWithFormat)

	credentialApplication.Format.LdpVC.ProofType[0] = unknownFormatName

	return credentialApplication
}

func makeCredentialApplicationWithUnknownLDPVPProofType(t *testing.T) cm.CredentialApplication {
	credentialApplication := makeCredentialApplicationFromBytes(t, credentialApplicationUniversityDegreeWithFormat)

	credentialApplication.Format.LdpVP.ProofType[0] = unknownFormatName

	return credentialApplication
}

func makeCredentialApplicationWithUnknownManifestID(t *testing.T) cm.CredentialApplication {
	credentialApplication := makeCredentialApplicationFromBytes(t, credentialApplicationUniversityDegreeWithFormat)

	credentialApplication.ManifestID = "SomeUnknownManifestID"

	return credentialApplication
}

func makeAttachmentFromBytes(t *testing.T) *decorator.GenericAttachment {
	var attachment decorator.GenericAttachment

	err := json.Unmarshal(credentialApplicationAttachmentDriversLicense, &attachment)
	require.NoError(t, err)

	return &attachment
}

func makeAttachmentWithoutCredentialApplicationField(t *testing.T) *decorator.GenericAttachment {
	attachment := makeAttachmentFromBytes(t)

	return removeCredentialApplicationFieldFromAttachment(t, attachment)
}

func removeCredentialApplicationFieldFromAttachment(t *testing.T,
	credentialApplicationAttachment *decorator.GenericAttachment) *decorator.GenericAttachment {
	attachmentAsMap, ok := credentialApplicationAttachment.Data.JSON.(map[string]interface{})
	require.True(t, ok, "couldn't assert attachment data as a map")

	delete(attachmentAsMap, "credential_application")

	return credentialApplicationAttachment
}

func makeAttachmentWithUnexpectedDataJSONType(t *testing.T) *decorator.GenericAttachment {
	attachment := makeAttachmentFromBytes(t)

	attachment.Data.JSON = "Not a map"

	return attachment
}

func makeAttachmentWithInvalidCredentialApplication(t *testing.T) *decorator.GenericAttachment {
	attachment := makeAttachmentFromBytes(t)

	credentialApplication := makeCredentialApplicationWithUnknownManifestID(t)

	attachmentAsMap, ok := attachment.Data.JSON.(map[string]interface{})
	require.True(t, ok, "couldn't assert attachment data as a map")

	attachmentAsMap["credential_application"] = credentialApplication

	return attachment
}

func makeAttachmentWithUnmarshallableCredentialAttachment(t *testing.T) *decorator.GenericAttachment {
	attachment := makeAttachmentFromBytes(t)

	attachmentAsMap, ok := attachment.Data.JSON.(map[string]interface{})
	require.True(t, ok, "couldn't assert attachment data as a map")

	attachmentAsMap["credential_application"] = func() {}

	return attachment
}

func makeAttachmentWithoutPresentationSubmission(t *testing.T) *decorator.GenericAttachment {
	attachment := makeAttachmentFromBytes(t)

	return removePresentationSubmissionFieldFromAttachment(t, attachment)
}

func removePresentationSubmissionFieldFromAttachment(t *testing.T,
	credentialApplicationAttachment *decorator.GenericAttachment) *decorator.GenericAttachment {
	attachmentAsMap, ok := credentialApplicationAttachment.Data.JSON.(map[string]interface{})
	require.True(t, ok, "couldn't assert attachment data as a map")

	delete(attachmentAsMap, "presentation_submission")

	return credentialApplicationAttachment
}

func makeAttachmentWithPresentationSubmissionWithIncorrectDefinitionID(t *testing.T) *decorator.GenericAttachment {
	attachment := makeAttachmentFromBytes(t)

	attachmentAsMap, ok := attachment.Data.JSON.(map[string]interface{})
	require.True(t, ok, "couldn't assert attachment data as a map")

	presentationSubmission := getPresentationSubmissionFromAttachmentData(t, attachmentAsMap)

	presentationSubmission.DefinitionID = "UnknownID"

	attachmentAsMap["presentation_submission"] = presentationSubmission

	return attachment
}

func makeAttachmentWithPresentationSubmissionWithIncorrectNumberOfDescriptors(
	t *testing.T) *decorator.GenericAttachment {
	attachment := makeAttachmentFromBytes(t)

	attachmentAsMap, ok := attachment.Data.JSON.(map[string]interface{})
	require.True(t, ok, "couldn't assert attachment data as a map")

	presentationSubmission := getPresentationSubmissionFromAttachmentData(t, attachmentAsMap)

	presentationSubmission.DescriptorMap = make([]*presexch.InputDescriptorMapping, 2)

	attachmentAsMap["presentation_submission"] = presentationSubmission

	return attachment
}

func makeAttachmentWithPresentationSubmissionWithIncorrectDescriptorID(
	t *testing.T) *decorator.GenericAttachment {
	attachment := makeAttachmentFromBytes(t)

	attachmentAsMap, ok := attachment.Data.JSON.(map[string]interface{})
	require.True(t, ok, "couldn't assert attachment data as a map")

	presentationSubmission := getPresentationSubmissionFromAttachmentData(t, attachmentAsMap)

	presentationSubmission.DescriptorMap[0].ID = "WrongID"

	attachmentAsMap["presentation_submission"] = presentationSubmission

	return attachment
}

func getPresentationSubmissionFromAttachmentData(t *testing.T,
	attachmentAsMap map[string]interface{}) presexch.PresentationSubmission {
	presentationSubmissionRaw, ok := attachmentAsMap["presentation_submission"]
	require.True(t, ok, "presentation_submission missing from attachment")

	presentationSubmissionBytes, err := json.Marshal(presentationSubmissionRaw)
	require.NoError(t, err)

	var presentationSubmission presexch.PresentationSubmission

	err = json.Unmarshal(presentationSubmissionBytes, &presentationSubmission)
	require.NoError(t, err)

	return presentationSubmission
}
