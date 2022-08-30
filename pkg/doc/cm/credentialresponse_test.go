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

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/doc/cm"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

var (
	//go:embed testdata/credential_response_university_degree.json
	validCredentialResponse []byte //nolint:gochecknoglobals
	//go:embed testdata/issue_credential_message_university_degree.json
	validIssueCredentialMessage []byte //nolint:gochecknoglobals
	//go:embed testdata/VP_with_drivers_license_VC.json
	vpWithDriversLicenseVC []byte //nolint:gochecknoglobals
	//go:embed testdata/VP_with_drivers_license_VC_and_credential_response.json
	vpWithDriversLicenseVCAndCredentialResponse []byte //nolint:gochecknoglobals
	// The "minimal" VP below is ones that was created by a call to verifiable.NewPresentation() with no
	// arguments/options, which is how the cm.PresentCredentialResponse method generates a VP if the
	// WithExistingPresentationForPresentCredentialResponse option is not used.
	//go:embed testdata/VP_minimal_with_credential_response.json
	vpMinimalWithCredentialResponse []byte //nolint:gochecknoglobals
	//go:embed testdata/VP_with_multiple_VCs_and_credential_response.json
	vpMultipleWithCredentialResponse []byte //nolint:gochecknoglobals
)

func TestCredentialResponse_Unmarshal(t *testing.T) {
	t.Run("Valid Credential Response", func(t *testing.T) {
		makeValidCredentialResponse(t)
	})
	t.Run("Missing ID", func(t *testing.T) {
		credentialResponseBytes := makeCredentialResponseWithMissingID(t)

		var credentialResponse cm.CredentialResponse

		err := json.Unmarshal(credentialResponseBytes, &credentialResponse)
		require.EqualError(t, err, "invalid Credential Response: missing ID")
	})
	t.Run("Missing Manifest ID", func(t *testing.T) {
		credentialResponseBytes := makeCredentialResponseWithMissingManifestID(t)

		var credentialResponse cm.CredentialResponse

		err := json.Unmarshal(credentialResponseBytes, &credentialResponse)
		require.EqualError(t, err, "invalid Credential Response: missing manifest ID")
	})
}

func TestCredentialResponse_ResolveDescriptorMap(t *testing.T) {
	testDocumentLoaderOption := verifiable.WithJSONLDDocumentLoader(createTestDocumentLoader(t))

	t.Run("Success", func(t *testing.T) {
		credentialResponse := makeValidCredentialResponse(t)
		issueCredentialMessage := makeValidIssueCredentialMessage(t)

		verifiableCredentials, err := credentialResponse.ResolveDescriptorMaps(
			issueCredentialMessage.Attachments[0].Data.JSON, testDocumentLoaderOption)
		require.NoError(t, err)
		require.Len(t, verifiableCredentials, 1)

		originalVC := getVCFromValidIssueCredentialMessage(t)

		require.True(t, reflect.DeepEqual(verifiableCredentials[0], originalVC),
			"resolved VC differs from the original VC")
	})
	t.Run("Invalid JSONPath", func(t *testing.T) {
		credentialResponse := makeCredentialResponseWithInvalidJSONPath(t)
		issueCredentialMessage := makeValidIssueCredentialMessage(t)

		verifiableCredentials, err := credentialResponse.ResolveDescriptorMaps(
			issueCredentialMessage.Attachments[0].Data.JSON, testDocumentLoaderOption)
		require.EqualError(t, err, "failed to resolve descriptor map at index 0: parsing error: "+
			`%InvalidJSONPath	:1:1 - 1:2 unexpected "%" while scanning extensions`)
		require.Nil(t, verifiableCredentials)
	})
	t.Run("JSON data is not a map[string]interface{}", func(t *testing.T) {
		credentialResponse := makeValidCredentialResponse(t)

		verifiableCredentials, err := credentialResponse.ResolveDescriptorMaps(1)
		require.EqualError(t, err, "the given JSON data could not be asserted as a map[string]interface{}")
		require.Nil(t, verifiableCredentials)
	})
	t.Run("Failed to parse VC", func(t *testing.T) {
		credentialResponse := makeValidCredentialResponse(t)
		issueCredentialMessage := makeIssueCredentialMessageWithInvalidVC(t)

		verifiableCredentials, err := credentialResponse.ResolveDescriptorMaps(
			issueCredentialMessage.Attachments[0].Data.JSON)
		require.EqualError(t, err, "failed to resolve descriptor map at index 0: failed to parse "+
			"credential: decode new credential: embedded proof is not JSON: json: cannot unmarshal string "+
			"into Go value of type map[string]interface {}")
		require.Nil(t, verifiableCredentials)
	})
}

func TestPresentCredentialResponse(t *testing.T) {
	t.Run("Without using WithExistingPresentationForPresentCredentialResponse option", func(t *testing.T) {
		credentialManifest := makeCredentialManifestFromBytes(t, credentialManifestDriversLicenseWithPresentationDefinition)

		presentation, err := cm.PresentCredentialResponse(&credentialManifest)
		require.NoError(t, err)
		require.NotNil(t, presentation)

		expectedPresentation := makePresentationFromBytes(t, vpMinimalWithCredentialResponse,
			"Present Credential Response without existing Presentation")

		reunmarshalledPresentation := marshalThenUnmarshalAgain(t, presentation,
			"Present Credential Response without existing presentation")

		makeCredentialResponseIDsTheSame(t, reunmarshalledPresentation, expectedPresentation)
		require.True(t, reflect.DeepEqual(reunmarshalledPresentation, expectedPresentation),
			"the presentation with a Credential Response added to it differs from what was expected")
	})
	t.Run("Using WithExistingPresentationForPresentCredentialResponse option", func(t *testing.T) {
		t.Run("CustomFields is not nil", func(t *testing.T) {
			testName := "Present Credential Response with existing presentation, CustomFields is not nil"

			presentation := makePresentationFromBytes(t, vpWithDriversLicenseVC, testName)

			doPresentCredentialResponseTestWithExistingPresentation(t, presentation, testName)
		})
		t.Run("CustomFields is nil", func(t *testing.T) {
			testName := "Present Credential Response with existing presentation, CustomFields is nil"

			presentation := makePresentationFromBytes(t, vpWithDriversLicenseVC, testName)

			presentation.CustomFields = nil

			doPresentCredentialResponseTestWithExistingPresentation(t, presentation, testName)
		})
	})
}

func doPresentCredentialResponseTestWithExistingPresentation(t *testing.T,
	presentationToAddCredentialResponseTo *verifiable.Presentation, testName string) {
	credentialManifest := makeCredentialManifestFromBytes(t, credentialManifestDriversLicenseWithPresentationDefinition)

	presentationWithAddedCredentialResponse, err := cm.PresentCredentialResponse(&credentialManifest,
		cm.WithExistingPresentationForPresentCredentialResponse(presentationToAddCredentialResponseTo))
	require.NoError(t, err)

	expectedPresentation := makePresentationFromBytes(t, vpWithDriversLicenseVCAndCredentialResponse, testName)

	reunmarshalledPresentation := marshalThenUnmarshalAgain(t, presentationWithAddedCredentialResponse, testName)

	makeCredentialResponseIDsTheSame(t, reunmarshalledPresentation, expectedPresentation)

	require.True(t, reflect.DeepEqual(reunmarshalledPresentation, expectedPresentation),
		"the presentation with a Credential Response added to it differs from what was expected")
}

// The credential Response ID is randomly generated in the PresentCredentialResponse method, so this method
// is useful for allowing two presentations created by that method to be compared using reflect.DeepEqual.
func makeCredentialResponseIDsTheSame(t *testing.T, presentation1,
	presentation2 *verifiable.Presentation) {
	credentialResponseFromPresentation1, ok :=
		presentation1.CustomFields["credential_response"].(map[string]interface{})
	require.True(t, ok)

	credentialResponseFromPresentation2, ok :=
		presentation2.CustomFields["credential_response"].(map[string]interface{})
	require.True(t, ok)

	credentialResponseFromPresentation2["id"] = credentialResponseFromPresentation1["id"]
}

func makeValidCredentialResponse(t *testing.T) cm.CredentialResponse {
	var credentialResponse cm.CredentialResponse

	err := json.Unmarshal(validCredentialResponse, &credentialResponse)
	require.NoError(t, err)

	return credentialResponse
}

func makeValidIssueCredentialMessage(t *testing.T) issuecredential.IssueCredentialV3 {
	var issueCredentialMessage issuecredential.IssueCredentialV3

	err := json.Unmarshal(validIssueCredentialMessage, &issueCredentialMessage)
	require.NoError(t, err)

	return issueCredentialMessage
}

func getVCFromValidIssueCredentialMessage(t *testing.T) verifiable.Credential {
	issueCredentialMessage := makeValidIssueCredentialMessage(t)

	jsonAttachmentAsMap, ok := issueCredentialMessage.Attachments[0].Data.JSON.(map[string]interface{})
	require.True(t, ok)

	verifiableCredentialsRaw := jsonAttachmentAsMap["verifiableCredential"]

	verifiableCredentialsAsArrayOfInterface, ok := verifiableCredentialsRaw.([]interface{})
	require.True(t, ok)

	vcBytes, err := json.Marshal(verifiableCredentialsAsArrayOfInterface[0])
	require.NoError(t, err)

	vc, err := verifiable.ParseCredential(vcBytes, verifiable.WithJSONLDDocumentLoader(createTestDocumentLoader(t)))
	require.NoError(t, err)

	return *vc
}

func makeCredentialResponseWithMissingID(t *testing.T) []byte {
	credentialResponse := makeValidCredentialResponse(t)

	credentialResponse.ID = ""

	credentialResponseBytes, err := json.Marshal(credentialResponse)
	require.NoError(t, err)

	return credentialResponseBytes
}

func makeCredentialResponseWithMissingManifestID(t *testing.T) []byte {
	credentialResponse := makeValidCredentialResponse(t)

	credentialResponse.ManifestID = ""

	credentialResponseBytes, err := json.Marshal(credentialResponse)
	require.NoError(t, err)

	return credentialResponseBytes
}

func makeCredentialResponseWithInvalidJSONPath(t *testing.T) cm.CredentialResponse {
	credentialResponse := makeValidCredentialResponse(t)

	credentialResponse.OutputDescriptorMappingObjects[0].Path = invalidJSONPath

	return credentialResponse
}

func makeIssueCredentialMessageWithInvalidVC(t *testing.T) issuecredential.IssueCredentialV3 {
	var issueCredentialMessage issuecredential.IssueCredentialV3

	err := json.Unmarshal(validIssueCredentialMessage, &issueCredentialMessage)
	require.NoError(t, err)

	jsonAttachmentAsMap, ok := issueCredentialMessage.Attachments[0].Data.JSON.(map[string]interface{})
	require.True(t, ok)

	jsonAttachmentAsMap["verifiableCredential"] = []interface{}{"NotAValidVC"}

	return issueCredentialMessage
}
