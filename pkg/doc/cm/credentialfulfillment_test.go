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
	//go:embed testdata/credential_fulfillment_university_degree.json
	validCredentialFulfillment []byte //nolint:gochecknoglobals
	//go:embed testdata/issue_credential_message_university_degree.json
	validIssueCredentialMessage []byte //nolint:gochecknoglobals
	//go:embed testdata/VP_with_drivers_license_VC.json
	vpWithDriversLicenseVC []byte //nolint:gochecknoglobals
	//go:embed testdata/VP_with_drivers_license_VC_and_credential_fulfillment.json
	vpWithDriversLicenseVCAndCredentialFulfillment []byte //nolint:gochecknoglobals
	// The "minimal" VP below is ones that was created by a call to verifiable.NewPresentation() with no
	// arguments/options, which is how the cm.PresentCredentialFulfillment method generates a VP if the
	// WithExistingPresentationForPresentCredentialFulfillment option is not used.
	//go:embed testdata/VP_minimal_with_credential_fulfillment.json
	vpMinimalWithCredentialFulfillment []byte //nolint:gochecknoglobals
	//go:embed testdata/VP_with_multiple_VCs_and_credential_fulfillment.json
	vpMultipleWithCredentialFulfillment []byte //nolint:gochecknoglobals
)

func TestCredentialFulfillment_Unmarshal(t *testing.T) {
	t.Run("Valid Credential Fulfillment", func(t *testing.T) {
		makeValidCredentialFulfillment(t)
	})
	t.Run("Missing ID", func(t *testing.T) {
		credentialFulfillmentBytes := makeCredentialFulfillmentWithMissingID(t)

		var credentialFulfillment cm.CredentialFulfillment

		err := json.Unmarshal(credentialFulfillmentBytes, &credentialFulfillment)
		require.EqualError(t, err, "invalid Credential Fulfillment: missing ID")
	})
	t.Run("Missing Manifest ID", func(t *testing.T) {
		credentialFulfillmentBytes := makeCredentialFulfillmentWithMissingManifestID(t)

		var credentialFulfillment cm.CredentialFulfillment

		err := json.Unmarshal(credentialFulfillmentBytes, &credentialFulfillment)
		require.EqualError(t, err, "invalid Credential Fulfillment: missing manifest ID")
	})
}

func TestCredentialFulfillment_ResolveDescriptorMap(t *testing.T) {
	testDocumentLoaderOption := verifiable.WithJSONLDDocumentLoader(createTestDocumentLoader(t))

	t.Run("Success", func(t *testing.T) {
		credentialFulfillment := makeValidCredentialFulfillment(t)
		issueCredentialMessage := makeValidIssueCredentialMessage(t)

		verifiableCredentials, err := credentialFulfillment.ResolveDescriptorMaps(
			issueCredentialMessage.Attachments[0].Data.JSON, testDocumentLoaderOption)
		require.NoError(t, err)
		require.Len(t, verifiableCredentials, 1)

		originalVC := getVCFromValidIssueCredentialMessage(t)

		require.True(t, reflect.DeepEqual(verifiableCredentials[0], originalVC),
			"resolved VC differs from the original VC")
	})
	t.Run("Invalid JSONPath", func(t *testing.T) {
		credentialFulfillment := makeCredentialFulfillmentWithInvalidJSONPath(t)
		issueCredentialMessage := makeValidIssueCredentialMessage(t)

		verifiableCredentials, err := credentialFulfillment.ResolveDescriptorMaps(
			issueCredentialMessage.Attachments[0].Data.JSON, testDocumentLoaderOption)
		require.EqualError(t, err, "failed to resolve descriptor map at index 0: parsing error: "+
			`%InvalidJSONPath	:1:1 - 1:2 unexpected "%" while scanning extensions`)
		require.Nil(t, verifiableCredentials)
	})
	t.Run("JSON data is not a map[string]interface{}", func(t *testing.T) {
		credentialFulfillment := makeValidCredentialFulfillment(t)

		verifiableCredentials, err := credentialFulfillment.ResolveDescriptorMaps(1)
		require.EqualError(t, err, "the given JSON data could not be asserted as a map[string]interface{}")
		require.Nil(t, verifiableCredentials)
	})
	t.Run("Failed to parse VC", func(t *testing.T) {
		credentialFulfillment := makeValidCredentialFulfillment(t)
		issueCredentialMessage := makeIssueCredentialMessageWithInvalidVC(t)

		verifiableCredentials, err := credentialFulfillment.ResolveDescriptorMaps(
			issueCredentialMessage.Attachments[0].Data.JSON)
		require.EqualError(t, err, "failed to resolve descriptor map at index 0: failed to parse "+
			"credential: decode new credential: embedded proof is not JSON: json: cannot unmarshal string "+
			"into Go value of type map[string]interface {}")
		require.Nil(t, verifiableCredentials)
	})
}

func TestPresentCredentialFulfillment(t *testing.T) {
	t.Run("Without using WithExistingPresentationForPresentCredentialFulfillment option", func(t *testing.T) {
		credentialManifest := makeCredentialManifestFromBytes(t, credentialManifestDriversLicenseWithPresentationDefinition)

		presentation, err := cm.PresentCredentialFulfillment(&credentialManifest)
		require.NoError(t, err)
		require.NotNil(t, presentation)

		expectedPresentation := makePresentationFromBytes(t, vpMinimalWithCredentialFulfillment,
			"Present Credential Fulfillment without existing Presentation")

		reunmarshalledPresentation := marshalThenUnmarshalAgain(t, presentation,
			"Present Credential Fulfillment without existing presentation")

		makeCredentialFulfillmentIDsTheSame(t, reunmarshalledPresentation, expectedPresentation)
		require.True(t, reflect.DeepEqual(reunmarshalledPresentation, expectedPresentation),
			"the presentation with a Credential Fulfillment added to it differs from what was expected")
	})
	t.Run("Using WithExistingPresentationForPresentCredentialFulfillment option", func(t *testing.T) {
		t.Run("CustomFields is not nil", func(t *testing.T) {
			testName := "Present Credential Fulfillment with existing presentation, CustomFields is not nil"

			presentation := makePresentationFromBytes(t, vpWithDriversLicenseVC, testName)

			doPresentCredentialFulfillmentTestWithExistingPresentation(t, presentation, testName)
		})
		t.Run("CustomFields is nil", func(t *testing.T) {
			testName := "Present Credential Fulfillment with existing presentation, CustomFields is nil"

			presentation := makePresentationFromBytes(t, vpWithDriversLicenseVC, testName)

			presentation.CustomFields = nil

			doPresentCredentialFulfillmentTestWithExistingPresentation(t, presentation, testName)
		})
	})
}

func doPresentCredentialFulfillmentTestWithExistingPresentation(t *testing.T,
	presentationToAddCredentialFulfillmentTo *verifiable.Presentation, testName string) {
	credentialManifest := makeCredentialManifestFromBytes(t, credentialManifestDriversLicenseWithPresentationDefinition)

	presentationWithAddedCredentialFulfillment, err := cm.PresentCredentialFulfillment(&credentialManifest,
		cm.WithExistingPresentationForPresentCredentialFulfillment(presentationToAddCredentialFulfillmentTo))
	require.NoError(t, err)

	expectedPresentation := makePresentationFromBytes(t, vpWithDriversLicenseVCAndCredentialFulfillment, testName)

	reunmarshalledPresentation := marshalThenUnmarshalAgain(t, presentationWithAddedCredentialFulfillment, testName)

	makeCredentialFulfillmentIDsTheSame(t, reunmarshalledPresentation, expectedPresentation)

	require.True(t, reflect.DeepEqual(reunmarshalledPresentation, expectedPresentation),
		"the presentation with a Credential Fulfillment added to it differs from what was expected")
}

// The credential Fulfillment ID is randomly generated in the PresentCredentialFulfillment method, so this method
// is useful for allowing two presentations created by that method to be compared using reflect.DeepEqual.
func makeCredentialFulfillmentIDsTheSame(t *testing.T, presentation1,
	presentation2 *verifiable.Presentation) {
	credentialFulfillmentFromPresentation1, ok :=
		presentation1.CustomFields["credential_fulfillment"].(map[string]interface{})
	require.True(t, ok)

	credentialFulfillmentFromPresentation2, ok :=
		presentation2.CustomFields["credential_fulfillment"].(map[string]interface{})
	require.True(t, ok)

	credentialFulfillmentFromPresentation2["id"] = credentialFulfillmentFromPresentation1["id"]
}

func makeValidCredentialFulfillment(t *testing.T) cm.CredentialFulfillment {
	var credentialFulfillment cm.CredentialFulfillment

	err := json.Unmarshal(validCredentialFulfillment, &credentialFulfillment)
	require.NoError(t, err)

	return credentialFulfillment
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

func makeCredentialFulfillmentWithMissingID(t *testing.T) []byte {
	credentialFulfillment := makeValidCredentialFulfillment(t)

	credentialFulfillment.ID = ""

	credentialFulfillmentBytes, err := json.Marshal(credentialFulfillment)
	require.NoError(t, err)

	return credentialFulfillmentBytes
}

func makeCredentialFulfillmentWithMissingManifestID(t *testing.T) []byte {
	credentialFulfillment := makeValidCredentialFulfillment(t)

	credentialFulfillment.ManifestID = ""

	credentialFulfillmentBytes, err := json.Marshal(credentialFulfillment)
	require.NoError(t, err)

	return credentialFulfillmentBytes
}

func makeCredentialFulfillmentWithInvalidJSONPath(t *testing.T) cm.CredentialFulfillment {
	credentialFulfillment := makeValidCredentialFulfillment(t)

	credentialFulfillment.OutputDescriptorMappingObjects[0].Path = invalidJSONPath

	return credentialFulfillment
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
