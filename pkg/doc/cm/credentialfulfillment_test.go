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
	//go:embed testdata/valid_credential_fulfillment.json
	validCredentialFulfillment []byte //nolint:gochecknoglobals
	//go:embed testdata/valid_issue_credential_message.json
	validIssueCredentialMessage []byte //nolint:gochecknoglobals
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
