/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cm_test

import (
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/cm"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/internal/ldtestutil"
)

var (
	//go:embed testdata/valid_credential_manifest.json
	validCredentialManifest []byte //nolint:gochecknoglobals
	//go:embed testdata/valid_credential_manifest_with_format.json
	validCredentialManifestWithFormat []byte //nolint:gochecknoglobals
	//go:embed testdata/valid_credential_manifest_with_presentation_definition.json
	validCredentialManifestWithPresentationSubmission []byte //nolint:gochecknoglobals
	//go:embed testdata/valid_credential.jsonld
	validVC []byte //nolint:gochecknoglobals
)

const invalidJSONPath = "%InvalidJSONPath"

func TestCredentialManifest_Unmarshal(t *testing.T) {
	t.Run("Valid Credential Manifest", func(t *testing.T) {
		t.Run("Without format or Presentation Submission", func(t *testing.T) {
			makeCredentialManifestFromBytes(t, validCredentialManifest)
		})
		t.Run("With format", func(t *testing.T) {
			makeCredentialManifestFromBytes(t, validCredentialManifestWithFormat)
		})
		t.Run("With Presentation Submission", func(t *testing.T) {
			makeCredentialManifestFromBytes(t, validCredentialManifestWithPresentationSubmission)
		})
	})
	t.Run("Missing issuer ID", func(t *testing.T) {
		credentialManifest := makeCredentialManifestFromBytes(t, validCredentialManifest)

		credentialManifest.Issuer.ID = ""

		invalidCredentialManifest, err := json.Marshal(credentialManifest)
		require.NoError(t, err)

		err = json.Unmarshal(invalidCredentialManifest, &credentialManifest)
		require.EqualError(t, err, "invalid credential manifest: issuer ID missing")
	})
	t.Run("No output descriptors", func(t *testing.T) {
		credentialManifest := makeCredentialManifestFromBytes(t, validCredentialManifest)

		credentialManifest.OutputDescriptors = nil

		invalidCredentialManifest, err := json.Marshal(credentialManifest)
		require.NoError(t, err)

		err = json.Unmarshal(invalidCredentialManifest, &credentialManifest)
		require.EqualError(t, err, "invalid credential manifest: no output descriptors found")
	})
	t.Run("Output descriptor missing ID", func(t *testing.T) {
		credentialManifest := makeCredentialManifestFromBytes(t, validCredentialManifest)

		credentialManifest.OutputDescriptors[0].ID = ""

		invalidCredentialManifest, err := json.Marshal(credentialManifest)
		require.NoError(t, err)

		err = json.Unmarshal(invalidCredentialManifest, &credentialManifest)
		require.EqualError(t, err, "invalid credential manifest: missing ID for output descriptor at index 0")
	})
	t.Run("Duplicate output descriptor IDs", func(t *testing.T) {
		credentialManifest := makeCredentialManifestFromBytes(t, validCredentialManifest)

		credentialManifest.OutputDescriptors =
			append(credentialManifest.OutputDescriptors,
				cm.OutputDescriptor{ID: credentialManifest.OutputDescriptors[0].ID})

		invalidCredentialManifest, err := json.Marshal(credentialManifest)
		require.NoError(t, err)

		err = json.Unmarshal(invalidCredentialManifest, &credentialManifest)
		require.EqualError(t, err, "invalid credential manifest: the ID bachelors_degree appears "+
			"in multiple output descriptors")
	})
	t.Run("Missing schema for output descriptor", func(t *testing.T) {
		credentialManifest := makeCredentialManifestFromBytes(t, validCredentialManifest)

		credentialManifest.OutputDescriptors[0].Schema = ""

		invalidCredentialManifest, err := json.Marshal(credentialManifest)
		require.NoError(t, err)

		err = json.Unmarshal(invalidCredentialManifest, &credentialManifest)
		require.EqualError(t, err, "invalid credential manifest: missing schema for "+
			"output descriptor at index 0")
	})
	t.Run("Invalid JSONPath", func(t *testing.T) {
		t.Run("Display title", func(t *testing.T) {
			var credentialManifest cm.CredentialManifest

			err := json.Unmarshal(createMarshalledCredentialManifestWithInvalidTitleJSONPath(t), &credentialManifest)
			require.EqualError(t, err, "invalid credential manifest: display title for output descriptor "+
				`at index 0 is invalid: path "%InvalidJSONPath" at index 0 is not a valid JSONPath: parsing error: `+
				`%InvalidJSONPath	:1:1 - 1:2 unexpected "%" while scanning extensions`)
		})
		t.Run("Display subtitle", func(t *testing.T) {
			var credentialManifest cm.CredentialManifest

			err := json.Unmarshal(createMarshalledCredentialManifestWithInvalidSubtitleJSONPath(t), &credentialManifest)
			require.EqualError(t, err, "invalid credential manifest: display subtitle for output descriptor "+
				`at index 0 is invalid: path "%InvalidJSONPath" at index 0 is not a valid JSONPath: parsing error: `+
				`%InvalidJSONPath	:1:1 - 1:2 unexpected "%" while scanning extensions`)
		})
		t.Run("Display description", func(t *testing.T) {
			var credentialManifest cm.CredentialManifest

			err := json.Unmarshal(createMarshalledCredentialManifestWithInvalidDescriptionJSONPath(t), &credentialManifest)
			require.EqualError(t, err, "invalid credential manifest: display description for output "+
				`descriptor at index 0 is invalid: path "%InvalidJSONPath" at index 0 is not a valid JSONPath: `+
				`parsing error: %InvalidJSONPath	:1:1 - 1:2 unexpected "%" while scanning extensions`)
		})
		t.Run("Display property", func(t *testing.T) {
			var credentialManifest cm.CredentialManifest

			err := json.Unmarshal(createMarshalledCredentialManifestWithInvalidPropertyJSONPath(t), &credentialManifest)
			require.EqualError(t, err, "invalid credential manifest: display property at index 0 for output "+
				`descriptor at index 0 is invalid: path "%InvalidJSONPath" at index 0 is not a valid JSONPath: `+
				`parsing error: %InvalidJSONPath	:1:1 - 1:2 unexpected "%" while scanning extensions`)
		})
	})
	t.Run("Invalid schema type", func(t *testing.T) {
		var credentialManifest cm.CredentialManifest

		err := json.Unmarshal(createMarshalledCredentialManifestWithInvalidSchemaType(t), &credentialManifest)
		require.EqualError(t, err, "invalid credential manifest: display title for output descriptor at "+
			"index 0 is invalid: InvalidSchemaType is not a valid schema type")
	})
	t.Run("Invalid schema format", func(t *testing.T) {
		var credentialManifest cm.CredentialManifest

		err := json.Unmarshal(createMarshalledCredentialManifestWithInvalidSchemaFormat(t), &credentialManifest)
		require.EqualError(t, err, "invalid credential manifest: display title for output descriptor at "+
			"index 0 is invalid: UnknownFormat is not a valid string schema format")
	})
}

func TestCredentialManifest_ResolveOutputDescriptors(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		t.Run("All descriptors resolved without needing to use fallbacks", func(t *testing.T) {
			var credentialManifest cm.CredentialManifest

			err := json.Unmarshal(validCredentialManifest, &credentialManifest)
			require.NoError(t, err)

			vc := parseTestCredential(t, validVC)

			resolvedDataDisplayDescriptors, err := credentialManifest.ResolveOutputDescriptors(vc)
			require.NoError(t, err)

			require.Len(t, resolvedDataDisplayDescriptors, 1)
			require.Equal(t, "Bachelor of Applied Science", resolvedDataDisplayDescriptors[0].Title)
			require.Equal(t, "Electrical Systems Specialty", resolvedDataDisplayDescriptors[0].Subtitle)
			require.Equal(t, "Awarded for completing a four year program at Example University.",
				resolvedDataDisplayDescriptors[0].Description)
			require.Equal(t, resolvedDataDisplayDescriptors[0].Properties[0], true)
			require.Equal(t, resolvedDataDisplayDescriptors[0].Properties[1], float64(4))
		})
		t.Run("Fallbacks used for some descriptors", func(t *testing.T) {
			var credentialManifest cm.CredentialManifest

			err := json.Unmarshal(validCredentialManifest, &credentialManifest)
			require.NoError(t, err)

			vc := parseTestCredential(t, createValidVCMissingSomeFields(t))

			resolvedDataDisplayDescriptors, err :=
				credentialManifest.ResolveOutputDescriptors(vc)
			require.NoError(t, err)

			require.Len(t, resolvedDataDisplayDescriptors, 1)
			require.Equal(t, "Bachelor of Applied Science", resolvedDataDisplayDescriptors[0].Title)
			// For the subtitle, the fallback is simply a blank string.
			require.Equal(t, "", resolvedDataDisplayDescriptors[0].Subtitle)
			require.Equal(t, "Awarded for completing a four year program at Example University.",
				resolvedDataDisplayDescriptors[0].Description)
			// For the "with distinction" property, the fallback is more specifically listed as "unknown".
			require.Equal(t, resolvedDataDisplayDescriptors[0].Properties[0], "Unknown")
			require.Equal(t, resolvedDataDisplayDescriptors[0].Properties[1], float64(4))
		})
	})
	t.Run("Fail to resolve title display mapping object", func(t *testing.T) {
		credentialManifest := createCredentialManifestWithInvalidTitleJSONPath(t)

		vc := parseTestCredential(t, validVC)

		resolvedDataDisplayDescriptors, err := credentialManifest.ResolveOutputDescriptors(vc)
		require.EqualError(t, err, "failed to resolve output descriptors at index 0: failed to resolve "+
			`title display mapping object: parsing error: %InvalidJSONPath	:1:1 - 1:2 unexpected "%" while `+
			"scanning extensions")
		require.Nil(t, resolvedDataDisplayDescriptors)
	})
	t.Run("Fail to resolve display mapping object", func(t *testing.T) {
		vc := parseTestCredential(t, validVC)

		t.Run("Display title", func(t *testing.T) {
			credentialManifest := createCredentialManifestWithInvalidTitleJSONPath(t)

			resolvedDataDisplayDescriptors, err := credentialManifest.ResolveOutputDescriptors(vc)
			require.EqualError(t, err, "failed to resolve output descriptors at index 0: failed to resolve "+
				`title display mapping object: parsing error: %InvalidJSONPath	:1:1 - 1:2 unexpected "%" while `+
				"scanning extensions")
			require.Nil(t, resolvedDataDisplayDescriptors)
		})
		t.Run("Display subtitle", func(t *testing.T) {
			credentialManifest := createCredentialManifestWithInvalidSubtitleJSONPath(t)

			resolvedDataDisplayDescriptors, err := credentialManifest.ResolveOutputDescriptors(vc)
			require.EqualError(t, err, "failed to resolve output descriptors at index 0: failed to resolve "+
				`subtitle display mapping object: parsing error: %InvalidJSONPath	:1:1 - 1:2 unexpected "%" while `+
				"scanning extensions")
			require.Nil(t, resolvedDataDisplayDescriptors)
		})
		t.Run("Display description", func(t *testing.T) {
			credentialManifest := createCredentialManifestWithInvalidDescriptionJSONPath(t)

			resolvedDataDisplayDescriptors, err := credentialManifest.ResolveOutputDescriptors(vc)
			require.EqualError(t, err, "failed to resolve output descriptors at index 0: failed to resolve "+
				`description display mapping object: parsing error: %InvalidJSONPath	:1:1 - 1:2 unexpected "%" `+
				"while scanning extensions")
			require.Nil(t, resolvedDataDisplayDescriptors)
		})
		t.Run("Display property", func(t *testing.T) {
			credentialManifest := createCredentialManifestWithInvalidPropertyJSONPath(t)

			resolvedDataDisplayDescriptors, err := credentialManifest.ResolveOutputDescriptors(vc)
			require.EqualError(t, err, "failed to resolve output descriptors at index 0: failed to resolve "+
				`the display mapping object for the property at index 0: parsing error: %InvalidJSONPath	:1:1 - `+
				`1:2 unexpected "%" while scanning extensions`)
			require.Nil(t, resolvedDataDisplayDescriptors)
		})
	})
}

func createMarshalledCredentialManifestWithInvalidTitleJSONPath(t *testing.T) []byte {
	credentialManifest := createCredentialManifestWithInvalidTitleJSONPath(t)

	credentialManifestWithInvalidJSONPathBytes, err := json.Marshal(credentialManifest)
	require.NoError(t, err)

	return credentialManifestWithInvalidJSONPathBytes
}

func createCredentialManifestWithInvalidTitleJSONPath(t *testing.T) cm.CredentialManifest {
	credentialManifest := makeCredentialManifestFromBytes(t, validCredentialManifest)

	credentialManifest.OutputDescriptors[0].Display.Title.Paths[0] = invalidJSONPath

	return credentialManifest
}

func createMarshalledCredentialManifestWithInvalidSubtitleJSONPath(t *testing.T) []byte {
	credentialManifest := createCredentialManifestWithInvalidSubtitleJSONPath(t)

	credentialManifestWithInvalidJSONPathBytes, err := json.Marshal(credentialManifest)
	require.NoError(t, err)

	return credentialManifestWithInvalidJSONPathBytes
}

func createCredentialManifestWithInvalidSubtitleJSONPath(t *testing.T) cm.CredentialManifest {
	credentialManifest := makeCredentialManifestFromBytes(t, validCredentialManifest)

	credentialManifest.OutputDescriptors[0].Display.Subtitle.Paths[0] = invalidJSONPath

	return credentialManifest
}

func createMarshalledCredentialManifestWithInvalidDescriptionJSONPath(t *testing.T) []byte {
	credentialManifest := createCredentialManifestWithInvalidDescriptionJSONPath(t)

	credentialManifestWithInvalidJSONPathBytes, err := json.Marshal(credentialManifest)
	require.NoError(t, err)

	return credentialManifestWithInvalidJSONPathBytes
}

func createCredentialManifestWithInvalidDescriptionJSONPath(t *testing.T) cm.CredentialManifest {
	credentialManifest := makeCredentialManifestFromBytes(t, validCredentialManifest)

	credentialManifest.OutputDescriptors[0].Display.Description.Paths = []string{invalidJSONPath}

	return credentialManifest
}

func createMarshalledCredentialManifestWithInvalidPropertyJSONPath(t *testing.T) []byte {
	credentialManifest := createCredentialManifestWithInvalidPropertyJSONPath(t)

	credentialManifestWithInvalidJSONPathBytes, err := json.Marshal(credentialManifest)
	require.NoError(t, err)

	return credentialManifestWithInvalidJSONPathBytes
}

func createCredentialManifestWithInvalidPropertyJSONPath(t *testing.T) cm.CredentialManifest {
	credentialManifest := makeCredentialManifestFromBytes(t, validCredentialManifest)

	credentialManifest.OutputDescriptors[0].Display.Properties[0].Paths[0] = invalidJSONPath

	return credentialManifest
}

func createMarshalledCredentialManifestWithInvalidSchemaType(t *testing.T) []byte {
	credentialManifest := createCredentialManifestWithInvalidSchemaType(t)

	credentialManifestWithInvalidJSONPathBytes, err := json.Marshal(credentialManifest)
	require.NoError(t, err)

	return credentialManifestWithInvalidJSONPathBytes
}

func createCredentialManifestWithInvalidSchemaType(t *testing.T) cm.CredentialManifest {
	credentialManifest := makeCredentialManifestFromBytes(t, validCredentialManifest)

	credentialManifest.OutputDescriptors[0].Display.Title.Schema.Type = "InvalidSchemaType"

	return credentialManifest
}

func createMarshalledCredentialManifestWithInvalidSchemaFormat(t *testing.T) []byte {
	credentialManifest := createCredentialManifestWithInvalidSchemaFormat(t)

	credentialManifestWithInvalidJSONPathBytes, err := json.Marshal(credentialManifest)
	require.NoError(t, err)

	return credentialManifestWithInvalidJSONPathBytes
}

func createCredentialManifestWithInvalidSchemaFormat(t *testing.T) cm.CredentialManifest {
	credentialManifest := makeCredentialManifestFromBytes(t, validCredentialManifest)

	credentialManifest.OutputDescriptors[0].Display.Title.Schema = cm.Schema{
		Type:   "string",
		Format: "UnknownFormat",
	}

	return credentialManifest
}

func createCredentialManifestWithNilJWTFormat(t *testing.T) cm.CredentialManifest {
	credentialManifest := makeCredentialManifestFromBytes(t, validCredentialManifestWithFormat)

	credentialManifest.Format.Jwt = nil

	return credentialManifest
}

func createCredentialManifestWithNilLDPFormat(t *testing.T) cm.CredentialManifest {
	credentialManifest := makeCredentialManifestFromBytes(t, validCredentialManifestWithFormat)

	credentialManifest.Format.Ldp = nil

	return credentialManifest
}

func makeCredentialManifestFromBytes(t *testing.T,
	credentialManifestBytes []byte) cm.CredentialManifest {
	var credentialManifest cm.CredentialManifest

	err := json.Unmarshal(credentialManifestBytes, &credentialManifest)
	require.NoError(t, err)

	return credentialManifest
}

func parseTestCredential(t *testing.T, vcData []byte) *verifiable.Credential {
	t.Helper()

	vc, err := verifiable.ParseCredential(vcData, verifiable.WithJSONLDDocumentLoader(createTestDocumentLoader(t)))
	require.NoError(t, err)

	return vc
}

func createTestDocumentLoader(t *testing.T) *ld.DocumentLoader {
	t.Helper()

	loader, err := ldtestutil.DocumentLoader()
	require.NoError(t, err)

	return loader
}

// Two of the fields that JSONPaths in the valid credential manifest point to are deleted here.
func createValidVCMissingSomeFields(t *testing.T) []byte {
	vcUnmarshalledIntoMap := map[string]interface{}{}

	err := json.Unmarshal(validVC, &vcUnmarshalledIntoMap)
	require.NoError(t, err)

	delete(vcUnmarshalledIntoMap, "minor")
	delete(vcUnmarshalledIntoMap, "withDistinction")

	vcMissingSomeFieldsBytes, err := json.Marshal(vcUnmarshalledIntoMap)
	require.NoError(t, err)

	return vcMissingSomeFieldsBytes
}
