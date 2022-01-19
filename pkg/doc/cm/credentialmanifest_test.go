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

// Sample Credential Manifests for a university degree.
var (
	//go:embed testdata/credential_manifest_university_degree.json
	credentialManifestUniversityDegree []byte //nolint:gochecknoglobals
	//go:embed testdata/credential_manifest_university_degree_with_format.json
	credentialManifestUniversityDegreeWithFormat []byte //nolint:gochecknoglobals
	//go:embed testdata/credential_manifest_university_degree_with_presentation_definition.json
	credentialManifestUniversityDegreeWithPresentationDefinition []byte //nolint:gochecknoglobals
)

// Sample Credential Manifests for a driver's license.
var (
	//go:embed testdata/credential_manifest_drivers_license.json
	credentialManifestDriversLicense []byte //nolint:gochecknoglobals
	//go:embed testdata/credential_manifest_drivers_license_with_presentation_definition.json
	credentialManifestDriversLicenseWithPresentationDefinition []byte //nolint:gochecknoglobals
	//go:embed testdata/credential_manifest_drivers_license_with_presentation_definition_and_format.json
	credentialManifestDriversLicenseWithPresentationDefinitionAndFormat []byte //nolint:gochecknoglobals
)

// Sample verifiable credential for a university degree.
var (
	//go:embed testdata/credential_university_degree.jsonld
	validVC []byte // nolint:gochecknoglobals
)

// miscellaneous samples.
var (
	//go:embed testdata/credential_manifest_multiple_vcs.json
	credentialManifestMultipleVCs []byte // nolint:gochecknoglobals
)

const invalidJSONPath = "%InvalidJSONPath"

func TestCredentialManifest_Unmarshal(t *testing.T) {
	t.Run("Valid Credential Manifest", func(t *testing.T) {
		t.Run("Without format or Presentation Submission", func(t *testing.T) {
			makeCredentialManifestFromBytes(t, credentialManifestUniversityDegree)
		})
		t.Run("With format", func(t *testing.T) {
			makeCredentialManifestFromBytes(t, credentialManifestUniversityDegreeWithFormat)
		})
		t.Run("With Presentation Submission", func(t *testing.T) {
			makeCredentialManifestFromBytes(t, credentialManifestUniversityDegreeWithPresentationDefinition)
		})
	})
	t.Run("Missing issuer ID", func(t *testing.T) {
		credentialManifest := makeCredentialManifestFromBytes(t, credentialManifestUniversityDegree)

		credentialManifest.Issuer.ID = ""

		invalidCredentialManifest, err := json.Marshal(credentialManifest)
		require.NoError(t, err)

		err = json.Unmarshal(invalidCredentialManifest, &credentialManifest)
		require.EqualError(t, err, "invalid credential manifest: issuer ID missing")
	})
	t.Run("No output descriptors", func(t *testing.T) {
		credentialManifest := makeCredentialManifestFromBytes(t, credentialManifestUniversityDegree)

		credentialManifest.OutputDescriptors = nil

		invalidCredentialManifest, err := json.Marshal(credentialManifest)
		require.NoError(t, err)

		err = json.Unmarshal(invalidCredentialManifest, &credentialManifest)
		require.EqualError(t, err, "invalid credential manifest: no output descriptors found")
	})
	t.Run("Output descriptor missing ID", func(t *testing.T) {
		credentialManifest := makeCredentialManifestFromBytes(t, credentialManifestUniversityDegree)

		credentialManifest.OutputDescriptors[0].ID = ""

		invalidCredentialManifest, err := json.Marshal(credentialManifest)
		require.NoError(t, err)

		err = json.Unmarshal(invalidCredentialManifest, &credentialManifest)
		require.EqualError(t, err, "invalid credential manifest: missing ID for output descriptor at index 0")
	})
	t.Run("Duplicate output descriptor IDs", func(t *testing.T) {
		credentialManifest := makeCredentialManifestFromBytes(t, credentialManifestUniversityDegree)

		credentialManifest.OutputDescriptors =
			append(credentialManifest.OutputDescriptors,
				&cm.OutputDescriptor{ID: credentialManifest.OutputDescriptors[0].ID})

		invalidCredentialManifest, err := json.Marshal(credentialManifest)
		require.NoError(t, err)

		err = json.Unmarshal(invalidCredentialManifest, &credentialManifest)
		require.EqualError(t, err, "invalid credential manifest: the ID bachelors_degree appears "+
			"in multiple output descriptors")
	})
	t.Run("Missing schema for output descriptor", func(t *testing.T) {
		credentialManifest := makeCredentialManifestFromBytes(t, credentialManifestUniversityDegree)

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

func TestResolveFulfillment(t *testing.T) {
	t.Run("Successes", func(t *testing.T) {
		testTable := map[string]struct {
			manifest    []byte
			fulfillment []byte
			expected    map[string]*cm.ResolvedDescriptor
		}{
			"single descriptor and credential": {
				manifest:    credentialManifestDriversLicense,
				fulfillment: vpWithDriversLicenseVCAndCredentialFulfillment,
				expected: map[string]*cm.ResolvedDescriptor{
					"driver_license_output": {
						Resolved: &cm.ResolvedDataDisplayDescriptor{
							Title:    "Washington State Driver License",
							Subtitle: "Class A, Commercial",
							Properties: map[string]interface{}{
								"Driving License Number": "34DGE352",
							},
						},
					},
				},
			},
			"multiple descriptor and credentials": {
				manifest:    credentialManifestMultipleVCs,
				fulfillment: vpMultipleWithCredentialFulfillment,
				expected: map[string]*cm.ResolvedDescriptor{
					"prc_output": {
						Resolved: &cm.ResolvedDataDisplayDescriptor{
							Title:    "Permanent Resident Card",
							Subtitle: "Permanent Resident Card",
							Properties: map[string]interface{}{
								"Card Holder's family name": "SMITH",
								"Card Holder's first name":  "JOHN",
							},
						},
					},
					"udc_output": {
						Resolved: &cm.ResolvedDataDisplayDescriptor{
							Title: "Bachelor's Degree",
							Properties: map[string]interface{}{
								"Degree":               "BachelorDegree",
								"Degree Holder's name": "Jayden Doe",
							},
						},
					},
				},
			},
			"single descriptor and credentials for multi descriptor manifest": {
				manifest:    credentialManifestMultipleVCs,
				fulfillment: vpWithDriversLicenseVCAndCredentialFulfillment,
				expected: map[string]*cm.ResolvedDescriptor{
					"driver_license_output": {
						Resolved: &cm.ResolvedDataDisplayDescriptor{
							Title:    "Washington State Driver License",
							Subtitle: "Class A, Commercial",
							Properties: map[string]interface{}{
								"Driving License Number": "34DGE352",
							},
						},
					},
				},
			},
		}

		t.Parallel()

		for testName, testData := range testTable {
			t.Run(testName, func(t *testing.T) {
				fulfillment := makePresentationFromBytes(t, testData.fulfillment, testName)
				manifest := &cm.CredentialManifest{}
				require.NoError(t, manifest.UnmarshalJSON(testData.manifest))

				results, err := manifest.ResolveFulfillment(fulfillment)
				require.NoError(t, err)
				require.Len(t, results, len(testData.expected))

				for _, r := range results {
					require.NotNil(t, r.Resolved)
					expected, ok := testData.expected[r.DescriptorID]
					require.True(t, ok, "unexpected descriptor ID '%s' in resolved properties", r.DescriptorID)
					require.Equal(t, expected.Resolved.Title, r.Resolved.Title)
					require.Equal(t, expected.Resolved.Subtitle, r.Resolved.Subtitle)
					require.Equal(t, expected.Resolved.Description, r.Resolved.Description)
					require.Len(t, r.Resolved.Properties, len(expected.Resolved.Properties))

					for label, value := range r.Resolved.Properties {
						expectedVal, ok := expected.Resolved.Properties[label]
						require.True(t, ok, "expected to find '%s' label in resolved properties", label)
						require.Equal(t, expectedVal, value)
					}
				}
			})
		}
	})

	t.Run("Fulfillment format failures", func(t *testing.T) {
		fulfillment := makePresentationFromBytes(t, vpMultipleWithCredentialFulfillment, t.Name())
		manifest := &cm.CredentialManifest{}
		require.NoError(t, manifest.UnmarshalJSON(credentialManifestMultipleVCs))

		t.Parallel()

		testTable := map[string]struct {
			credFulfillment []byte
			error           string
		}{
			"missing credential": {
				credFulfillment: []byte(`{
                      "id":"a30e3b91-fb77-4d22-95fa-871689c322e2",
                      "manifest_id":"dcc75a16-19f5-4273-84ce-4da69ee2b7fe",
                      "descriptor_map":[
                        {
                          "id":"udc_output",
                          "format":"ldp_vc",
                          "path":"$.verifiableCredential[0]"
                        },
                        {
                          "id":"prc_output",
                          "format":"ldp_vc",
                          "path":"$.verifiableCredential[5]"
                        }
                      ]
                    }`),
				error: "failed to select vc from descriptor",
			},
			"missing path in descriptor": {
				credFulfillment: []byte(`{
                      "id":"a30e3b91-fb77-4d22-95fa-871689c322e2",
                      "manifest_id":"dcc75a16-19f5-4273-84ce-4da69ee2b7fe",
                      "descriptor_map":[
                        {
                          "id":"udc_output",
                          "format":"ldp_vc"
                        },
                        {
                          "id":"prc_output",
                          "format":"ldp_vc",
                          "path":"$.verifiableCredential[5]"
                        }
                      ]
                    }`),
				error: "invalid credential path",
			},
			"descriptor id missing": {
				credFulfillment: []byte(`{
                      "id":"a30e3b91-fb77-4d22-95fa-871689c322e2",
                      "manifest_id":"dcc75a16-19f5-4273-84ce-4da69ee2b7fe",
                      "descriptor_map":[
                        {
                          "format":"ldp_vc",
                          "path":"$.verifiableCredential[0]"
                        }
                      ]
                    }`),
				error: "invalid descriptor ID",
			},
			"incorrect descriptor format": {
				credFulfillment: []byte(`{
                      "id":"a30e3b91-fb77-4d22-95fa-871689c322e2",
                      "manifest_id":"dcc75a16-19f5-4273-84ce-4da69ee2b7fe",
                      "descriptor_map":[
                          "format", "ldp_vc"
                      ]
                    }`),
				error: "invalid descriptor format",
			},
			"empty descriptor map": {
				credFulfillment: []byte(`{
                      "id":"a30e3b91-fb77-4d22-95fa-871689c322e2",
                      "manifest_id":"dcc75a16-19f5-4273-84ce-4da69ee2b7fe",
                      "descriptor_map":[]
                    }`),
				error: "",
			},
			"invalid descriptor format": {
				credFulfillment: []byte(`{
                      "id":"a30e3b91-fb77-4d22-95fa-871689c322e2",
                      "manifest_id":"dcc75a16-19f5-4273-84ce-4da69ee2b7fe",
                      "descriptor_map": {}
                    }`),
				error: "invalid descriptor map",
			},
			"not matching manifest": {
				credFulfillment: []byte(`{
                      "id":"a30e3b91-fb77-4d22-95fa-871689c322e2",
                      "manifest_id":"invalid",
                      "descriptor_map": {}
                    }`),
				error: "credential fulfillment not matching",
			},
			"matching descriptor not found in manifest": {
				credFulfillment: []byte(`{
                      "id":"a30e3b91-fb77-4d22-95fa-871689c322e2",
                      "manifest_id":"dcc75a16-19f5-4273-84ce-4da69ee2b7fe",
                      "descriptor_map":[
                        {
                          "id":"udc_output_missing",
                          "format":"ldp_vc",
                          "path":"$.verifiableCredential[0]"
                        },
                        {
                          "id":"prc_output",
                          "format":"ldp_vc",
                          "path":"$.verifiableCredential[1]"
                        }
                      ]
                    }`),
				error: "unable to find matching output descriptor from manifest",
			},
		}

		for testName, testData := range testTable {
			t.Run(testName, func(t *testing.T) {
				var credFulfillment map[string]interface{}
				require.NoError(t, json.Unmarshal(testData.credFulfillment, &credFulfillment))

				fulfillment.CustomFields["credential_fulfillment"] = credFulfillment

				results, err := manifest.ResolveFulfillment(fulfillment)
				require.Empty(t, results)
				if testData.error == "" {
					require.NoError(t, err)

					return
				}

				require.Error(t, err)
				require.Contains(t, err.Error(), testData.error)
			})
		}
	})

	t.Run("Failures", func(t *testing.T) {
		fulfillment := makePresentationFromBytes(t, vpMultipleWithCredentialFulfillment, t.Name())
		manifest := &cm.CredentialManifest{}
		require.NoError(t, manifest.UnmarshalJSON(credentialManifestMultipleVCs))

		// resolve err (resolved value is not string)
		for _, descr := range manifest.OutputDescriptors {
			if descr.ID == "udc_output" {
				incorrectProperties := `[{
                    "path":[
                      "$."
                    ],
                    "schema": {
                      "type": "string"
                    },
                    "fallback":"Unknown",
                    "label":"Driving License Number"
                  }]`

				require.NoError(t, json.Unmarshal([]byte(incorrectProperties), &descr.Display.Properties))
			}
		}
		results, err := manifest.ResolveFulfillment(fulfillment)
		require.Empty(t, results)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to resolve credential by descriptor")

		// unsupported formats
		var credFulfillment map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(`{
                      "id":"a30e3b91-fb77-4d22-95fa-871689c322e2",
                      "manifest_id":"dcc75a16-19f5-4273-84ce-4da69ee2b7fe",
                      "descriptor_map":[
                        {
                          "id":"udc_output",
                          "format":"jwt_vc",
                          "path":"$.verifiableCredential[0]"
                        },
                        {
                          "id":"prc_output",
                          "format":"jwt_vc",
                          "path":"$.verifiableCredential[1]"
                        }
                      ]
                    }`), &credFulfillment))

		fulfillment.CustomFields["credential_fulfillment"] = credFulfillment

		results, err = manifest.ResolveFulfillment(fulfillment)
		require.Empty(t, results)
		require.NoError(t, err)

		// marshal presentation error
		fulfillment.CustomFields["invalid"] = make(chan int)
		results, err = manifest.ResolveFulfillment(fulfillment)
		require.Empty(t, results)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to marshal vp")

		// missing credential fulfillment
		delete(fulfillment.CustomFields, "credential_fulfillment")
		results, err = manifest.ResolveFulfillment(fulfillment)
		require.Empty(t, results)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid credential fulfillment")
	})
}

func TestResolveCredential(t *testing.T) {
	t.Run("Successes", func(t *testing.T) {
		manifest := &cm.CredentialManifest{}
		require.NoError(t, manifest.UnmarshalJSON(credentialManifestUniversityDegree))

		vc := parseTestCredential(t, validVC)

		result, err := manifest.ResolveCredential("bachelors_degree", vc)
		require.NoError(t, err)
		require.NotEmpty(t, result)
		require.Equal(t, result.Title, "Bachelor of Applied Science")
		require.Equal(t, result.Subtitle, "Electrical Systems Specialty")
		require.EqualValues(t, result.Properties, map[string]interface{}{
			"With distinction": true,
			"Years studied":    float64(4),
		})
	})

	t.Run("Failures", func(t *testing.T) {
		manifest := &cm.CredentialManifest{}
		require.NoError(t, manifest.UnmarshalJSON(credentialManifestUniversityDegree))

		vc := parseTestCredential(t, validVC)

		// descriptor not found
		result, err := manifest.ResolveCredential("bachelors_degree_incorrect", vc)
		require.Empty(t, result)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to find matching descriptor")

		// credential marshal error
		vc.CustomFields["invalid"] = make(chan int)

		result, err = manifest.ResolveCredential("bachelors_degree", vc)
		require.Empty(t, result)
		require.Error(t, err)
		require.Contains(t, err.Error(), "JSON marshalling of verifiable credential")
	})
}

func createMarshalledCredentialManifestWithInvalidTitleJSONPath(t *testing.T) []byte {
	credentialManifest := createCredentialManifestWithInvalidTitleJSONPath(t)

	credentialManifestWithInvalidJSONPathBytes, err := json.Marshal(credentialManifest)
	require.NoError(t, err)

	return credentialManifestWithInvalidJSONPathBytes
}

func createCredentialManifestWithInvalidTitleJSONPath(t *testing.T) cm.CredentialManifest {
	credentialManifest := makeCredentialManifestFromBytes(t, credentialManifestUniversityDegree)

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
	credentialManifest := makeCredentialManifestFromBytes(t, credentialManifestUniversityDegree)

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
	credentialManifest := makeCredentialManifestFromBytes(t, credentialManifestUniversityDegree)

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
	credentialManifest := makeCredentialManifestFromBytes(t, credentialManifestUniversityDegree)

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
	credentialManifest := makeCredentialManifestFromBytes(t, credentialManifestUniversityDegree)

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
	credentialManifest := makeCredentialManifestFromBytes(t, credentialManifestUniversityDegree)

	credentialManifest.OutputDescriptors[0].Display.Title.Schema = cm.Schema{
		Type:   "string",
		Format: "UnknownFormat",
	}

	return credentialManifest
}

func createCredentialManifestWithNilJWTFormat(t *testing.T) cm.CredentialManifest {
	credentialManifest := makeCredentialManifestFromBytes(t, credentialManifestUniversityDegreeWithFormat)

	credentialManifest.Format.Jwt = nil

	return credentialManifest
}

func createCredentialManifestWithNilLDPFormat(t *testing.T) cm.CredentialManifest {
	credentialManifest := makeCredentialManifestFromBytes(t, credentialManifestUniversityDegreeWithFormat)

	credentialManifest.Format.Ldp = nil

	return credentialManifest
}

func makeCredentialManifestFromBytes(t *testing.T, credentialManifestBytes []byte) cm.CredentialManifest {
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
