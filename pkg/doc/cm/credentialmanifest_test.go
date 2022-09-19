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
	//go:embed testdata/credential_manifest_drivers_license_with_no_display_or_styles.json
	credentialManifestDriversLicenseWithNoDisplayOrStyles []byte //nolint:gochecknoglobals
)

// Sample verifiable credential for a university degree.
var (
	//go:embed testdata/credential_university_degree.jsonld
	validVC []byte // nolint:gochecknoglobals
	//go:embed testdata/credential_university_degree_jwt.txt
	validJWTVC []byte // nolint:gochecknoglobals
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
		t.Run("Without output descriptor display", func(t *testing.T) {
			makeCredentialManifestFromBytes(t, credentialManifestDriversLicenseWithNoDisplayOrStyles)
		})
		t.Run("Without issuer optional properties", func(t *testing.T) {
			credentialManifest := makeCredentialManifestFromBytes(t, credentialManifestUniversityDegree)

			credentialManifest.Issuer = cm.Issuer{ID: "valid ID"}

			invalidCredentialManifest, err := json.Marshal(credentialManifest)
			require.NoError(t, err)

			err = json.Unmarshal(invalidCredentialManifest, &credentialManifest)
			require.NoError(t, err)
		})
	})
	t.Run("Invalid Credential Manifest", func(t *testing.T) {
		t.Run("Missing ID", func(t *testing.T) {
			credentialManifest := makeCredentialManifestFromBytes(t, credentialManifestUniversityDegree)

			credentialManifest.ID = ""

			invalidCredentialManifest, err := json.Marshal(credentialManifest)
			require.NoError(t, err)

			err = json.Unmarshal(invalidCredentialManifest, &credentialManifest)
			require.EqualError(t, err, "invalid credential manifest: ID missing")
		})
		t.Run("Missing issuer", func(t *testing.T) {
			credentialManifest := makeCredentialManifestFromBytes(t, credentialManifestUniversityDegree)

			credentialManifest.Issuer = cm.Issuer{}

			invalidCredentialManifest, err := json.Marshal(credentialManifest)
			require.NoError(t, err)

			err = json.Unmarshal(invalidCredentialManifest, &credentialManifest)
			require.EqualError(t, err, "invalid credential manifest: issuer ID missing")
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
		t.Run("Missing paths and text", func(t *testing.T) {
			var credentialManifest cm.CredentialManifest

			err := json.Unmarshal(createMarshalledCredentialManifestWithMissingPropertyJSONPathAndText(t), &credentialManifest)
			require.EqualError(t, err, "invalid credential manifest: display property at index 0 for output descriptor at "+
				"index 0 is invalid: display mapping object must contain either a paths or a text property")
		})
		t.Run("Missing image URI", func(t *testing.T) {
			credentialManifest := createCredentialManifestWithNoImageURI(t)

			invalidCredentialManifest, err := json.Marshal(credentialManifest)
			require.NoError(t, err)

			err = json.Unmarshal(invalidCredentialManifest, &credentialManifest)
			require.EqualError(t, err, "invalid credential manifest: uri missing for image at index 0")
		})
	})
}

func TestResolveResponse(t *testing.T) {
	type match struct {
		Title       string
		Subtitle    string
		Description string
		Properties  map[string]*cm.ResolvedProperty
	}

	// nolint:lll
	t.Run("Successes", func(t *testing.T) {
		testTable := map[string]struct {
			manifest []byte
			response []byte
			expected map[string]*match
		}{
			"single descriptor and credential": {
				manifest: credentialManifestDriversLicense,
				response: vpWithDriversLicenseVCAndCredentialResponse,
				expected: map[string]*match{
					"driver_license_output": {
						Title:    "Washington State Driver License",
						Subtitle: "Class A, Commercial",
						Description: "License to operate a vehicle with a gross combined weight " +
							"rating (GCWR) of 26,001 or more pounds, as long as the GVWR of the vehicle(s) " +
							"being towed is over 10,000 pounds.",
						Properties: map[string]*cm.ResolvedProperty{
							"Driving License Number": {
								Label: "Driving License Number",
								Value: "34DGE352",
								Schema: cm.Schema{
									Type: "boolean",
								},
							},
						},
					},
				},
			},
			"multiple descriptor and credentials": {
				manifest: credentialManifestMultipleVCs,
				response: vpMultipleWithCredentialResponse,
				expected: map[string]*match{
					"prc_output": {
						Title:       "Permanent Resident Card",
						Subtitle:    "Permanent Resident Card",
						Description: "PR card of John Smith.",
						Properties: map[string]*cm.ResolvedProperty{
							"Card Holder's family name": {Label: "Card Holder's family name", Value: "SMITH", Schema: cm.Schema{Type: "string"}},
							"Card Holder's first name":  {Label: "Card Holder's first name", Value: "JOHN", Schema: cm.Schema{Type: "string"}},
						},
					},
					"udc_output": {
						Title:       "Bachelor's Degree",
						Description: "Awarded for completing a four year program at Example University.",
						Properties: map[string]*cm.ResolvedProperty{
							"Degree":               {Label: "Degree", Value: "BachelorDegree", Schema: cm.Schema{Type: "string"}},
							"Degree Holder's name": {Label: "Degree Holder's name", Value: "Jayden Doe", Schema: cm.Schema{Type: "string"}},
						},
					},
				},
			},
			"single descriptor and credentials for multi descriptor manifest": {
				manifest: credentialManifestMultipleVCs,
				response: vpWithDriversLicenseVCAndCredentialResponse,
				expected: map[string]*match{
					"driver_license_output": {
						Title:    "Washington State Driver License",
						Subtitle: "Class A, Commercial",
						Description: "License to operate a vehicle with a gross combined weight " +
							"rating (GCWR) of 26,001 or more pounds, as long as the GVWR of the vehicle(s) " +
							"being towed is over 10,000 pounds.",
						Properties: map[string]*cm.ResolvedProperty{
							"Driving License Number": {Label: "Driving License Number", Value: "34DGE352", Schema: cm.Schema{Type: "boolean"}},
						},
					},
				},
			},
		}

		t.Parallel()

		for testName, testData := range testTable {
			t.Run(testName, func(t *testing.T) {
				response := makePresentationFromBytes(t, testData.response, testName)
				manifest := &cm.CredentialManifest{}
				require.NoError(t, manifest.UnmarshalJSON(testData.manifest))

				results, err := manifest.ResolveResponse(response)
				require.NoError(t, err)
				require.Len(t, results, len(testData.expected))

				for _, r := range results {
					require.NotEmpty(t, r.DescriptorID)
					expected, ok := testData.expected[r.DescriptorID]
					require.True(t, ok, "unexpected descriptor ID '%s' in resolved properties", r.DescriptorID)
					require.Equal(t, expected.Title, r.Title)
					require.Equal(t, expected.Subtitle, r.Subtitle)
					require.Equal(t, expected.Description, r.Description)
					require.NotEmpty(t, r.Styles.Background)
					require.Len(t, r.Properties, len(expected.Properties))

					for _, resolvedProperty := range r.Properties {
						expectedVal, ok := expected.Properties[resolvedProperty.Label]
						require.True(t, ok, "expected to find '%s' label in resolved properties", resolvedProperty.Label)
						require.EqualValues(t, expectedVal, resolvedProperty)
					}
				}
			})
		}
	})

	t.Run("Response format failures", func(t *testing.T) {
		response := makePresentationFromBytes(t, vpMultipleWithCredentialResponse, t.Name())
		manifest := &cm.CredentialManifest{}
		require.NoError(t, manifest.UnmarshalJSON(credentialManifestMultipleVCs))

		t.Parallel()

		testTable := map[string]struct {
			credResponse []byte
			error        string
		}{
			"missing credential": {
				credResponse: []byte(`{
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
				credResponse: []byte(`{
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
				credResponse: []byte(`{
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
				credResponse: []byte(`{
                      "id":"a30e3b91-fb77-4d22-95fa-871689c322e2",
                      "manifest_id":"dcc75a16-19f5-4273-84ce-4da69ee2b7fe",
                      "descriptor_map":[
                          "format", "ldp_vc"
                      ]
                    }`),
				error: "invalid descriptor format",
			},
			"empty descriptor map": {
				credResponse: []byte(`{
                      "id":"a30e3b91-fb77-4d22-95fa-871689c322e2",
                      "manifest_id":"dcc75a16-19f5-4273-84ce-4da69ee2b7fe",
                      "descriptor_map":[]
                    }`),
				error: "",
			},
			"invalid descriptor format": {
				credResponse: []byte(`{
                      "id":"a30e3b91-fb77-4d22-95fa-871689c322e2",
                      "manifest_id":"dcc75a16-19f5-4273-84ce-4da69ee2b7fe",
                      "descriptor_map": {}
                    }`),
				error: "invalid descriptor map",
			},
			"not matching manifest": {
				credResponse: []byte(`{
                      "id":"a30e3b91-fb77-4d22-95fa-871689c322e2",
                      "manifest_id":"invalid",
                      "descriptor_map": {}
                    }`),
				error: "credential response not matching",
			},
			"matching descriptor not found in manifest": {
				credResponse: []byte(`{
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
				var credResponse map[string]interface{}
				require.NoError(t, json.Unmarshal(testData.credResponse, &credResponse))

				response.CustomFields["credential_response"] = credResponse

				results, err := manifest.ResolveResponse(response)
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
		response := makePresentationFromBytes(t, vpMultipleWithCredentialResponse, t.Name())
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
		results, err := manifest.ResolveResponse(response)
		require.Empty(t, results)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to resolve credential by descriptor")

		// unsupported formats
		var credResponse map[string]interface{}
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
                    }`), &credResponse))

		response.CustomFields["credential_response"] = credResponse

		results, err = manifest.ResolveResponse(response)
		require.Empty(t, results)
		require.NoError(t, err)

		// marshal presentation error
		response.CustomFields["invalid"] = make(chan int)
		results, err = manifest.ResolveResponse(response)
		require.Empty(t, results)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to marshal vp")

		// missing credential response
		delete(response.CustomFields, "credential_response")
		results, err = manifest.ResolveResponse(response)
		require.Empty(t, results)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid credential response")
	})
}

func TestResolveCredential(t *testing.T) {
	t.Run("Successes", func(t *testing.T) {
		testCases := []struct {
			name         string
			credResolver func(t *testing.T) cm.CredentialToResolveOption
		}{
			{
				name: "resolve credential struct",
				credResolver: func(t *testing.T) cm.CredentialToResolveOption {
					t.Helper()

					vc := parseTestCredential(t, validVC)

					return cm.CredentialToResolve(vc)
				},
			},
			{
				name: "resolve raw JSON-LD credential",
				credResolver: func(t *testing.T) cm.CredentialToResolveOption {
					t.Helper()

					return cm.RawCredentialToResolve(validVC)
				},
			},
			{
				name: "resolve raw JWT credential",
				credResolver: func(t *testing.T) cm.CredentialToResolveOption {
					t.Helper()

					return cm.RawCredentialToResolve(validJWTVC)
				},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				manifest := &cm.CredentialManifest{}
				require.NoError(t, manifest.UnmarshalJSON(credentialManifestUniversityDegree))

				result, err := manifest.ResolveCredential("bachelors_degree", tc.credResolver(t))
				require.NoError(t, err)
				require.NotEmpty(t, result)
				require.Equal(t, result.Title, "Bachelor of Applied Science")
				require.Equal(t, result.Subtitle, "Electrical Systems Specialty")

				expected := map[string]*cm.ResolvedProperty{
					"With distinction": {
						Label: "With distinction",
						Value: true,
						Schema: cm.Schema{
							Type: "boolean",
						},
					},
					"Years studied": {
						Label: "Years studied",
						Value: float64(4),
						Schema: cm.Schema{
							Type: "number",
						},
					},
				}

				for _, property := range result.Properties {
					expectedVal, ok := expected[property.Label]
					require.True(t, ok, "unexpected label '%s' in resolved properties", property.Label)
					require.EqualValues(t, expectedVal, property)
				}
			})
		}
	})

	t.Run("Failures", func(t *testing.T) {
		manifest := &cm.CredentialManifest{}
		require.NoError(t, manifest.UnmarshalJSON(credentialManifestUniversityDegree))

		// invalid credential to resolve
		result, err := manifest.ResolveCredential("bachelors_degree", nil)
		require.Empty(t, result)
		require.Error(t, err)
		require.Contains(t, err.Error(), "credential to resolve is not provided")

		// invalid raw credential to resolve
		result, err = manifest.ResolveCredential("bachelors_degree", cm.RawCredentialToResolve([]byte("---")))
		require.Empty(t, result)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid character")

		vc := parseTestCredential(t, validVC)

		// descriptor not found
		result, err = manifest.ResolveCredential("bachelors_degree_incorrect", cm.CredentialToResolve(vc))
		require.Empty(t, result)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to find matching descriptor")

		// credential marshal error
		vc.CustomFields["invalid"] = make(chan int)

		result, err = manifest.ResolveCredential("bachelors_degree", cm.CredentialToResolve(vc))
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

func createCredentialManifestWithMissingPropertyJSONPathAndText(t *testing.T) cm.CredentialManifest {
	credentialManifest := makeCredentialManifestFromBytes(t, credentialManifestUniversityDegree)

	credentialManifest.OutputDescriptors[0].Display.Properties[0].Paths = []string{}
	credentialManifest.OutputDescriptors[0].Display.Properties[0].Text = ""

	return credentialManifest
}

func createMarshalledCredentialManifestWithMissingPropertyJSONPathAndText(t *testing.T) []byte {
	credentialManifest := createCredentialManifestWithMissingPropertyJSONPathAndText(t)

	credentialManifestWithNoPathsOrType, err := json.Marshal(credentialManifest)
	require.NoError(t, err)

	return credentialManifestWithNoPathsOrType
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

func createCredentialManifestWithNoImageURI(t *testing.T) cm.CredentialManifest {
	credentialManifest := makeCredentialManifestFromBytes(t, credentialManifestUniversityDegree)

	credentialManifest.OutputDescriptors[0].Styles.Thumbnail = &cm.ImageURIWithAltText{
		Alt: "valid alt",
	}
	require.Empty(t, credentialManifest.OutputDescriptors[0].Styles.Thumbnail.URI)

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
