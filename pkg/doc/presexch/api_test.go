/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presexch_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	jsonld "github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/util/fingerprint"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/kms"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/kms/localkms"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/component/models/did"
	ldcontext "github.com/hyperledger/aries-framework-go/component/models/ld/context"
	ldprocessor "github.com/hyperledger/aries-framework-go/component/models/ld/processor"
	ldtestutil "github.com/hyperledger/aries-framework-go/component/models/ld/testutil"
	. "github.com/hyperledger/aries-framework-go/component/models/presexch"
	"github.com/hyperledger/aries-framework-go/component/models/signature/suite"
	"github.com/hyperledger/aries-framework-go/component/models/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/component/models/signature/verifier"
	utiltime "github.com/hyperledger/aries-framework-go/component/models/util/time"
	"github.com/hyperledger/aries-framework-go/component/models/verifiable"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	cryptoapi "github.com/hyperledger/aries-framework-go/spi/crypto"
	kmsapi "github.com/hyperledger/aries-framework-go/spi/kms"
	"github.com/hyperledger/aries-framework-go/spi/secretlock"

	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"
)

const testCredID = "http://test.credential.com/123456"

func TestPresentationDefinition_Match(t *testing.T) {
	t.Run("match one credential", func(t *testing.T) {
		uri := randomURI()

		customType := "CustomType" //nolint: goconst

		expected := newVC([]string{uri})
		expected.Types = append(expected.Types, customType)

		defs := &PresentationDefinition{
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", uri, customType),
				}},
			}},
		}

		docLoader := createTestDocumentLoader(t, uri, customType)

		matched, err := defs.Match(
			[]*verifiable.Presentation{
				newVP(t,
					&PresentationSubmission{DescriptorMap: []*InputDescriptorMapping{{
						ID:   defs.InputDescriptors[0].ID,
						Path: "$.verifiableCredential[0]",
					}}},
					expected,
				)},
			docLoader, WithCredentialOptions(verifiable.WithJSONLDDocumentLoader(docLoader)))
		require.NoError(t, err)
		require.Len(t, matched, 1)
		result, ok := matched[defs.InputDescriptors[0].ID]
		require.True(t, ok)
		require.Equal(t, expected.ID, result.Credential.ID)
	})

	str := "string"
	subjectKey := "subject-field"
	subjectVal := "blah"

	t.Run("match two presentations", func(t *testing.T) {
		uri := randomURI()

		customType := "CustomType" //nolint: goconst

		expected := newVC([]string{uri})
		expected.Types = append(expected.Types, customType)

		expectedTwo := newVC(nil)

		expectedTwo.Subject.(map[string]interface{})[subjectKey] = subjectVal

		defs := &PresentationDefinition{
			InputDescriptors: []*InputDescriptor{
				{
					ID: "ID-0",
					Schema: []*Schema{{
						URI: fmt.Sprintf("%s#%s", uri, customType),
					}},
				},
				{
					ID: "ID-1",
					Schema: []*Schema{{
						URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
					}},
					Constraints: &Constraints{
						Fields: []*Field{
							{
								ID:   uuid.NewString(),
								Path: []string{"credentialSubject", subjectKey},
								Filter: &Filter{
									Type:  &str,
									Const: subjectVal,
								},
							},
						},
					},
				},
			},
		}

		docLoader := createTestDocumentLoader(t, uri, customType)

		vpWithSubmissionType := newVP(t, nil, expected)

		vpWithSubmissionType.CustomFields = map[string]interface{}{
			"presentation_submission": &PresentationSubmission{
				DescriptorMap: []*InputDescriptorMapping{
					{
						ID:   defs.InputDescriptors[0].ID,
						Path: "$", // TODO: $[0]
						PathNested: &InputDescriptorMapping{
							ID:   defs.InputDescriptors[0].ID,
							Path: "$.verifiableCredential[0]",
						},
					},
				},
			},
		}

		presList := []*verifiable.Presentation{
			vpWithSubmissionType,
			newVP(t,
				&PresentationSubmission{
					DescriptorMap: []*InputDescriptorMapping{
						{
							ID:   defs.InputDescriptors[1].ID,
							Path: "$", // TODO: $[1]
							PathNested: &InputDescriptorMapping{
								ID:   defs.InputDescriptors[1].ID,
								Path: "$.verifiableCredential[0]",
							},
						},
					},
				},
				expectedTwo,
			)}

		opt := []MatchOption{WithCredentialOptions(verifiable.WithJSONLDDocumentLoader(docLoader))}

		matched, err := defs.Match(presList, docLoader, opt...)
		require.NoError(t, err)
		require.Len(t, matched, 2)
		result, ok := matched[defs.InputDescriptors[0].ID]
		require.True(t, ok)
		require.Equal(t, expected.ID, result.Credential.ID)
		result, ok = matched[defs.InputDescriptors[1].ID]
		require.True(t, ok)
		require.Equal(t, expectedTwo.ID, result.Credential.ID)
	})

	t.Run("match two presentations, with merged submission", func(t *testing.T) {
		uri := randomURI()

		customType := "CustomType" //nolint: goconst

		expected := newVC([]string{uri})
		expected.Types = append(expected.Types, customType)

		expectedTwo := newVC(nil)
		expectedTwo.Subject.(map[string]interface{})[subjectKey] = subjectVal

		defs := &PresentationDefinition{
			InputDescriptors: []*InputDescriptor{
				{
					ID: "ID-0",
					Schema: []*Schema{{
						URI: fmt.Sprintf("%s#%s", uri, customType),
					}},
				},
				{
					ID: "ID-1",
					Schema: []*Schema{{
						URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
					}},
					Constraints: &Constraints{
						Fields: []*Field{
							{
								ID:   uuid.NewString(),
								Path: []string{"credentialSubject", subjectKey},
								Filter: &Filter{
									Type:  &str,
									Const: subjectVal,
								},
							},
						},
					},
				},
			},
		}

		docLoader := createTestDocumentLoader(t, uri, customType)

		presList := []*verifiable.Presentation{
			newVP(t, nil, expected),
			newVP(t, nil, expectedTwo),
		}

		submission := &PresentationSubmission{
			DescriptorMap: []*InputDescriptorMapping{
				{
					ID:   defs.InputDescriptors[0].ID,
					Path: "$[0]",
					PathNested: &InputDescriptorMapping{
						ID:   defs.InputDescriptors[0].ID,
						Path: "$.verifiableCredential[0]",
					},
				},
				{
					ID:   defs.InputDescriptors[1].ID,
					Path: "$[1]",
					PathNested: &InputDescriptorMapping{
						ID:   defs.InputDescriptors[1].ID,
						Path: "$.verifiableCredential[0]",
					},
				},
			},
		}

		opt := []MatchOption{
			WithCredentialOptions(verifiable.WithJSONLDDocumentLoader(docLoader)),
			WithMergedSubmission(submission),
		}

		matched, err := defs.Match(presList, docLoader, opt...)
		require.NoError(t, err)
		require.Len(t, matched, 2)
		result, ok := matched[defs.InputDescriptors[0].ID]
		require.True(t, ok)
		require.Equal(t, expected.ID, result.Credential.ID)
		result, ok = matched[defs.InputDescriptors[1].ID]
		require.True(t, ok)
		require.Equal(t, expectedTwo.ID, result.Credential.ID)

		// json-unmarshalled merged submission

		submissionJSON := map[string]interface{}{}

		submissionBytes, err := json.Marshal(submission)
		require.NoError(t, err)

		require.NoError(t, json.Unmarshal(submissionBytes, &submissionJSON))

		opt = []MatchOption{
			WithCredentialOptions(verifiable.WithJSONLDDocumentLoader(docLoader)),
			WithMergedSubmissionMap(submissionJSON),
		}

		matched, err = defs.Match(presList, docLoader, opt...)
		require.NoError(t, err)
		require.Len(t, matched, 2)
		result, ok = matched[defs.InputDescriptors[0].ID]
		require.True(t, ok)
		require.Equal(t, expected.ID, result.Credential.ID)
		result, ok = matched[defs.InputDescriptors[1].ID]
		require.True(t, ok)
		require.Equal(t, expectedTwo.ID, result.Credential.ID)
	})

	t.Run("match one presentation, with merged submission", func(t *testing.T) {
		uri := randomURI()

		customType := "CustomType" //nolint: goconst

		expected := newVC([]string{uri})
		expected.Types = append(expected.Types, customType)

		defs := &PresentationDefinition{
			InputDescriptors: []*InputDescriptor{
				{
					ID: "ID-0",
					Schema: []*Schema{{
						URI: fmt.Sprintf("%s#%s", uri, customType),
					}},
				},
			},
		}

		docLoader := createTestDocumentLoader(t, uri, customType)

		presList := []*verifiable.Presentation{
			newVP(t, nil, expected),
		}

		opt := []MatchOption{
			WithCredentialOptions(verifiable.WithJSONLDDocumentLoader(docLoader)),
			WithMergedSubmission(&PresentationSubmission{
				DescriptorMap: []*InputDescriptorMapping{
					{
						ID:   defs.InputDescriptors[0].ID,
						Path: "$",
						PathNested: &InputDescriptorMapping{
							ID:   defs.InputDescriptors[0].ID,
							Path: "$.verifiableCredential[0]",
						},
					},
				},
			}),
		}

		matched, err := defs.Match(presList, docLoader, opt...)
		require.NoError(t, err)
		require.Len(t, matched, 1)
		result, ok := matched[defs.InputDescriptors[0].ID]
		require.True(t, ok)
		require.Equal(t, expected.ID, result.Credential.ID)
	})

	t.Run("match one nested credential", func(t *testing.T) {
		uri := randomURI()

		customType := "CustomType"

		expectedNested := newVC([]string{uri})
		expectedNested.Types = append(expectedNested.Types, customType)
		expectedNested.ID = testCredID

		expected := newVCWithCustomFld([]string{uri}, "nestedVC", expectedNested)
		expected.Types = append(expected.Types, customType)

		defs := &PresentationDefinition{
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", uri, customType),
				}},
			}},
		}

		docLoader := createTestDocumentLoader(t, uri, customType)

		matched, err := defs.Match(
			[]*verifiable.Presentation{
				newVP(t,
					&PresentationSubmission{DescriptorMap: []*InputDescriptorMapping{{
						ID:   defs.InputDescriptors[0].ID,
						Path: "$.verifiableCredential[0]",
						PathNested: &InputDescriptorMapping{
							ID:   defs.InputDescriptors[0].ID,
							Path: "$.nestedVC",
						},
					}}},
					expected,
				)},
			docLoader, WithCredentialOptions(verifiable.WithJSONLDDocumentLoader(docLoader)))
		require.NoError(t, err)
		require.Len(t, matched, 1)
		result, ok := matched[defs.InputDescriptors[0].ID]
		require.True(t, ok)
		require.Equal(t, expectedNested.ID, result.Credential.ID)
	})

	t.Run("match one nested jwt credential", func(t *testing.T) {
		uri := randomURI()
		contextLoader := createTestDocumentLoader(t, uri)
		agent := newAgent(t)

		customType := "CustomType"

		expectedNested := newSignedJWTVC(t, agent, []string{uri})

		expected := newVCWithCustomFld([]string{uri}, "nestedVC", expectedNested)
		expected.Types = append(expected.Types, customType)
		expected.ID = testCredID

		defs := &PresentationDefinition{
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
				}},
			}},
		}

		docLoader := createTestDocumentLoader(t, uri, customType)

		matched, err := defs.Match(
			[]*verifiable.Presentation{
				newVP(t,
					&PresentationSubmission{DescriptorMap: []*InputDescriptorMapping{{
						ID:   defs.InputDescriptors[0].ID,
						Path: "$.verifiableCredential[0]",
						PathNested: &InputDescriptorMapping{
							ID:   defs.InputDescriptors[0].ID,
							Path: "$.nestedVC",
						},
					}}},
					expected,
				)},
			docLoader,
			WithCredentialOptions(
				verifiable.WithJSONLDDocumentLoader(contextLoader),
				verifiable.WithPublicKeyFetcher(didKeyFetcher()),
			),
		)
		require.NoError(t, err)
		require.Len(t, matched, 1)
		result, ok := matched[defs.InputDescriptors[0].ID]
		require.True(t, ok)
		require.Equal(t, expectedNested.ID, result.Credential.ID)
	})

	t.Run("match with self referencing", func(t *testing.T) {
		uri := randomURI()
		contextLoader := createTestDocumentLoader(t, uri)
		agent := newAgent(t)

		expected := newSignedJWTVC(t, agent, []string{uri})

		defs := &PresentationDefinition{
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
				}},
			}},
		}

		matched, err := defs.Match(
			[]*verifiable.Presentation{
				newVP(t,
					&PresentationSubmission{DescriptorMap: []*InputDescriptorMapping{{
						ID:   defs.InputDescriptors[0].ID,
						Path: "$",
						PathNested: &InputDescriptorMapping{
							ID:   defs.InputDescriptors[0].ID,
							Path: "$.verifiableCredential[0]",
						},
					}}},
					expected,
				),
			}, contextLoader,
			WithCredentialOptions(
				verifiable.WithJSONLDDocumentLoader(contextLoader),
				verifiable.WithPublicKeyFetcher(didKeyFetcher()),
			),
		)
		require.NoError(t, err)
		require.Len(t, matched, 1)
		result, ok := matched[defs.InputDescriptors[0].ID]
		require.True(t, ok)
		require.Equal(t, expected.ID, result.Credential.ID)
	})

	t.Run("match one nested sd-jwt credential", func(t *testing.T) {
		uri := randomURI()
		contextLoader := createTestDocumentLoader(t, uri)
		agent := newAgent(t)

		customType := "CustomType"

		expectedNested := newSignedSDJWTVC(t, agent, []string{uri})

		expected := newVCWithCustomFld([]string{uri}, "nestedVC", expectedNested)
		expected.Types = append(expected.Types, customType)
		expected.ID = testCredID

		defs := &PresentationDefinition{
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
				}},
			}},
		}

		docLoader := createTestDocumentLoader(t, uri, customType)

		matched, err := defs.Match(
			[]*verifiable.Presentation{newVP(t,
				&PresentationSubmission{DescriptorMap: []*InputDescriptorMapping{{
					ID:   defs.InputDescriptors[0].ID,
					Path: "$.verifiableCredential[0]",
					PathNested: &InputDescriptorMapping{
						ID:   defs.InputDescriptors[0].ID,
						Path: "$.nestedVC",
					},
				}}},
				expected,
			)},
			docLoader,
			WithCredentialOptions(
				verifiable.WithJSONLDDocumentLoader(contextLoader),
				verifiable.WithPublicKeyFetcher(didKeyFetcher()),
			),
		)
		require.NoError(t, err)
		require.Len(t, matched, 1)
		result, ok := matched[defs.InputDescriptors[0].ID]
		require.True(t, ok)
		require.Equal(t, expectedNested.ID, result.Credential.ID)
	})

	t.Run("match with self referencing - sdjwt", func(t *testing.T) {
		uri := randomURI()
		contextLoader := createTestDocumentLoader(t, uri)
		agent := newAgent(t)

		expected := newSignedSDJWTVC(t, agent, []string{uri})

		defs := &PresentationDefinition{
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
				}},
			}},
		}

		matched, err := defs.Match(
			[]*verifiable.Presentation{
				newVP(t,
					&PresentationSubmission{DescriptorMap: []*InputDescriptorMapping{{
						ID:   defs.InputDescriptors[0].ID,
						Path: "$",
						PathNested: &InputDescriptorMapping{
							ID:   defs.InputDescriptors[0].ID,
							Path: "$.verifiableCredential[0]",
						},
					}}},
					expected,
				),
			},
			contextLoader,
			WithCredentialOptions(
				verifiable.WithJSONLDDocumentLoader(contextLoader),
				verifiable.WithPublicKeyFetcher(didKeyFetcher()),
			),
		)
		require.NoError(t, err)
		require.Len(t, matched, 1)
		result, ok := matched[defs.InputDescriptors[0].ID]
		require.True(t, ok)
		require.Equal(t, expected.ID, result.Credential.ID)
	})

	t.Run("match one signed credential", func(t *testing.T) {
		uri := randomURI()
		contextLoader := createTestDocumentLoader(t, uri)
		agent := newAgent(t)
		expected := newSignedVC(t, agent, []string{uri}, contextLoader)
		defs := &PresentationDefinition{
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
				}},
			}},
		}

		matched, err := defs.Match(
			[]*verifiable.Presentation{
				newVP(t,
					&PresentationSubmission{DescriptorMap: []*InputDescriptorMapping{{
						ID:   defs.InputDescriptors[0].ID,
						Path: "$.verifiableCredential[0]",
					}}},
					expected,
				),
			},
			contextLoader,
			WithCredentialOptions(
				verifiable.WithJSONLDDocumentLoader(contextLoader),
				verifiable.WithPublicKeyFetcher(didKeyFetcher()),
			),
		)
		require.NoError(t, err)
		require.Len(t, matched, 1)
		result, ok := matched[defs.InputDescriptors[0].ID]
		require.True(t, ok)
		require.Equal(t, expected.ID, result.Credential.ID)
	})

	t.Run("error if vp does not have the right context", func(t *testing.T) {
		uri := randomURI()
		defs := &PresentationDefinition{
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: uri,
				}},
			}},
		}

		vp := newVP(t,
			&PresentationSubmission{DescriptorMap: []*InputDescriptorMapping{{
				ID:   defs.InputDescriptors[0].ID,
				Path: "$.verifiableCredential[0]",
			}}},
			newVC([]string{uri}),
		)

		vp.Context = []string{"https://www.w3.org/2018/credentials/v1"}

		docLoader := createTestDocumentLoader(t, uri)

		_, err := defs.Match([]*verifiable.Presentation{vp},
			docLoader, WithCredentialOptions(verifiable.WithJSONLDDocumentLoader(docLoader)))
		require.Error(t, err)
	})

	t.Run("error if vp can't marshal", func(t *testing.T) {
		uri := randomURI()

		customType := "CustomType" //nolint: goconst

		expected := newVC([]string{uri})
		expected.Types = append(expected.Types, customType)

		defs := &PresentationDefinition{
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", uri, customType),
				}},
			}},
		}

		docLoader := createTestDocumentLoader(t, uri, customType)

		_, err := defs.Match(
			[]*verifiable.Presentation{
				{
					Context: []string{verifiable.ContextURI, PresentationSubmissionJSONLDContextIRI},
					Type:    []string{verifiable.VPType, PresentationSubmissionJSONLDType},
					CustomFields: map[string]interface{}{
						"no-marshal": new(chan<- int),
					},
				}},
			docLoader,
			WithCredentialOptions(verifiable.WithJSONLDDocumentLoader(docLoader)),
			WithDisableSchemaValidation())
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to marshal vp")
	})

	t.Run("error if vp does not have the right type", func(t *testing.T) {
		uri := randomURI()
		defs := &PresentationDefinition{
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: uri,
				}},
			}},
		}

		vp := newVP(t,
			&PresentationSubmission{DescriptorMap: []*InputDescriptorMapping{{
				ID:   defs.InputDescriptors[0].ID,
				Path: "$.verifiableCredential[0]",
			}}},
			newVC([]string{uri}),
		)

		vp.Type = []string{"VerifiablePresentation"}

		docLoader := createTestDocumentLoader(t, uri)

		_, err := defs.Match([]*verifiable.Presentation{vp},
			docLoader, WithCredentialOptions(verifiable.WithJSONLDDocumentLoader(docLoader)))
		require.Error(t, err)
	})

	t.Run("error if descriptor_map has an invalid ID", func(t *testing.T) {
		uri := randomURI()
		defs := &PresentationDefinition{
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: uri,
				}},
			}},
		}

		docLoader := createTestDocumentLoader(t, uri)

		_, err := defs.Match(
			[]*verifiable.Presentation{
				newVP(t,
					&PresentationSubmission{DescriptorMap: []*InputDescriptorMapping{{
						ID:   "INVALID",
						Path: "$.verifiableCredential[0]",
					}}},
					newVC([]string{uri}),
				),
			}, docLoader, WithCredentialOptions(verifiable.WithJSONLDDocumentLoader(docLoader)))
		require.Error(t, err)
	})

	t.Run("error if jsonpath in descriptor_map points to a nonexistent element", func(t *testing.T) {
		uri := randomURI()
		defs := &PresentationDefinition{
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: uri,
				}},
			}},
		}

		docLoader := createTestDocumentLoader(t, uri)

		_, err := defs.Match(
			[]*verifiable.Presentation{
				newVP(t,
					&PresentationSubmission{DescriptorMap: []*InputDescriptorMapping{{
						ID:   defs.InputDescriptors[0].ID,
						Path: "$.verifiableCredential[1]",
					}}}, nil,
				),
			}, docLoader, WithCredentialOptions(verifiable.WithJSONLDDocumentLoader(docLoader)))
		require.Error(t, err)
	})

	t.Run("error if cannot parse credential", func(t *testing.T) {
		uri := randomURI()
		defs := &PresentationDefinition{
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: uri,
				}},
			}},
		}

		docLoader := createTestDocumentLoader(t, "invalidURI")

		_, err := defs.Match(
			[]*verifiable.Presentation{
				newVP(t,
					&PresentationSubmission{DescriptorMap: []*InputDescriptorMapping{{
						ID:   defs.InputDescriptors[0].ID,
						Path: "$.verifiableCredential[0]",
					}}}, newVC([]string{uri}),
				),
			}, docLoader, WithCredentialOptions(verifiable.WithJSONLDDocumentLoader(docLoader)))
		require.Error(t, err)
	})

	t.Run("error if embedded credential has a type different than the input descriptor schema uri", func(t *testing.T) {
		uri := randomURI()
		defs := &PresentationDefinition{
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: uri,
				}},
			}},
		}

		diffURI := randomURI()
		require.NotEqual(t, uri, diffURI)

		docLoader := createTestDocumentLoader(t, diffURI)

		_, err := defs.Match(
			[]*verifiable.Presentation{
				newVP(t,
					&PresentationSubmission{DescriptorMap: []*InputDescriptorMapping{{
						ID:   defs.InputDescriptors[0].ID,
						Path: "$.verifiableCredential[0]",
					}}},
					newVC([]string{diffURI}),
				),
			}, docLoader, WithCredentialOptions(verifiable.WithJSONLDDocumentLoader(docLoader)))
		require.Error(t, err)
	})

	t.Run("error when missing required credential", func(t *testing.T) {
		uriOne := randomURI()
		uriTwo := randomURI()
		defs := &PresentationDefinition{
			InputDescriptors: []*InputDescriptor{
				{
					ID: uuid.New().String(),
					Schema: []*Schema{{
						URI: uriOne,
					}},
				},
				{
					ID: uuid.New().String(),
					Schema: []*Schema{{
						URI: uriTwo,
					}},
				},
			},
		}

		docLoader := createTestDocumentLoader(t, uriOne)

		_, err := defs.Match(
			[]*verifiable.Presentation{
				newVP(t,
					&PresentationSubmission{DescriptorMap: []*InputDescriptorMapping{{
						ID:   defs.InputDescriptors[0].ID,
						Path: "$.verifiableCredential[0]",
					}}},
					newVC([]string{uriOne}),
				),
			}, docLoader, WithCredentialOptions(verifiable.WithJSONLDDocumentLoader(docLoader)))
		require.Error(t, err)
	})

	t.Run("error if embedded credential has a type different than the input descriptor schema uri", func(t *testing.T) {
		uri := randomURI()
		defs := &PresentationDefinition{
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: uri,
				}},
			}},
		}

		docLoader := createTestDocumentLoader(t, uri)

		_, err := defs.Match(
			[]*verifiable.Presentation{
				newVP(t,
					nil,
					newVC([]string{uri}),
				),
			}, docLoader, WithCredentialOptions(verifiable.WithJSONLDDocumentLoader(docLoader)))
		require.Error(t, err)
	})

	t.Run("error if descriptor_map has an invalid ID", func(t *testing.T) {
		uri := randomURI()

		docLoader := createTestDocumentLoader(t, uri)

		defs := &PresentationDefinition{
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: uri,
				}},
			}},
		}

		_, err := defs.Match(
			[]*verifiable.Presentation{
				newVP(t,
					&PresentationSubmission{},
					newVC([]string{uri}),
				),
			}, docLoader, WithCredentialOptions(verifiable.WithJSONLDDocumentLoader(docLoader)))
		require.Error(t, err)
	})

	t.Run("error if merged submission has invalid credential paths", func(t *testing.T) {
		uri := randomURI()

		customType := "CustomType" //nolint: goconst

		expected := newVC([]string{uri})
		expected.Types = append(expected.Types, customType)

		expectedTwo := newVC(nil)
		expectedTwo.Subject.(map[string]interface{})[subjectKey] = subjectVal

		defs := &PresentationDefinition{
			InputDescriptors: []*InputDescriptor{
				{
					ID: "ID-0",
					Schema: []*Schema{{
						URI: fmt.Sprintf("%s#%s", uri, customType),
					}},
				},
				{
					ID: "ID-1",
					Schema: []*Schema{{
						URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
					}},
					Constraints: &Constraints{
						Fields: []*Field{
							{
								ID:   uuid.NewString(),
								Path: []string{"credentialSubject", subjectKey},
								Filter: &Filter{
									Type:  &str,
									Const: subjectVal,
								},
							},
						},
					},
				},
			},
		}

		docLoader := createTestDocumentLoader(t, uri, customType)

		presList := []*verifiable.Presentation{
			newVP(t, nil, expected),
			newVP(t, nil, expectedTwo),
		}

		opt := []MatchOption{
			WithCredentialOptions(verifiable.WithJSONLDDocumentLoader(docLoader)),
			WithMergedSubmission(&PresentationSubmission{
				DescriptorMap: []*InputDescriptorMapping{
					{
						ID:   defs.InputDescriptors[0].ID,
						Path: "$",
						PathNested: &InputDescriptorMapping{
							ID:   defs.InputDescriptors[0].ID,
							Path: "$.verifiableCredential[0]",
						},
					},
					{
						ID:   defs.InputDescriptors[1].ID,
						Path: "$",
						PathNested: &InputDescriptorMapping{
							ID:   defs.InputDescriptors[1].ID,
							Path: "$.verifiableCredential[0]",
						},
					},
				},
			}),
		}

		_, err := defs.Match(presList, docLoader, opt...)
		require.Error(t, err)
		require.Contains(t, err.Error(), "presentation submission has invalid path")
	})

	t.Run("error if submission ignores an input descriptor", func(t *testing.T) {
		uri := randomURI()

		customType := "CustomType" //nolint: goconst

		expected := newVC([]string{uri})
		expected.Types = append(expected.Types, customType)

		defs := &PresentationDefinition{
			InputDescriptors: []*InputDescriptor{
				{
					ID: uuid.New().String(),
					Schema: []*Schema{{
						URI: fmt.Sprintf("%s#%s", uri, customType),
					}},
				},
				{
					ID: uuid.NewString(),
					Schema: []*Schema{{
						URI: randomURI(),
					}},
				},
			},
		}

		docLoader := createTestDocumentLoader(t, uri, customType)

		_, err := defs.Match(
			[]*verifiable.Presentation{
				newVP(t,
					&PresentationSubmission{DescriptorMap: []*InputDescriptorMapping{{
						ID:   defs.InputDescriptors[0].ID,
						Path: "$.verifiableCredential[0]",
					}}},
					expected,
				)},
			docLoader, WithCredentialOptions(verifiable.WithJSONLDDocumentLoader(docLoader)))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed submission requirements")
	})
}

func TestE2E(t *testing.T) {
	baseSchemaURI := randomURI()

	customType := "CustomType"

	// verifier sends their presentation definitions to the holder
	verifierDefinitions := &PresentationDefinition{
		InputDescriptors: []*InputDescriptor{{
			ID: uuid.New().String(),
			Schema: []*Schema{{
				URI: fmt.Sprintf("%s#%s", baseSchemaURI, customType),
			}, {
				URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
			}},
		}},
	}

	// holder builds their presentation submission against the verifier's definitions
	holderCredential := newVC([]string{baseSchemaURI})
	holderCredential.Types = append(holderCredential.Types, customType)

	vp := newVP(t,
		&PresentationSubmission{DescriptorMap: []*InputDescriptorMapping{{
			ID:   verifierDefinitions.InputDescriptors[0].ID,
			Path: "$.verifiableCredential[0]",
		}}},
		holderCredential,
	)

	// holder sends VP over the wire to the verifier
	vpBytes := marshal(t, vp)

	// load json-ld context
	loader := createTestDocumentLoader(t, baseSchemaURI, customType)

	// verifier parses the vp
	receivedVP, err := verifiable.ParsePresentation(vpBytes,
		verifiable.WithPresDisabledProofCheck(),
		verifiable.WithPresJSONLDDocumentLoader(loader))
	require.NoError(t, err)

	// verifier matches the received VP against their definitions
	matched, err := verifierDefinitions.Match(
		[]*verifiable.Presentation{receivedVP}, loader,
		WithCredentialOptions(verifiable.WithJSONLDDocumentLoader(loader)))
	require.NoError(t, err)
	require.Len(t, matched, 1)
	result, ok := matched[verifierDefinitions.InputDescriptors[0].ID]
	require.True(t, ok)
	require.Equal(t, holderCredential.ID, result.Credential.ID)
}

func newVC(ctx []string) *verifiable.Credential {
	vc := &verifiable.Credential{
		Context: []string{verifiable.ContextURI},
		Types:   []string{verifiable.VCType},
		ID:      "http://test.credential.com/123",
		Issuer:  verifiable.Issuer{ID: "http://test.issuer.com"},
		Issued: &utiltime.TimeWrapper{
			Time: time.Now(),
		},
		Subject: map[string]interface{}{
			"id": uuid.New().String(),
		},
	}

	if ctx != nil {
		vc.Context = append(vc.Context, ctx...)
	}

	return vc
}

func newVCWithCustomFld(ctx []string, fldName string, fld interface{}) *verifiable.Credential {
	vc := &verifiable.Credential{
		Context: []string{verifiable.ContextURI},
		Types:   []string{verifiable.VCType},
		ID:      "http://test.credential.com/123",
		Issuer:  verifiable.Issuer{ID: "http://test.issuer.com"},
		Issued: &utiltime.TimeWrapper{
			Time: time.Now(),
		},
		Subject: map[string]interface{}{
			"id": uuid.New().String(),
		},
		CustomFields: map[string]interface{}{
			fldName: fld,
		},
	}

	if ctx != nil {
		vc.Context = append(vc.Context, ctx...)
	}

	return vc
}

func newSignedVC(t *testing.T,
	agent provider, ctx []string, ctxLoader jsonld.DocumentLoader) *verifiable.Credential {
	t.Helper()

	vc := newVC(ctx)

	keyID, kh, err := agent.KMS().Create(kmsapi.ED25519Type)
	require.NoError(t, err)

	signer := suite.NewCryptoSigner(agent.Crypto(), kh)
	now := time.Now()

	pubKey, kt, err := agent.KMS().ExportPubKeyBytes(keyID)
	require.NoError(t, err)
	require.Equal(t, kmsapi.ED25519Type, kt)

	_, verMethod := fingerprint.CreateDIDKeyByCode(fingerprint.ED25519PubKeyMultiCodec, pubKey)

	err = vc.AddLinkedDataProof(
		&verifiable.LinkedDataProofContext{
			SignatureType:           ed25519signature2018.SignatureType,
			Suite:                   ed25519signature2018.New(suite.WithSigner(signer)),
			SignatureRepresentation: verifiable.SignatureJWS,
			Created:                 &now,
			VerificationMethod:      verMethod,
			Purpose:                 "assertionMethod",
		},
		ldprocessor.WithDocumentLoader(ctxLoader),
	)
	require.NoError(t, err)

	return vc
}

func newSignedJWTVC(t *testing.T,
	agent provider, ctx []string) *verifiable.Credential {
	t.Helper()

	vc := newVC(ctx)

	keyID, kh, err := agent.KMS().Create(kmsapi.ED25519Type)
	require.NoError(t, err)

	signer := suite.NewCryptoSigner(agent.Crypto(), kh)

	pubKey, kt, err := agent.KMS().ExportPubKeyBytes(keyID)
	require.NoError(t, err)
	require.Equal(t, kmsapi.ED25519Type, kt)

	issuer, verMethod := fingerprint.CreateDIDKeyByCode(fingerprint.ED25519PubKeyMultiCodec, pubKey)

	vc.Issuer = verifiable.Issuer{ID: issuer}

	claims, err := vc.JWTClaims(false)
	require.NoError(t, err)

	jwsAlgo, err := verifiable.KeyTypeToJWSAlgo(kmsapi.ED25519Type)
	require.NoError(t, err)

	jws, err := claims.MarshalJWS(jwsAlgo, signer, verMethod)
	require.NoError(t, err)

	vc.JWT = jws

	return vc
}

func newSignedSDJWTVC(t *testing.T,
	agent provider, ctx []string) *verifiable.Credential {
	t.Helper()

	vc := getTestVCWithContext(ctx)

	keyID, kh, err := agent.KMS().Create(kmsapi.ED25519Type)
	require.NoError(t, err)

	signer := suite.NewCryptoSigner(agent.Crypto(), kh)

	pubKey, kt, err := agent.KMS().ExportPubKeyBytes(keyID)
	require.NoError(t, err)
	require.Equal(t, kmsapi.ED25519Type, kt)

	issuer, verMethod := fingerprint.CreateDIDKeyByCode(fingerprint.ED25519PubKeyMultiCodec, pubKey)

	vc.Issuer = verifiable.Issuer{ID: issuer}

	jwsAlgo, err := verifiable.KeyTypeToJWSAlgo(kmsapi.ED25519Type)
	require.NoError(t, err)

	algName, err := jwsAlgo.Name()
	require.NoError(t, err)

	combinedFormatForIssuance, err := vc.MakeSDJWT(verifiable.GetJWTSigner(signer, algName), verMethod)
	require.NoError(t, err)

	parsed, err := verifiable.ParseCredential([]byte(combinedFormatForIssuance),
		verifiable.WithPublicKeyFetcher(holderPublicKeyFetcher(pubKey)))
	require.NoError(t, err)

	return parsed
}

func newVP(t *testing.T, submission *PresentationSubmission, vcs ...*verifiable.Credential) *verifiable.Presentation {
	vp, err := verifiable.NewPresentation(verifiable.WithCredentials(vcs...))
	require.NoError(t, err)

	vp.Context = append(vp.Context, "https://identity.foundation/presentation-exchange/submission/v1")
	vp.Type = append(vp.Type, "PresentationSubmission")

	if submission != nil {
		vp.CustomFields = make(map[string]interface{})
		vp.CustomFields["presentation_submission"] = toMap(t, submission)
	}

	return vp
}

func toMap(t *testing.T, v interface{}) map[string]interface{} {
	bits, err := json.Marshal(v)
	require.NoError(t, err)

	m := make(map[string]interface{})

	err = json.Unmarshal(bits, &m)
	require.NoError(t, err)

	return m
}

func marshal(t *testing.T, v interface{}) []byte {
	bits, err := json.Marshal(v)
	require.NoError(t, err)

	return bits
}

func randomURI() string {
	return fmt.Sprintf("https://my.test.context.jsonld/%s", uuid.New().String())
}

func createTestDocumentLoader(t *testing.T, contextURL string, types ...string) jsonld.DocumentLoader {
	include := fmt.Sprintf(`"ctx":"%s#"`, contextURL)

	for _, typ := range types {
		include += fmt.Sprintf(`,"%s":"ctx:%s"`, typ, typ)
	}

	jsonLDContext := fmt.Sprintf(`{
    "@context":{
      "@version":1.1,
      "@protected":true,
      "name":"http://schema.org/name",
      "ex":"https://example.org/examples#",
      "xsd":"http://www.w3.org/2001/XMLSchema#",
	  %s
   }
}`, include)

	loader, err := ldtestutil.DocumentLoader(ldcontext.Document{
		URL:     contextURL,
		Content: []byte(jsonLDContext),
	})
	require.NoError(t, err)

	return loader
}

func newAgent(t *testing.T) provider {
	t.Helper()

	storeProv := mem.NewProvider()

	kmsStore, err := kms.NewAriesProviderWrapper(storeProv)
	require.NoError(t, err)

	kmsInstance, err := localkms.New("local-lock://test", &kmsProvider{
		store: kmsStore,
	})
	require.NoError(t, err)

	cryptoInstance, err := tinkcrypto.New()
	require.NoError(t, err)

	return &mockProvider{
		KMSInstance:    kmsInstance,
		CryptoInstance: cryptoInstance,
	}
}

func getTestVCWithContext(ctx []string) *verifiable.Credential {
	subject := map[string]interface{}{
		"id":           uuid.New().String(),
		"sub":          "john_doe_42",
		"given_name":   "John",
		"family_name":  "Doe",
		"email":        "johndoe@example.com",
		"phone_number": "+1-202-555-0101",
		"birthdate":    "1940-01-01",
		"address": map[string]interface{}{
			"street_address": "123 Main St",
			"locality":       "Anytown",
			"region":         "Anystate",
			"country":        "US",
		},
	}

	vc := verifiable.Credential{
		Context: []string{verifiable.ContextURI},
		Types:   []string{verifiable.VCType},
		ID:      "http://example.edu/credentials/1872",
		Issued: &utiltime.TimeWrapper{
			Time: time.Now(),
		},
		Issuer: verifiable.Issuer{
			ID: "did:example:76e12ec712ebc6f1c221ebfeb1f",
		},
		Schemas: []verifiable.TypedID{{
			ID:   "https://www.w3.org/TR/vc-data-model/2.0/#types",
			Type: "JsonSchemaValidator2018",
		}},
		Subject: subject,
	}

	if ctx != nil {
		vc.Context = append(vc.Context, ctx...)
	}

	return &vc
}

func holderPublicKeyFetcher(pubKeyBytes []byte) verifiable.PublicKeyFetcher {
	return func(issuerID, keyID string) (*verifier.PublicKey, error) {
		return &verifier.PublicKey{
			Type:  kmsapi.RSARS256,
			Value: pubKeyBytes,
		}, nil
	}
}

func didKeyFetcher() verifiable.PublicKeyFetcher {
	kv := key.New()

	return verifiable.NewVDRKeyResolver(resolveFunc(kv.Read)).PublicKeyFetcher()
}

type resolveFunc func(did string, opts ...vdr.DIDMethodOption) (*did.DocResolution, error)

func (r resolveFunc) Resolve(did string, opts ...vdr.DIDMethodOption) (*did.DocResolution, error) {
	return r(did, opts...)
}

type provider interface {
	KMS() kmsapi.KeyManager
	Crypto() cryptoapi.Crypto
}

type mockProvider struct {
	KMSInstance    kmsapi.KeyManager
	CryptoInstance cryptoapi.Crypto
}

func (m *mockProvider) KMS() kmsapi.KeyManager {
	return m.KMSInstance
}

func (m *mockProvider) Crypto() cryptoapi.Crypto {
	return m.CryptoInstance
}

type kmsProvider struct {
	store kmsapi.Store
}

func (k *kmsProvider) StorageProvider() kmsapi.Store {
	return k.store
}

func (k *kmsProvider) SecretLock() secretlock.Service {
	return &noop.NoLock{}
}
