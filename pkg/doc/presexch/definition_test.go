/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presexch_test

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"github.com/PaesslerAG/gval"
	"github.com/PaesslerAG/jsonpath"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	. "github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

func TestPresentationDefinition_IsValid(t *testing.T) {
	samples := []string{"sample_1.json", "sample_2.json", "sample_3.json"}

	for _, sample := range samples {
		file := sample
		t.Run(file, func(t *testing.T) {
			var pd *PresentationDefinition
			parseJSONFile(t, "testdata/"+file, &pd)

			require.NoError(t, pd.ValidateSchema())
		})
	}

	t.Run("id is required", func(t *testing.T) {
		errMsg := "presentation_definition: id is required,presentation_definition: input_descriptors is required"
		pd := &PresentationDefinition{
			SubmissionRequirements: []*SubmissionRequirement{{Rule: All, From: "A"}},
		}
		require.EqualError(t, pd.ValidateSchema(), errMsg)
	})
}

func TestPresentationDefinition_CreateVP(t *testing.T) {
	t.Run("Checks schema", func(t *testing.T) {
		pd := &PresentationDefinition{ID: uuid.New().String()}

		vp, err := pd.CreateVP()

		require.EqualError(t, err, "presentation_definition: input_descriptors is required")
		require.Nil(t, vp)
	})

	t.Run("Matches one credentials", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://www.w3.org/TR/vc-data-model/#types",
				}},
			}},
		}

		vp, err := pd.CreateVP(&verifiable.Credential{
			ID: uuid.New().String(),
			Schemas: []verifiable.TypedID{{
				ID: "https://www.w3.org/TR/vc-data-model/#types",
			}},
		})

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, len(vp.Credentials()), 1)

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("Matches two credentials", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://www.w3.org/TR/vc-data-model/#types",
				}},
			}},
		}

		vp, err := pd.CreateVP(&verifiable.Credential{
			ID: uuid.New().String(),
			Schemas: []verifiable.TypedID{{
				ID: "https://www.w3.org/TR/vc-data-model/#types",
			}},
		}, &verifiable.Credential{
			ID: uuid.New().String(),
			Schemas: []verifiable.TypedID{{
				ID: "https://www.w3.org/TR/vc-data-model/#types",
			}},
		})

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, len(vp.Credentials()), 2)

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("Matches one credentials (one ignored)", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://www.w3.org/TR/vc-data-model/#types",
				}},
			}},
		}

		vp, err := pd.CreateVP(&verifiable.Credential{
			ID: uuid.New().String(),
			Schemas: []verifiable.TypedID{{
				ID: "https://www.w3.org/TR/vc-data-model/#types",
			}},
		}, &verifiable.Credential{
			ID: uuid.New().String(),
			Schemas: []verifiable.TypedID{{
				ID: "https://www.w3.org/TR/vc-data-model/2.0/#types",
			}},
		})

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, len(vp.Credentials()), 1)

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("No matches", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://www.w3.org/TR/vc-data-model/1.0/#types",
				}},
			}},
		}

		vp, err := pd.CreateVP(&verifiable.Credential{
			ID: uuid.New().String(),
			Schemas: []verifiable.TypedID{{
				ID: "https://www.w3.org/TR/vc-data-model/2.0/#types",
			}},
		}, &verifiable.Credential{
			ID: uuid.New().String(),
			Schemas: []verifiable.TypedID{{
				ID: "https://www.w3.org/TR/vc-data-model/3.0/#types",
			}},
		})

		errMsg := "credentials do not satisfy requirements with schema [https://www.w3.org/TR/vc-data-model/1.0/#types]"
		require.EqualError(t, err, errMsg)
		require.Nil(t, vp)
	})

	t.Run("Matches two descriptors", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://www.w3.org/TR/vc-data-model/1.0/#types",
				}},
			}, {
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://www.w3.org/TR/vc-data-model/2.0/#types",
				}},
			}},
		}

		vp, err := pd.CreateVP(&verifiable.Credential{
			ID: uuid.New().String(),
			Schemas: []verifiable.TypedID{{
				ID: "https://www.w3.org/TR/vc-data-model/1.0/#types",
			}},
		}, &verifiable.Credential{
			ID: uuid.New().String(),
			Schemas: []verifiable.TypedID{{
				ID: "https://www.w3.org/TR/vc-data-model/2.0/#types",
			}},
		})

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, len(vp.Credentials()), 2)

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("Does not match one of descriptors", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://www.w3.org/TR/vc-data-model/1.0/#types",
				}},
			}, {
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://www.w3.org/TR/vc-data-model/2.0/#types",
				}},
			}},
		}

		vp, err := pd.CreateVP(&verifiable.Credential{
			ID: uuid.New().String(),
			Schemas: []verifiable.TypedID{{
				ID: "https://www.w3.org/TR/vc-data-model/1.0/#types",
			}},
		}, &verifiable.Credential{
			ID: uuid.New().String(),
			Schemas: []verifiable.TypedID{{
				ID: "https://www.w3.org/TR/vc-data-model/3.0/#types",
			}},
		})

		errMsg := "credentials do not satisfy requirements with schema [https://www.w3.org/TR/vc-data-model/2.0/#types]"
		require.EqualError(t, err, errMsg)
		require.Nil(t, vp)
	})

	t.Run("Does not match one of descriptors (required)", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://www.w3.org/TR/vc-data-model/1.0/#types",
				}},
			}, {
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://www.w3.org/TR/vc-data-model/2.0/#types",
				}, {
					URI:      "https://www.w3.org/TR/vc-data-model/3.0/#types",
					Required: true,
				}},
			}},
		}
		vp, err := pd.CreateVP(&verifiable.Credential{
			ID: uuid.New().String(),
			Schemas: []verifiable.TypedID{{
				ID: "https://www.w3.org/TR/vc-data-model/1.0/#types",
			}},
		}, &verifiable.Credential{
			ID: uuid.New().String(),
			Schemas: []verifiable.TypedID{{
				ID: "https://www.w3.org/TR/vc-data-model/2.0/#types",
			}},
		})
		errMsg := "credentials do not satisfy requirements with schema " +
			"[https://www.w3.org/TR/vc-data-model/2.0/#types required:https://www.w3.org/TR/vc-data-model/3.0/#types]"
		require.EqualError(t, err, errMsg)
		require.Nil(t, vp)
	})

	t.Run("Ignores schema that is not required", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://www.w3.org/TR/vc-data-model/1.0/#types",
				}},
			}, {
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://www.w3.org/TR/vc-data-model/2.0/#types",
				}, {
					URI:      "https://www.w3.org/TR/vc-data-model/3.0/#types",
					Required: true,
				}},
			}},
		}
		vp, err := pd.CreateVP(&verifiable.Credential{
			ID: uuid.New().String(),
			Schemas: []verifiable.TypedID{{
				ID: "https://www.w3.org/TR/vc-data-model/1.0/#types",
			}},
		}, &verifiable.Credential{
			ID: uuid.New().String(),
			Schemas: []verifiable.TypedID{{
				ID: "https://www.w3.org/TR/vc-data-model/3.0/#types",
			}},
		})

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, len(vp.Credentials()), 2)

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("Requires two schemas", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://www.w3.org/TR/vc-data-model/1.0/#types",
				}},
			}, {
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI:      "https://www.w3.org/TR/vc-data-model/2.0/#types",
					Required: true,
				}, {
					URI:      "https://www.w3.org/TR/vc-data-model/3.0/#types",
					Required: true,
				}},
			}},
		}
		vp, err := pd.CreateVP(&verifiable.Credential{
			ID: uuid.New().String(),
			Schemas: []verifiable.TypedID{{
				ID: "https://www.w3.org/TR/vc-data-model/1.0/#types",
			}},
		}, &verifiable.Credential{
			ID: uuid.New().String(),
			Schemas: []verifiable.TypedID{{
				ID: "https://www.w3.org/TR/vc-data-model/2.0/#types",
			}, {
				ID: "https://www.w3.org/TR/vc-data-model/3.0/#types",
			}},
		})

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, len(vp.Credentials()), 2)

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})
}

func checkSubmission(t *testing.T, vp *verifiable.Presentation, pd *PresentationDefinition) {
	t.Helper()

	ps, ok := vp.CustomFields["presentation_submission"].(PresentationSubmission)
	require.True(t, ok)
	require.NotEmpty(t, ps.ID)
	require.Equal(t, ps.DefinitionID, pd.ID)

	src, err := json.Marshal(vp)
	require.NoError(t, err)

	vpAsMap := map[string]interface{}{}
	require.NoError(t, json.Unmarshal(src, &vpAsMap))

	builder := gval.Full(jsonpath.PlaceholderExtension())

	for _, descriptor := range ps.DescriptorMap {
		require.NotEmpty(t, descriptor.ID)
		require.NotEmpty(t, descriptor.Path)
		require.NotEmpty(t, descriptor.Format)

		path, err := builder.NewEvaluable(descriptor.Path)
		require.NoError(t, err)
		_, err = path(context.TODO(), vpAsMap)
		require.NoError(t, err)
	}
}

func checkVP(t *testing.T, vp *verifiable.Presentation) {
	t.Helper()

	src, err := json.Marshal(vp)
	require.NoError(t, err)

	_, err = verifiable.ParseUnverifiedPresentation(src)
	require.NoError(t, err)
}

func parseJSONFile(t *testing.T, name string, v interface{}) {
	t.Helper()

	jf, err := os.Open(name) // nolint: gosec
	if err != nil {
		t.Error(err)
	}

	defer func() {
		if err = jf.Close(); err != nil {
			t.Error(err)
		}
	}()

	byteValue, err := ioutil.ReadAll(jf)
	if err != nil {
		t.Error(err)
	}

	if err = json.Unmarshal(byteValue, &v); err != nil {
		t.Error(err)
	}
}
