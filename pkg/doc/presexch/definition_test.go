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
	"strings"
	"testing"

	"github.com/PaesslerAG/gval"
	"github.com/PaesslerAG/jsonpath"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	. "github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

const errMsgSchema = "credentials do not satisfy requirements"

// nolint: gochecknoglobals
var (
	strFilterType = "string"
	arrFilterType = "array"
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

	t.Run("Checks submission requirements", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			SubmissionRequirements: []*SubmissionRequirement{{
				Rule: "all",
				From: "A",
			}},
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://www.w3.org/TR/vc-data-model/#types",
				}},
			}},
		}

		vp, err := pd.CreateVP()

		require.EqualError(t, err, "submission requirements is not supported yet")
		require.Nil(t, vp)
	})

	t.Run("Predicate (not supported)", func(t *testing.T) {
		predicate := Required

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://www.w3.org/TR/vc-data-model/#types",
				}},
				Constraints: &Constraints{
					Fields: []*Field{{
						Path:      []string{"$.first_name", "$.last_name"},
						Predicate: &predicate,
						Filter:    &Filter{Type: &strFilterType},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP(&verifiable.Credential{
			ID: uuid.New().String(),
			Schemas: []verifiable.TypedID{{
				ID: "https://www.w3.org/TR/vc-data-model/#types",
			}},
			CustomFields: map[string]interface{}{
				"first_name": "Jesse",
			},
		})

		require.EqualError(t, err, "filter field.0: predicate not supported yet")
		require.Nil(t, vp)
	})

	t.Run("Predicate (marshal error)", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://www.w3.org/TR/vc-data-model/#types",
				}},
				Constraints: &Constraints{
					Fields: []*Field{{
						Path:   []string{"$.last_name"},
						Filter: &Filter{Type: &strFilterType},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP(&verifiable.Credential{
			ID: uuid.New().String(),
			Schemas: []verifiable.TypedID{{
				ID: "https://www.w3.org/TR/vc-data-model/#types",
			}},
			CustomFields: map[string]interface{}{
				"first_name": make(chan struct{}),
				"last_name":  "Jon",
			},
		})

		require.EqualError(t, err, errMsgSchema)
		require.Nil(t, vp)
	})

	t.Run("No matches (path)", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://www.w3.org/TR/vc-data-model/#types",
				}},
				Constraints: &Constraints{
					Fields: []*Field{{
						Path: []string{"$.first_name", "$.last_name"},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP(&verifiable.Credential{
			ID: uuid.New().String(),
			Schemas: []verifiable.TypedID{{
				ID: "https://www.w3.org/TR/vc-data-model/#types",
			}},
			CustomFields: map[string]interface{}{
				"first_name": "Jesse",
			},
		}, &verifiable.Credential{
			ID: uuid.New().String(),
			Schemas: []verifiable.TypedID{{
				ID: "https://www.w3.org/TR/vc-data-model/#types",
			}},
			CustomFields: map[string]interface{}{
				"last_name": "Travis",
			},
		})

		require.EqualError(t, err, errMsgSchema)
		require.Nil(t, vp)
	})

	t.Run("No matches (one field path)", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://www.w3.org/TR/vc-data-model/#types",
				}},
				Constraints: &Constraints{
					Fields: []*Field{{
						Path: []string{"$.first_name"},
					}, {
						Path: []string{"$.last_name"},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP(&verifiable.Credential{
			ID: uuid.New().String(),
			Schemas: []verifiable.TypedID{{
				ID: "https://www.w3.org/TR/vc-data-model/#types",
			}},
			CustomFields: map[string]interface{}{
				"first_name": "Jesse",
			},
		}, &verifiable.Credential{
			ID: uuid.New().String(),
			Schemas: []verifiable.TypedID{{
				ID: "https://www.w3.org/TR/vc-data-model/#types",
			}},
			CustomFields: map[string]interface{}{
				"last_name": "Travis",
			},
		})

		require.EqualError(t, err, errMsgSchema)
		require.Nil(t, vp)
	})

	t.Run("Matches one credentials (two fields)", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://www.w3.org/TR/vc-data-model/#types",
				}},
				Constraints: &Constraints{
					Fields: []*Field{{
						Path:   []string{"$.first_name"},
						Filter: &Filter{Type: &strFilterType},
					}, {
						Path:   []string{"$.last_name"},
						Filter: &Filter{Type: &strFilterType},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP(&verifiable.Credential{
			ID: uuid.New().String(),
			Schemas: []verifiable.TypedID{{
				ID: "https://www.w3.org/TR/vc-data-model/#types",
			}},
			CustomFields: map[string]interface{}{
				"first_name": "Jesse",
			},
		}, &verifiable.Credential{
			ID: uuid.New().String(),
			Schemas: []verifiable.TypedID{{
				ID: "https://www.w3.org/TR/vc-data-model/#types",
			}},
			CustomFields: map[string]interface{}{
				"first_name": "Jesse",
				"last_name":  "Travis",
			},
		})

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, len(vp.Credentials()), 1)

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("Matches one credentials (three fields - disclosure)", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://www.w3.org/TR/vc-data-model/#types",
				}},
				Constraints: &Constraints{
					LimitDisclosure: true,
					Fields: []*Field{{
						Path:   []string{"$.first_name"},
						Filter: &Filter{Type: &strFilterType},
					}, {
						Path:   []string{"$.issuer"},
						Filter: &Filter{Type: &strFilterType},
					}, {
						Path: []string{"$.all[*].authors[*].name"},
						Filter: &Filter{
							Type: &arrFilterType,
						},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP(&verifiable.Credential{
			ID:      uuid.New().String(),
			Context: []string{"https://www.w3.org/2018/credentials/v1"},
			Types:   []string{"VerifiableCredential"},
			Issuer:  verifiable.Issuer{ID: uuid.New().String()},
			Schemas: []verifiable.TypedID{{
				ID: "https://www.w3.org/TR/vc-data-model/#types",
			}},
			CustomFields: map[string]interface{}{
				"last_name": "Travis",
			},
		}, &verifiable.Credential{
			ID:      uuid.New().String(),
			Context: []string{"https://www.w3.org/2018/credentials/v1"},
			Types:   []string{"VerifiableCredential"},
			Issuer:  verifiable.Issuer{ID: uuid.New().String()},
			Schemas: []verifiable.TypedID{{
				ID: "https://www.w3.org/TR/vc-data-model/#types",
			}},
			CustomFields: map[string]interface{}{
				"first_name": "Jesse",
				"ssn":        "000-00-000",
				"last_name":  "Travis",
				"all": []interface{}{
					map[string]interface{}{
						"authors": []interface{}{map[string]interface{}{
							"name":    "Andrew",
							"license": "yes",
						}, map[string]interface{}{
							"name":    "Jessy",
							"license": "no",
						}},
					},
					map[string]interface{}{
						"authors": []interface{}{map[string]interface{}{
							"license": "unknown",
						}},
					},
					map[string]interface{}{
						"authors": []interface{}{map[string]interface{}{
							"name":    "Bob",
							"license": "yes",
						}, map[string]interface{}{
							"name":    "Carol",
							"license": "no",
						}},
					},
				},
			},
		})

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 1, len(vp.Credentials()))

		cred, ok := vp.Credentials()[0].(*verifiable.Credential)
		require.True(t, ok)
		require.NotEmpty(t, cred.Issuer)

		require.EqualValues(t, []interface{}{
			map[string]interface{}{
				"authors": []interface{}{map[string]interface{}{
					"name": "Andrew",
				}, map[string]interface{}{
					"name": "Jessy",
				}},
			},
			map[string]interface{}{
				"authors": []interface{}{map[string]interface{}{
					"name": "Bob",
				}, map[string]interface{}{
					"name": "Carol",
				}},
			},
		}, cred.CustomFields["all"])

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("Create new credential (error)", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://www.w3.org/TR/vc-data-model/#types",
				}},
				Constraints: &Constraints{
					LimitDisclosure: true,
					Fields: []*Field{{
						Path: []string{"$.first_name"},
						Filter: &Filter{
							Type:    &strFilterType,
							Pattern: "^Jesse",
						},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP(&verifiable.Credential{
			ID:     uuid.New().String(),
			Issuer: verifiable.Issuer{CustomFields: map[string]interface{}{"k": "v"}},
			Schemas: []verifiable.TypedID{{
				ID: "https://www.w3.org/TR/vc-data-model/#types",
			}},
			CustomFields: map[string]interface{}{
				"first_name": "Jesse",
			},
		})

		require.Error(t, err)
		require.True(t, strings.HasPrefix(err.Error(), "create new credential"))
		require.Nil(t, vp)
	})

	t.Run("Matches one credentials (field pattern)", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://www.w3.org/TR/vc-data-model/#types",
				}},
				Constraints: &Constraints{
					Fields: []*Field{{
						Path: []string{"$.first_name"},
						Filter: &Filter{
							Type:    &strFilterType,
							Pattern: "^Jesse",
						},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP(&verifiable.Credential{
			ID: uuid.New().String(),
			Schemas: []verifiable.TypedID{{
				ID: "https://www.w3.org/TR/vc-data-model/#types",
			}},
			CustomFields: map[string]interface{}{
				"first_name": "Jesse",
			},
		}, &verifiable.Credential{
			ID: uuid.New().String(),
			Schemas: []verifiable.TypedID{{
				ID: "https://www.w3.org/TR/vc-data-model/#types",
			}},
			CustomFields: map[string]interface{}{
				"first_name": "Travis",
				"last_name":  "Jesse",
			},
		})

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, len(vp.Credentials()), 1)

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("Matches one credentials", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://www.w3.org/TR/vc-data-model/#types",
				}},
				Constraints: &Constraints{
					Fields: []*Field{{
						Path: []string{"$.first_name", "$.last_name"},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP(&verifiable.Credential{
			ID: uuid.New().String(),
			Schemas: []verifiable.TypedID{{
				ID: "https://www.w3.org/TR/vc-data-model/#types",
			}},
			CustomFields: map[string]interface{}{
				"first_name": "Jesse",
			},
		}, &verifiable.Credential{
			ID: uuid.New().String(),
			Schemas: []verifiable.TypedID{{
				ID: "https://www.w3.org/TR/vc-data-model/#types",
			}},
			CustomFields: map[string]interface{}{
				"first_name": "Jesse",
				"last_name":  "Travis",
			},
		})

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, len(vp.Credentials()), 1)

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("Matches one credentials (two descriptors)", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://www.w3.org/TR/vc-data-model/#types",
				}},
				Constraints: &Constraints{
					Fields: []*Field{{
						Path: []string{"$.first_name", "$.last_name"},
					}},
				},
			}, {
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://www.w3.org/TR/vc-data-model/#types",
				}},
				Constraints: &Constraints{
					Fields: []*Field{{
						Path: []string{"$.first_name", "$.last_name"},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP(&verifiable.Credential{
			ID: uuid.New().String(),
			Schemas: []verifiable.TypedID{{
				ID: "https://www.w3.org/TR/vc-data-model/#types",
			}},
			CustomFields: map[string]interface{}{
				"first_name": "Jesse",
			},
		}, &verifiable.Credential{
			ID: uuid.New().String(),
			Schemas: []verifiable.TypedID{{
				ID: "https://www.w3.org/TR/vc-data-model/#types",
			}},
			CustomFields: map[string]interface{}{
				"first_name": "Jesse",
				"last_name":  "Travis",
			},
		})

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, len(vp.Credentials()), 1)

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("Matches two credentials (one descriptor)", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: "https://www.w3.org/TR/vc-data-model/#types",
				}},
				Constraints: &Constraints{
					Fields: []*Field{{
						Path: []string{"$.first_name"},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP(&verifiable.Credential{
			ID: uuid.New().String(),
			Schemas: []verifiable.TypedID{{
				ID: "https://www.w3.org/TR/vc-data-model/#types",
			}},
			CustomFields: map[string]interface{}{
				"first_name": "Jesse",
			},
		}, &verifiable.Credential{
			ID: uuid.New().String(),
			Schemas: []verifiable.TypedID{{
				ID: "https://www.w3.org/TR/vc-data-model/#types",
			}},
			CustomFields: map[string]interface{}{
				"first_name": "Jesse",
				"last_name":  "Travis",
			},
		})

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, len(vp.Credentials()), 2)

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

		require.EqualError(t, err, errMsgSchema)
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

		require.EqualError(t, err, errMsgSchema)
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

		require.EqualError(t, err, errMsgSchema)
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

	require.GreaterOrEqual(t, len(ps.DescriptorMap), len(pd.InputDescriptors))

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
