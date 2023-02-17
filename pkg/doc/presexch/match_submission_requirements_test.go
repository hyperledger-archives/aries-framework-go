/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presexch_test

import (
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

var (
	//go:embed testdata/presentation_definition.json
	presentationDefinition []byte

	//go:embed testdata/submission_requirements_pd.json
	submissionRequirementsPD []byte

	//go:embed testdata/nested_submission_requirements_pd.json
	nestedSubmissionRequirementsPD []byte

	//go:embed testdata/university_degree.jwt
	universityDegreeVC []byte

	//go:embed testdata/permanent_resident_card.jwt
	permanentResidentCardVC []byte

	//go:embed testdata/drivers_license.jwt
	driverLicenseVC []byte

	//go:embed testdata/drivers_license2.jwt
	driverLicenseVC2 []byte

	//go:embed testdata/verified_employee.jwt
	verifiedEmployeeVC []byte
)

const (
	driversLicenseVCType = "DriversLicense"
)

func TestInstance_GetSubmissionRequirements(t *testing.T) {
	docLoader := createTestJSONLDDocumentLoader(t)

	contents := [][]byte{
		universityDegreeVC,
		permanentResidentCardVC,
		driverLicenseVC,
		driverLicenseVC2,
		verifiedEmployeeVC,
	}

	var credentials []*verifiable.Credential

	for _, credContent := range contents {
		cred, credErr := verifiable.ParseCredential(credContent, verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(docLoader))
		require.NoError(t, credErr)

		credentials = append(credentials, cred)
	}

	t.Run("Success", func(t *testing.T) {
		pdQuery := &presexch.PresentationDefinition{}
		err := json.Unmarshal(presentationDefinition, pdQuery)
		require.NoError(t, err)

		requirements, err := pdQuery.MatchSubmissionRequirement(
			credentials,
			docLoader,
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(docLoader),
		)

		require.NoError(t, err)
		require.Len(t, requirements, 1)

		require.Len(t, requirements[0].Descriptors, 3)

		for _, desc := range requirements[0].Descriptors {
			if desc.ID == driversLicenseVCType {
				require.Len(t, desc.MatchedVCs, 2)
			}
		}
	})

	t.Run("Success with submission requirements", func(t *testing.T) {
		pdQuery := &presexch.PresentationDefinition{}
		err := json.Unmarshal(submissionRequirementsPD, pdQuery)
		require.NoError(t, err)

		requirements, err := pdQuery.MatchSubmissionRequirement(
			credentials,
			docLoader,
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(docLoader),
		)

		require.NoError(t, err)
		require.Len(t, requirements, 1)

		require.Len(t, requirements[0].Descriptors, 3)

		for _, desc := range requirements[0].Descriptors {
			if desc.ID == driversLicenseVCType {
				require.Len(t, desc.MatchedVCs, 2)
			}
		}
	})

	t.Run("Success with nested submission requirements", func(t *testing.T) {
		pdQuery := &presexch.PresentationDefinition{}
		err := json.Unmarshal(nestedSubmissionRequirementsPD, pdQuery)
		require.NoError(t, err)

		requirements, err := pdQuery.MatchSubmissionRequirement(
			credentials,
			docLoader,
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(docLoader),
		)

		require.NoError(t, err)
		require.Len(t, requirements, 1)

		require.Len(t, requirements[0].Descriptors, 0)
		require.Len(t, requirements[0].Nested, 2)

		for _, req := range requirements[0].Nested {
			if req.Name == "VerifiedEmployee or Degree" {
				require.Len(t, req.Descriptors, 2)
			}

			if req.Name == driversLicenseVCType {
				require.Len(t, req.Descriptors, 1)
				require.Len(t, req.Descriptors[0].MatchedVCs, 2)
			}
		}
	})

	t.Run("Checks schema", func(t *testing.T) {
		pd := &presexch.PresentationDefinition{ID: uuid.New().String()}

		vp, err := pd.MatchSubmissionRequirement(nil, nil)

		require.EqualError(t, err, "presentation_definition: input_descriptors is required")
		require.Nil(t, vp)
	})

	t.Run("Checks submission requirements (no descriptor)", func(t *testing.T) {
		issuerID := uuid.New().String()

		pd := &presexch.PresentationDefinition{
			ID: uuid.New().String(),
			SubmissionRequirements: []*presexch.SubmissionRequirement{
				{
					Rule: "all",
					From: "A",
				},
				{
					Rule:  "pick",
					Count: 1,
					FromNested: []*presexch.SubmissionRequirement{
						{
							Rule: "all",
							From: "teenager",
						},
					},
				},
			},
			InputDescriptors: []*presexch.InputDescriptor{{
				ID:    uuid.New().String(),
				Group: []string{"A"},
				Schema: []*presexch.Schema{{
					URI: verifiable.ContextURI,
				}},
				Constraints: &presexch.Constraints{
					SubjectIsIssuer: &subIsIssuerRequired,
					Fields: []*presexch.Field{{
						Path: []string{"$.first_name", "$.last_name"},
					}},
				},
			}},
		}

		result, err := pd.MatchSubmissionRequirement([]*verifiable.Credential{
			{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
				},
			}, {
				ID:      uuid.New().String(),
				Subject: []verifiable.Subject{{ID: issuerID}},
				Issuer:  verifiable.Issuer{ID: issuerID},
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
					"last_name":  "Travis",
					"age":        17,
				},
			},
		}, docLoader)

		require.EqualError(t, err, "no descriptors for from: teenager")
		require.Nil(t, result)
	})
}
