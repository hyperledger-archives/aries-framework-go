/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presexch_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/PaesslerAG/gval"
	"github.com/PaesslerAG/jsonpath"
	"github.com/google/uuid"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
	. "github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/bbsblssignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

const errMsgSchema = "credentials do not satisfy requirements"

// nolint: gochecknoglobals
var (
	strFilterType = "string"
	arrFilterType = "array"
	intFilterType = "integer"

	subIsIssuerRequired = Required
	// schemaURI is being set in init() function.
	schemaURI string
)

// nolint: gochecknoinits
func init() {
	server := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		res.WriteHeader(http.StatusOK)
		//nolint: gosec,errcheck
		res.Write([]byte(verifiable.DefaultSchema))
	}))

	schemaURI = server.URL
}

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

		vp, err := pd.CreateVP(nil)

		require.EqualError(t, err, "presentation_definition: input_descriptors is required")
		require.Nil(t, vp)
	})

	t.Run("Checks submission requirements", func(t *testing.T) {
		issuerID := uuid.New().String()

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			SubmissionRequirements: []*SubmissionRequirement{
				{
					Rule: "all",
					From: "A",
				},
				{
					Rule:  "pick",
					Count: 1,
					FromNested: []*SubmissionRequirement{
						{
							Rule: "all",
							From: "teenager",
						},
						{
							Rule: "all",
							From: "child",
						},
						{
							Rule: "pick",
							From: "adult",
							Min:  2,
						},
					},
				},
			},
			InputDescriptors: []*InputDescriptor{{
				ID:    uuid.New().String(),
				Group: []string{"A"},
				Schema: []*Schema{{
					URI: schemaURI,
				}},
				Constraints: &Constraints{
					SubjectIsIssuer: &subIsIssuerRequired,
					Fields: []*Field{{
						Path: []string{"$.first_name", "$.last_name"},
					}},
				},
			}, {
				ID:    uuid.New().String(),
				Group: []string{"child"},
				Schema: []*Schema{{
					URI: schemaURI,
				}},
				Constraints: &Constraints{
					SubjectIsIssuer: &subIsIssuerRequired,
					Fields: []*Field{{
						Path: []string{"$.age"},
						Filter: &Filter{
							Type:    &intFilterType,
							Minimum: 3,
							Maximum: 12,
						},
					}},
				},
			}, {
				ID:    uuid.New().String(),
				Group: []string{"teenager"},
				Schema: []*Schema{{
					URI: schemaURI,
				}},
				Constraints: &Constraints{
					SubjectIsIssuer: &subIsIssuerRequired,
					Fields: []*Field{{
						Path: []string{"$.age"},
						Filter: &Filter{
							Type:    &intFilterType,
							Minimum: 13,
							Maximum: 17,
						},
					}},
				},
			}, {
				ID:    uuid.New().String(),
				Group: []string{"adult"},
				Schema: []*Schema{{
					URI: schemaURI,
				}},
				Constraints: &Constraints{
					SubjectIsIssuer: &subIsIssuerRequired,
					Fields: []*Field{{
						Path: []string{"$.age"},
						Filter: &Filter{
							Type:    &intFilterType,
							Minimum: 18,
							Maximum: 23,
						},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID:   schemaURI,
					Type: "JsonSchemaValidator2018",
				}},
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
				},
			},
			{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Subject: []verifiable.Subject{{ID: issuerID}},
				Issuer:  verifiable.Issuer{ID: issuerID},
				Schemas: []verifiable.TypedID{{
					ID: schemaURI,
				}},
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
					"last_name":  "Travis",
					"age":        17,
				},
			},
			{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Subject: []verifiable.Subject{{ID: issuerID}},
				Issuer:  verifiable.Issuer{ID: issuerID},
				Schemas: []verifiable.TypedID{{
					ID: schemaURI,
				}},
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
					"last_name":  "Travis",
					"age":        2,
				},
			},
		})

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 1, len(vp.Credentials()))

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("Checks submission requirements (no descriptor)", func(t *testing.T) {
		issuerID := uuid.New().String()

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			SubmissionRequirements: []*SubmissionRequirement{
				{
					Rule: "all",
					From: "A",
				},
				{
					Rule:  "pick",
					Count: 1,
					FromNested: []*SubmissionRequirement{
						{
							Rule: "all",
							From: "teenager",
						},
					},
				},
			},
			InputDescriptors: []*InputDescriptor{{
				ID:    uuid.New().String(),
				Group: []string{"A"},
				Schema: []*Schema{{
					URI: schemaURI,
				}},
				Constraints: &Constraints{
					SubjectIsIssuer: &subIsIssuerRequired,
					Fields: []*Field{{
						Path: []string{"$.first_name", "$.last_name"},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID:   schemaURI,
					Type: "JsonSchemaValidator2018",
				}},
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
				},
			}, {
				ID:      uuid.New().String(),
				Subject: []verifiable.Subject{{ID: issuerID}},
				Issuer:  verifiable.Issuer{ID: issuerID},
				Schemas: []verifiable.TypedID{{
					ID: schemaURI,
				}},
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
					"last_name":  "Travis",
					"age":        17,
				},
			},
		})

		require.EqualError(t, err, "no descriptors for from: teenager")
		require.Nil(t, vp)
	})

	t.Run("Predicate", func(t *testing.T) {
		predicate := Required

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: schemaURI,
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

		vp, err := pd.CreateVP([]*verifiable.Credential{
			{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      "http://example.edu/credentials/1872",
				Schemas: []verifiable.TypedID{{
					ID:   schemaURI,
					Type: "JsonSchemaValidator2018",
				}},
				Subject: "did:example:76e12ec712ebc6f1c221ebfeb1f",
				Issued: &util.TimeWithTrailingZeroMsec{
					Time: time.Now(),
				},
				Issuer: verifiable.Issuer{
					ID: "did:example:76e12ec712ebc6f1c221ebfeb1f",
				},
				CustomFields: map[string]interface{}{
					"first_name": "First name",
					"last_name":  "Last name",
					"info":       "Info",
				},
			},
		})

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 1, len(vp.Credentials()))

		vc, ok := vp.Credentials()[0].(*verifiable.Credential)
		require.True(t, ok)

		require.True(t, vc.CustomFields["first_name"].(bool))
		require.True(t, vc.CustomFields["last_name"].(bool))
		require.EqualValues(t, "Info", vc.CustomFields["info"])

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("Predicate (limit disclosure)", func(t *testing.T) {
		predicate := Required

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: schemaURI,
				}},
				Constraints: &Constraints{
					LimitDisclosure: true,
					Fields: []*Field{{
						Path:      []string{"$.first_name", "$.last_name"},
						Predicate: &predicate,
						Filter:    &Filter{Type: &strFilterType},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      "http://example.edu/credentials/1872",
				Schemas: []verifiable.TypedID{{
					ID:   schemaURI,
					Type: "JsonSchemaValidator2018",
				}},
				Subject: "did:example:76e12ec712ebc6f1c221ebfeb1f",
				Issued: &util.TimeWithTrailingZeroMsec{
					Time: time.Now(),
				},
				Issuer: verifiable.Issuer{
					ID: "did:example:76e12ec712ebc6f1c221ebfeb1f",
				},
				CustomFields: map[string]interface{}{
					"first_name": "First name",
					"last_name":  "Last name",
					"info":       "Info",
				},
			},
		})

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 1, len(vp.Credentials()))

		vc, ok := vp.Credentials()[0].(*verifiable.Credential)
		require.True(t, ok)

		require.True(t, vc.CustomFields["first_name"].(bool))
		require.True(t, vc.CustomFields["last_name"].(bool))

		_, ok = vc.CustomFields["info"]
		require.False(t, ok)

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("Limit disclosure BBS+", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				Schema: []*Schema{{
					URI: schemaURI,
				}},
				ID: uuid.New().String(),
				Constraints: &Constraints{
					LimitDisclosure: true,
					Fields: []*Field{{
						Path:   []string{"$.credentialSubject.degree.degreeSchool"},
						Filter: &Filter{Type: &strFilterType},
					}},
				},
			}},
		}

		vc := &verifiable.Credential{
			ID: "https://issuer.oidp.uscis.gov/credentials/83627465",
			Context: []string{
				"https://www.w3.org/2018/credentials/v1",
				"https://www.w3.org/2018/credentials/examples/v1",
				"https://w3id.org/security/bbs/v1",
			},
			Types: []string{
				"VerifiableCredential",
				"UniversityDegreeCredential",
			},
			Schemas: []verifiable.TypedID{{
				ID:   schemaURI,
				Type: "JsonSchemaValidator2018",
			}},
			Subject: verifiable.Subject{
				ID: "did:example:b34ca6cd37bbf23",
				CustomFields: map[string]interface{}{
					"name":   "Jayden Doe",
					"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1",
					"degree": map[string]interface{}{
						"degree":       "MIT",
						"degreeSchool": "MIT school",
						"type":         "BachelorDegree",
					},
				},
			},
			Issued: &util.TimeWithTrailingZeroMsec{
				Time: time.Now(),
			},
			Expired: &util.TimeWithTrailingZeroMsec{
				Time: time.Now().AddDate(1, 0, 0),
			},
			Issuer: verifiable.Issuer{
				ID: "did:example:489398593",
			},
			CustomFields: map[string]interface{}{
				"identifier":  "83627465",
				"name":        "Permanent Resident Card",
				"description": "Government of Example Permanent Resident Card.",
			},
		}

		publicKey, privateKey, err := bbs12381g2pub.GenerateKeyPair(sha256.New, nil)
		require.NoError(t, err)

		srcPublicKey, err := publicKey.Marshal()
		require.NoError(t, err)

		signer, err := newBBSSigner(privateKey)
		require.NoError(t, err)

		require.NoError(t, vc.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
			SignatureType:           "BbsBlsSignature2020",
			SignatureRepresentation: verifiable.SignatureProofValue,
			Suite:                   bbsblssignature2020.New(suite.WithSigner(signer)),
			VerificationMethod:      "did:example:123456#key1",
		}, jsonld.WithDocumentLoader(createTestJSONLDDocumentLoader())))

		vp, err := pd.CreateVP([]*verifiable.Credential{vc},
			verifiable.WithJSONLDDocumentLoader(createTestJSONLDDocumentLoader()),
			verifiable.WithPublicKeyFetcher(verifiable.SingleKey(srcPublicKey, "Bls12381G2Key2020")),
		)
		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 1, len(vp.Credentials()))

		vc, ok := vp.Credentials()[0].(*verifiable.Credential)
		require.True(t, ok)

		subject := vc.Subject.([]verifiable.Subject)[0]
		degree := subject.CustomFields["degree"]
		require.NotNil(t, degree)

		degreeMap, ok := degree.(map[string]interface{})
		require.True(t, ok)

		require.Equal(t, "MIT school", degreeMap["degreeSchool"])
		require.Equal(t, "BachelorDegree", degreeMap["type"])
		require.Empty(t, degreeMap["degree"])
		require.Equal(t, "did:example:b34ca6cd37bbf23", subject.ID)
		require.Empty(t, subject.CustomFields["spouse"])
		require.Empty(t, vc.CustomFields["name"])

		require.NotEmpty(t, vc.Proofs)

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("Predicate and limit disclosure BBS+ (no proof)", func(t *testing.T) {
		predicate := Required

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				Schema: []*Schema{{
					URI: schemaURI,
				}},
				ID: uuid.New().String(),
				Constraints: &Constraints{
					LimitDisclosure: true,
					Fields: []*Field{{
						Path:      []string{"$.credentialSubject.givenName", "$.credentialSubject.familyName"},
						Filter:    &Filter{Type: &strFilterType},
						Predicate: &predicate,
					}, {
						Path:   []string{"$.credentialSubject.type"},
						Filter: &Filter{Type: &arrFilterType},
					}},
				},
			}},
		}

		vc := &verifiable.Credential{
			ID: "https://issuer.oidp.uscis.gov/credentials/83627465",
			Context: []string{
				"https://www.w3.org/2018/credentials/v1",
				"https://w3id.org/citizenship/v1",
				"https://w3id.org/security/bbs/v1",
			},
			Types: []string{
				"VerifiableCredential",
				"PermanentResidentCard",
			},
			Schemas: []verifiable.TypedID{{
				ID:   schemaURI,
				Type: "JsonSchemaValidator2018",
			}},
			Subject: verifiable.Subject{
				ID: "did:example:b34ca6cd37bbf23",
				CustomFields: map[string]interface{}{
					"type": []string{
						"PermanentResident",
						"Person",
					},
					"givenName":              "JOHN",
					"familyName":             "SMITH",
					"gender":                 "Male",
					"image":                  "data:image/png;base64,iVBORw0KGgokJggg==",
					"residentSince":          "2015-01-01",
					"lprCategory":            "C09",
					"lprNumber":              "999-999-999",
					"commuterClassification": "C1",
					"birthCountry":           "Bahamas",
					"birthDate":              "1958-07-17",
				},
			},
			Issued: &util.TimeWithTrailingZeroMsec{
				Time: time.Now(),
			},
			Expired: &util.TimeWithTrailingZeroMsec{
				Time: time.Now().AddDate(1, 0, 0),
			},
			Issuer: verifiable.Issuer{
				ID: "did:example:489398593",
			},
			CustomFields: map[string]interface{}{
				"identifier":  "83627465",
				"name":        "Permanent Resident Card",
				"description": "Government of Example Permanent Resident Card.",
			},
		}

		publicKey, privateKey, err := bbs12381g2pub.GenerateKeyPair(sha256.New, nil)
		require.NoError(t, err)

		srcPublicKey, err := publicKey.Marshal()
		require.NoError(t, err)

		signer, err := newBBSSigner(privateKey)
		require.NoError(t, err)

		require.NoError(t, vc.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
			SignatureType:           "BbsBlsSignature2020",
			SignatureRepresentation: verifiable.SignatureProofValue,
			Suite:                   bbsblssignature2020.New(suite.WithSigner(signer)),
			VerificationMethod:      "did:example:123456#key1",
		}, jsonld.WithDocumentLoader(createTestJSONLDDocumentLoader())))

		vp, err := pd.CreateVP([]*verifiable.Credential{vc},
			verifiable.WithJSONLDDocumentLoader(createTestJSONLDDocumentLoader()),
			verifiable.WithPublicKeyFetcher(verifiable.SingleKey(srcPublicKey, "Bls12381G2Key2020")),
		)
		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 1, len(vp.Credentials()))

		vc, ok := vp.Credentials()[0].(*verifiable.Credential)
		require.True(t, ok)

		require.Equal(t, true, vc.Subject.([]verifiable.Subject)[0].CustomFields["givenName"])
		require.Equal(t, true, vc.Subject.([]verifiable.Subject)[0].CustomFields["familyName"])
		require.Empty(t, vc.Subject.([]verifiable.Subject)[0].CustomFields["gender"])
		require.Empty(t, vc.Proofs)

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("Predicate (marshal error)", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: schemaURI,
				}},
				Constraints: &Constraints{
					Fields: []*Field{{
						Path:   []string{"$.last_name"},
						Filter: &Filter{Type: &strFilterType},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID:   schemaURI,
					Type: "JsonSchemaValidator2018",
				}},
				CustomFields: map[string]interface{}{
					"first_name": make(chan struct{}),
					"last_name":  "Jon",
				},
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
					URI: schemaURI,
				}},
				Constraints: &Constraints{
					Fields: []*Field{{
						Path: []string{"$.first_name", "$.last_name"},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID:   schemaURI,
					Type: "JsonSchemaValidator2018",
				}},
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
				},
			},
			{
				ID: uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID: schemaURI,
				}},
				CustomFields: map[string]interface{}{
					"last_name": "Travis",
				},
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
					URI: schemaURI,
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

		vp, err := pd.CreateVP([]*verifiable.Credential{
			{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID:   schemaURI,
					Type: "JsonSchemaValidator2018",
				}},
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
				},
			},
			{
				ID: uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID: schemaURI,
				}},
				CustomFields: map[string]interface{}{
					"last_name": "Travis",
				},
			},
		})

		require.EqualError(t, err, errMsgSchema)
		require.Nil(t, vp)
	})

	t.Run("Matches one credentials (two fields)", func(t *testing.T) {
		issuerID := uuid.New().String()

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: schemaURI,
				}},
				Constraints: &Constraints{
					SubjectIsIssuer: &subIsIssuerRequired,
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

		vp, err := pd.CreateVP([]*verifiable.Credential{
			{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Subject: map[string]interface{}{},
				Schemas: []verifiable.TypedID{{
					ID:   schemaURI,
					Type: "JsonSchemaValidator2018",
				}},
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
				},
			}, {
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Subject: verifiable.Subject{ID: issuerID},
				Issuer:  verifiable.Issuer{ID: issuerID},
				Schemas: []verifiable.TypedID{{
					ID: schemaURI,
				}},
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
					"last_name":  "Travis",
				},
			},
		})

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 1, len(vp.Credentials()))

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("Matches one credentials (three fields - disclosure)", func(t *testing.T) {
		issuerID := "did:example:76e12ec712ebc6f1c221ebfeb1f"

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: schemaURI,
				}},
				Constraints: &Constraints{
					SubjectIsIssuer: &subIsIssuerRequired,
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

		vp, err := pd.CreateVP([]*verifiable.Credential{
			{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Subject: []map[string]interface{}{{}},
				Issuer:  verifiable.Issuer{ID: uuid.New().String()},
				Schemas: []verifiable.TypedID{{
					ID:   schemaURI,
					Type: "JsonSchemaValidator2018",
				}},
				CustomFields: map[string]interface{}{
					"last_name": "Travis",
				},
			},
			{
				ID:      "http://example.edu/credentials/1872",
				Context: []string{"https://www.w3.org/2018/credentials/v1"},
				Types:   []string{"VerifiableCredential"},
				Subject: []map[string]interface{}{{"id": issuerID}},
				Issuer:  verifiable.Issuer{ID: issuerID},
				Schemas: []verifiable.TypedID{{
					ID:   schemaURI,
					Type: "JsonSchemaValidator2018",
				}},
				Issued: &util.TimeWithTrailingZeroMsec{
					Time: time.Now(),
				},
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
					URI: schemaURI,
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

		vp, err := pd.CreateVP([]*verifiable.Credential{
			{
				ID:     uuid.New().String(),
				Issuer: verifiable.Issuer{CustomFields: map[string]interface{}{"k": "v"}},
				Schemas: []verifiable.TypedID{{
					ID:   schemaURI,
					Type: "JsonSchemaValidator2018",
				}},
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
				},
			},
		})

		require.Error(t, err)
		require.True(t, strings.HasPrefix(err.Error(), "create new credential"))
		require.Nil(t, vp)
	})

	t.Run("Matches one credentials (field pattern)", func(t *testing.T) {
		issuerID := uuid.New().String()

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: schemaURI,
				}},
				Constraints: &Constraints{
					SubjectIsIssuer: &subIsIssuerRequired,
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

		vp, err := pd.CreateVP([]*verifiable.Credential{
			{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Subject: map[string]interface{}{"id": issuerID},
				Issuer:  verifiable.Issuer{ID: issuerID},
				Schemas: []verifiable.TypedID{{
					ID:   schemaURI,
					Type: "JsonSchemaValidator2018",
				}},
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
				},
			},
			{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Subject: map[string]interface{}{"id": 123},
				Schemas: []verifiable.TypedID{{
					ID: schemaURI,
				}},
				CustomFields: map[string]interface{}{
					"first_name": "Travis",
					"last_name":  "Jesse",
				},
			},
		})

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 1, len(vp.Credentials()))

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("Matches one credentials", func(t *testing.T) {
		issuerID := uuid.New().String()

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: schemaURI,
				}},
				Constraints: &Constraints{
					SubjectIsIssuer: &subIsIssuerRequired,
					Fields: []*Field{{
						Path: []string{"$.first_name", "$.last_name"},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID:   schemaURI,
					Type: "JsonSchemaValidator2018",
				}},
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
				},
			},
			{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Subject: []verifiable.Subject{{ID: issuerID}},
				Issuer:  verifiable.Issuer{ID: issuerID},
				Schemas: []verifiable.TypedID{{
					ID: schemaURI,
				}},
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
					"last_name":  "Travis",
				},
			},
		})

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 1, len(vp.Credentials()))

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("Matches one credentials (two descriptors)", func(t *testing.T) {
		issuerID := uuid.New().String()

		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: schemaURI,
				}},
				Constraints: &Constraints{
					SubjectIsIssuer: &subIsIssuerRequired,
					Fields: []*Field{{
						Path: []string{"$.first_name", "$.last_name"},
					}},
				},
			}, {
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: schemaURI,
				}},
				Constraints: &Constraints{
					Fields: []*Field{{
						Path: []string{"$.first_name", "$.last_name"},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Subject: issuerID,
				Issuer:  verifiable.Issuer{ID: issuerID},
				Schemas: []verifiable.TypedID{{
					ID:   schemaURI,
					Type: "JsonSchemaValidator2018",
				}},
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
				},
			},
			{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Subject: issuerID,
				Issuer:  verifiable.Issuer{ID: issuerID},
				Schemas: []verifiable.TypedID{{
					ID: schemaURI,
				}},
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
					"last_name":  "Travis",
				},
			},
		})

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 1, len(vp.Credentials()))

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("Matches two credentials (one descriptor)", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: schemaURI,
				}},
				Constraints: &Constraints{
					Fields: []*Field{{
						Path: []string{"$.first_name"},
					}},
				},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID:   schemaURI,
					Type: "JsonSchemaValidator2018",
				}},
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
				},
			},
			{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID: schemaURI,
				}},
				CustomFields: map[string]interface{}{
					"first_name": "Jesse",
					"last_name":  "Travis",
				},
			},
		})

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 2, len(vp.Credentials()))

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("Matches two credentials", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: schemaURI,
				}},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID:   schemaURI,
					Type: "JsonSchemaValidator2018",
				}},
			},
			{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID: schemaURI,
				}},
			},
		})

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 2, len(vp.Credentials()))

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})

	t.Run("Matches one credentials (one ignored)", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: schemaURI,
				}},
			}},
		}

		vp, err := pd.CreateVP([]*verifiable.Credential{
			{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID:   schemaURI,
					Type: "JsonSchemaValidator2018",
				}},
			},
			{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID: "https://www.w3.org/TR/vc-data-model/2.0/#types",
				}},
			},
		})

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 1, len(vp.Credentials()))

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

		vp, err := pd.CreateVP([]*verifiable.Credential{
			{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID:   "https://www.w3.org/TR/vc-data-model/2.0/#types",
					Type: "JsonSchemaValidator2018",
				}},
			},
			{
				ID: uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID:   "https://www.w3.org/TR/vc-data-model/3.0/#types",
					Type: "JsonSchemaValidator2018",
				}},
			},
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

		vp, err := pd.CreateVP([]*verifiable.Credential{
			{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID:   "https://www.w3.org/TR/vc-data-model/1.0/#types",
					Type: "JsonSchemaValidator2018",
				}},
			},
			{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID:   "https://www.w3.org/TR/vc-data-model/2.0/#types",
					Type: "JsonSchemaValidator2018",
				}},
			},
		})

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 2, len(vp.Credentials()))

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

		vp, err := pd.CreateVP([]*verifiable.Credential{
			{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID:   "https://www.w3.org/TR/vc-data-model/1.0/#types",
					Type: "JsonSchemaValidator2018",
				}},
			},
			{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID:   "https://www.w3.org/TR/vc-data-model/3.0/#types",
					Type: "JsonSchemaValidator2018",
				}},
			},
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
		vp, err := pd.CreateVP([]*verifiable.Credential{
			{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID:   "https://www.w3.org/TR/vc-data-model/1.0/#types",
					Type: "JsonSchemaValidator2018",
				}},
			},
			{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID: "https://www.w3.org/TR/vc-data-model/2.0/#types",
				}},
			},
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
		vp, err := pd.CreateVP([]*verifiable.Credential{
			{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID:   "https://www.w3.org/TR/vc-data-model/1.0/#types",
					Type: "JsonSchemaValidator2018",
				}},
			},
			{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID: "https://www.w3.org/TR/vc-data-model/3.0/#types",
				}},
			},
		})

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 2, len(vp.Credentials()))

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
		vp, err := pd.CreateVP([]*verifiable.Credential{
			{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID:   "https://www.w3.org/TR/vc-data-model/1.0/#types",
					Type: "JsonSchemaValidator2018",
				}},
			},
			{
				Context: []string{verifiable.ContextURI},
				Types:   []string{verifiable.VCType},
				ID:      uuid.New().String(),
				Schemas: []verifiable.TypedID{{
					ID: "https://www.w3.org/TR/vc-data-model/2.0/#types",
				}, {
					ID: "https://www.w3.org/TR/vc-data-model/3.0/#types",
				}},
			},
		})

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, 2, len(vp.Credentials()))

		checkSubmission(t, vp, pd)
		checkVP(t, vp)
	})
}

func checkSubmission(t *testing.T, vp *verifiable.Presentation, pd *PresentationDefinition) {
	t.Helper()

	ps, ok := vp.CustomFields["presentation_submission"].(*PresentationSubmission)
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

	_, err = verifiable.ParsePresentation(src,
		verifiable.WithPresDisabledProofCheck(),
		verifiable.WithPresJSONLDDocumentLoader(createTestJSONLDDocumentLoader()))
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

type bbsSigner struct {
	privateKey []byte
}

func newBBSSigner(key *bbs12381g2pub.PrivateKey) (*bbsSigner, error) { //nolint:interfacer
	src, err := key.Marshal()
	if err != nil {
		return nil, err
	}

	return &bbsSigner{privateKey: src}, nil
}

func (s *bbsSigner) Sign(data []byte) ([]byte, error) {
	return bbs12381g2pub.New().Sign(s.textToLines(string(data)), s.privateKey)
}

func (s *bbsSigner) textToLines(txt string) [][]byte {
	lines := strings.Split(txt, "\n")
	linesBytes := make([][]byte, 0, len(lines))

	for i := range lines {
		if strings.TrimSpace(lines[i]) != "" {
			linesBytes = append(linesBytes, []byte(lines[i]))
		}
	}

	return linesBytes
}

func createTestJSONLDDocumentLoader() *ld.CachingDocumentLoader {
	loader := CachingJSONLDLoader()

	reader, err := ld.DocumentFromReader(strings.NewReader(contextBBSContent))
	if err != nil {
		panic(err)
	}

	loader.AddDocument("https://w3id.org/security/bbs/v1", reader)

	return loader
}

const contextBBSContent = `{
  "@context": {
    "@version": 1.1,
    "id": "@id",
    "type": "@type",
    "ldssk": "https://w3id.org/security#",
    "BbsBlsSignature2020": {
      "@id": "https://w3id.org/security#BbsBlsSignature2020",
      "@context": {
        "@version": 1.1,
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "sec": "https://w3id.org/security#",
        "xsd": "http://www.w3.org/2001/XMLSchema#",
        "challenge": "sec:challenge",
        "created": {
          "@id": "http://purl.org/dc/terms/created",
          "@type": "xsd:dateTime"
        },
        "domain": "sec:domain",
        "proofValue": "sec:proofValue",
        "nonce": "sec:nonce",
        "proofPurpose": {
          "@id": "sec:proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@version": 1.1,
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "sec": "https://w3id.org/security#",
            "assertionMethod": {
              "@id": "sec:assertionMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "authentication": {
              "@id": "sec:authenticationMethod",
              "@type": "@id",
              "@container": "@set"
            }
          }
        },
        "verificationMethod": {
          "@id": "sec:verificationMethod",
          "@type": "@id"
        }
      }
    },
    "BbsBlsSignatureProof2020": {
      "@id": "https://w3id.org/security#BbsBlsSignatureProof2020",
      "@context": {
        "@version": 1.1,
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "sec": "https://w3id.org/security#",
        "xsd": "http://www.w3.org/2001/XMLSchema#",
        "challenge": "sec:challenge",
        "created": {
          "@id": "http://purl.org/dc/terms/created",
          "@type": "xsd:dateTime"
        },
        "domain": "sec:domain",
        "nonce": "sec:nonce",
        "proofPurpose": {
          "@id": "sec:proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@version": 1.1,
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "sec": "https://w3id.org/security#",
            "assertionMethod": {
              "@id": "sec:assertionMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "authentication": {
              "@id": "sec:authenticationMethod",
              "@type": "@id",
              "@container": "@set"
            }
          }
        },
        "proofValue": "sec:proofValue",
        "verificationMethod": {
          "@id": "sec:verificationMethod",
          "@type": "@id"
        }
      }
    },
    "Bls12381G2Key2020": "ldssk:Bls12381G2Key2020"
  }
}`
