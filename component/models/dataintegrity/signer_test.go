/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dataintegrity

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"

	"github.com/hyperledger/aries-framework-go/component/models/dataintegrity/models"
)

func TestNewSigner(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		s, err := NewSigner(&mockSuiteInitializer{
			mockSuite: &mockSuite{},
			typeStr:   mockSuiteType,
		}, &mockSuiteInitializer{
			mockSuite: &mockSuite{},
			typeStr:   mockSuiteType + "-but-different",
		}, &mockSuiteInitializer{
			mockSuite: &mockSuite{},
			typeStr:   mockSuiteType,
		})

		require.NoError(t, err)
		require.NotNil(t, s)
		require.Len(t, s.suites, 2)
	})

	t.Run("initializer error", func(t *testing.T) {
		s, err := NewSigner(&mockSuiteInitializer{
			mockSuite: &mockSuite{},
			initErr:   errExpected,
			typeStr:   mockSuiteType,
		})

		require.Nil(t, s)
		require.ErrorIs(t, err, errExpected)
	})
}

func TestSigner_AddProof(t *testing.T) {
	mockDoc := []byte(`{"id":"foo","data":[{"id":"data-1","value":3}]}`)

	t.Run("success", func(t *testing.T) {
		createdTime := time.Now().Format(models.DateTimeFormat)

		s, err := NewSigner(&mockSuiteInitializer{
			mockSuite: &mockSuite{
				CreateProofVal: &models.Proof{
					Type:               mockSuiteType,
					ProofPurpose:       "mock-purpose",
					VerificationMethod: "mock-vm",
					Domain:             "mock-domain",
					Challenge:          "mock-challenge",
					Created:            createdTime,
				},
			},
			typeStr: mockSuiteType,
		})

		require.NoError(t, err)

		signedDoc, err := s.AddProof(mockDoc, &models.ProofOptions{
			SuiteType: mockSuiteType,
			Domain:    "mock-domain",
			Challenge: "mock-challenge",
			MaxAge:    1000,
		})
		require.NoError(t, err)

		fmt.Println(string(signedDoc))

		expectProof := []byte(fmt.Sprintf(`{
			"type": "mock-suite-2023",
			"proofPurpose": "mock-purpose",
			"verificationMethod":"mock-vm",
			"proofValue":"",
			"created": "%s",
			"domain": "mock-domain",
			"challenge":"mock-challenge"
		}`, createdTime))

		proofBytes, unsignedDoc := extractProof(t, signedDoc)

		require.True(t, jsonEquals(proofBytes, expectProof), "proof doesn't match expected")
		require.True(t, jsonEquals(unsignedDoc, mockDoc), "adding proof changed other parts of doc")
	})

	t.Run("failure", func(t *testing.T) {
		t.Run("unsupported suite", func(t *testing.T) {
			s, err := NewSigner(&mockSuiteInitializer{
				mockSuite: &mockSuite{
					CreateProofVal: &models.Proof{
						Type:               mockSuiteType,
						ProofPurpose:       "mock-purpose",
						VerificationMethod: "mock-vm",
					},
				},
				typeStr: mockSuiteType,
			})

			require.NoError(t, err)

			signedDoc, err := s.AddProof(mockDoc, &models.ProofOptions{SuiteType: "wrong-suite-type"})
			require.ErrorIs(t, err, ErrUnsupportedSuite)
			require.Nil(t, signedDoc)
		})

		t.Run("suite create proof", func(t *testing.T) {
			s, err := NewSigner(&mockSuiteInitializer{
				mockSuite: &mockSuite{
					CreateProofErr: errExpected,
				},
				typeStr: mockSuiteType,
			})

			require.NoError(t, err)

			signedDoc, err := s.AddProof(mockDoc, &models.ProofOptions{SuiteType: mockSuiteType})
			require.ErrorIs(t, err, ErrProofGeneration)
			require.Nil(t, signedDoc)
		})

		t.Run("missing required field", func(t *testing.T) {
			t.Run("type", func(t *testing.T) {
				s, err := NewSigner(&mockSuiteInitializer{
					mockSuite: &mockSuite{
						CreateProofVal: &models.Proof{
							// Type:               mockSuiteType,
							ProofPurpose:       "mock-purpose",
							VerificationMethod: "mock-vm",
						},
					},
					typeStr: mockSuiteType,
				})

				require.NoError(t, err)

				signedDoc, err := s.AddProof(mockDoc, &models.ProofOptions{SuiteType: mockSuiteType})
				require.ErrorIs(t, err, ErrProofGeneration)
				require.Nil(t, signedDoc)
			})

			t.Run("proofPurpose", func(t *testing.T) {
				s, err := NewSigner(&mockSuiteInitializer{
					mockSuite: &mockSuite{
						CreateProofVal: &models.Proof{
							Type: mockSuiteType,
							// ProofPurpose:       "mock-purpose",
							VerificationMethod: "mock-vm",
						},
					},
					typeStr: mockSuiteType,
				})

				require.NoError(t, err)

				signedDoc, err := s.AddProof(mockDoc, &models.ProofOptions{SuiteType: mockSuiteType})
				require.ErrorIs(t, err, ErrProofGeneration)
				require.Nil(t, signedDoc)
			})

			t.Run("verificationMethod", func(t *testing.T) {
				s, err := NewSigner(&mockSuiteInitializer{
					mockSuite: &mockSuite{
						CreateProofVal: &models.Proof{
							Type:         mockSuiteType,
							ProofPurpose: "mock-purpose",
							// VerificationMethod: "mock-vm",
						},
					},
					typeStr: mockSuiteType,
				})

				require.NoError(t, err)

				signedDoc, err := s.AddProof(mockDoc, &models.ProofOptions{SuiteType: mockSuiteType})
				require.ErrorIs(t, err, ErrProofGeneration)
				require.Nil(t, signedDoc)
			})

			t.Run("created, required by suite", func(t *testing.T) {
				s, err := NewSigner(&mockSuiteInitializer{
					mockSuite: &mockSuite{
						CreateProofVal: &models.Proof{
							Type:               mockSuiteType,
							ProofPurpose:       "mock-purpose",
							VerificationMethod: "mock-vm",
						},
						ReqCreatedVal: true,
					},
					typeStr: mockSuiteType,
				})

				require.NoError(t, err)

				signedDoc, err := s.AddProof(mockDoc, &models.ProofOptions{SuiteType: mockSuiteType})
				require.ErrorIs(t, err, ErrProofGeneration)
				require.Nil(t, signedDoc)
			})
		})

		t.Run("incorrect domain", func(t *testing.T) {
			s, err := NewSigner(&mockSuiteInitializer{
				mockSuite: &mockSuite{
					CreateProofVal: &models.Proof{
						Type:               mockSuiteType,
						ProofPurpose:       "mock-purpose",
						VerificationMethod: "mock-vm",
						Domain:             "wrong-domain",
					},
				},
				typeStr: mockSuiteType,
			})

			require.NoError(t, err)

			signedDoc, err := s.AddProof(mockDoc, &models.ProofOptions{
				SuiteType: mockSuiteType,
				Domain:    "expected-domain",
			})
			require.ErrorIs(t, err, ErrProofGeneration)
			require.Nil(t, signedDoc)
		})

		t.Run("incorrect challenge", func(t *testing.T) {
			s, err := NewSigner(&mockSuiteInitializer{
				mockSuite: &mockSuite{
					CreateProofVal: &models.Proof{
						Type:               mockSuiteType,
						ProofPurpose:       "mock-purpose",
						VerificationMethod: "mock-vm",
						Domain:             "expected-domain",
						Challenge:          "wrong-challenge",
					},
				},
				typeStr: mockSuiteType,
			})

			require.NoError(t, err)

			signedDoc, err := s.AddProof(mockDoc, &models.ProofOptions{
				SuiteType: mockSuiteType,
				Domain:    "expected-domain",
				Challenge: "expected-challenge",
			})
			require.ErrorIs(t, err, ErrProofGeneration)
			require.Nil(t, signedDoc)
		})
	})
}

func extractProof(t *testing.T, doc []byte) (proof []byte, rest []byte) {
	var err error

	proofRaw := gjson.GetBytes(doc, proofPath)

	proof = []byte(proofRaw.Raw)

	rest, err = sjson.DeleteBytes(doc, proofPath)
	require.NoError(t, err)

	return proof, rest
}
