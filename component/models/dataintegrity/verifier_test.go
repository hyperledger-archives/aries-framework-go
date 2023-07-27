/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dataintegrity

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/sjson"

	"github.com/hyperledger/aries-framework-go/component/models/dataintegrity/models"
)

func TestNewVerifier(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		v, err := NewVerifier(&mockSuiteInitializer{
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
		require.NotNil(t, v)
		require.Len(t, v.suites, 2)
	})

	t.Run("initializer error", func(t *testing.T) {
		v, err := NewVerifier(&mockSuiteInitializer{
			mockSuite: &mockSuite{},
			initErr:   errExpected,
			typeStr:   mockSuiteType,
		})

		require.Nil(t, v)
		require.ErrorIs(t, err, errExpected)
	})
}

func TestVerifier_VerifyProof(t *testing.T) {
	mockDoc := []byte(`{"id":"foo","data":[{"id":"data-1","value":3}]}`)

	t.Run("success", func(t *testing.T) {
		createdTime := time.Now().Format(models.DateTimeFormat)

		v, err := NewVerifier(&mockSuiteInitializer{
			mockSuite: &mockSuite{
				ReqCreatedVal: true,
			},
			typeStr: mockSuiteType,
		})

		require.NoError(t, err)

		mockProof := &models.Proof{
			Type:               mockSuiteType,
			VerificationMethod: "mock-vm",
			ProofPurpose:       "mock-purpose",
			Created:            createdTime,
			Domain:             "mock-domain",
			Challenge:          "mock-challenge",
		}

		signedDoc, err := mockAddProof(mockDoc, mockProof)
		require.NoError(t, err)

		err = v.VerifyProof(signedDoc, &models.ProofOptions{
			Purpose:   "mock-purpose",
			MaxAge:    1000,
			Domain:    "mock-domain",
			Challenge: "mock-challenge",
		})
		require.NoError(t, err)
	})

	t.Run("failure", func(t *testing.T) {
		t.Run("missing proof", func(t *testing.T) {
			v, err := NewVerifier(&mockSuiteInitializer{
				mockSuite: &mockSuite{},
				typeStr:   mockSuiteType,
			})

			require.NoError(t, err)

			err = v.VerifyProof(mockDoc, &models.ProofOptions{
				Purpose: "mock-purpose",
			})
			require.ErrorIs(t, err, ErrMissingProof)
		})

		t.Run("proof json is invalid", func(t *testing.T) {
			v, err := NewVerifier(&mockSuiteInitializer{
				mockSuite: &mockSuite{},
				typeStr:   mockSuiteType,
			})

			require.NoError(t, err)

			signedDoc, err := sjson.SetRawBytes(mockDoc, proofPath, []byte(`["not","an","object"]`))
			require.NoError(t, err)

			err = v.VerifyProof(signedDoc, &models.ProofOptions{
				Purpose: "mock-purpose",
			})
			require.ErrorIs(t, err, ErrMalformedProof)
		})

		t.Run("missing required field", func(t *testing.T) {
			v, err := NewVerifier(&mockSuiteInitializer{
				mockSuite: &mockSuite{
					ReqCreatedVal: true,
				},
				typeStr: mockSuiteType,
			})

			require.NoError(t, err)

			t.Run("type", func(t *testing.T) {
				mockProof := &models.Proof{
					VerificationMethod: "mock-vm",
					ProofPurpose:       "mock-purpose",
				}

				signedDoc, err := mockAddProof(mockDoc, mockProof)
				require.NoError(t, err)

				err = v.VerifyProof(signedDoc, &models.ProofOptions{
					Purpose: "mock-purpose",
				})
				require.ErrorIs(t, err, ErrMalformedProof)
			})

			t.Run("verificationMethod", func(t *testing.T) {
				mockProof := &models.Proof{
					Type:         mockSuiteType,
					ProofPurpose: "mock-purpose",
				}

				signedDoc, err := mockAddProof(mockDoc, mockProof)
				require.NoError(t, err)

				err = v.VerifyProof(signedDoc, &models.ProofOptions{
					Purpose: "mock-purpose",
				})
				require.ErrorIs(t, err, ErrMalformedProof)
			})

			t.Run("proofPurpose", func(t *testing.T) {
				mockProof := &models.Proof{
					Type:               mockSuiteType,
					VerificationMethod: "mock-vm",
				}

				signedDoc, err := mockAddProof(mockDoc, mockProof)
				require.NoError(t, err)

				err = v.VerifyProof(signedDoc, &models.ProofOptions{
					Purpose: "mock-purpose",
				})
				require.ErrorIs(t, err, ErrMalformedProof)
			})

			t.Run("created, with suite that requires it", func(t *testing.T) {
				mockProof := &models.Proof{
					Type:               mockSuiteType,
					VerificationMethod: "mock-vm",
					ProofPurpose:       "mock-purpose",
				}

				signedDoc, err := mockAddProof(mockDoc, mockProof)
				require.NoError(t, err)

				err = v.VerifyProof(signedDoc, &models.ProofOptions{
					Purpose: "mock-purpose",
				})
				require.ErrorIs(t, err, ErrMalformedProof)
			})
		})

		t.Run("unsupported suite", func(t *testing.T) {
			v, err := NewVerifier(&mockSuiteInitializer{
				mockSuite: &mockSuite{},
				typeStr:   mockSuiteType,
			})

			require.NoError(t, err)

			mockProof := &models.Proof{
				Type:               "unknown-suite",
				VerificationMethod: "mock-vm",
				ProofPurpose:       "mock-purpose",
			}

			signedDoc, err := mockAddProof(mockDoc, mockProof)
			require.NoError(t, err)

			err = v.VerifyProof(signedDoc, &models.ProofOptions{
				Purpose: "mock-purpose",
			})
			require.ErrorIs(t, err, ErrUnsupportedSuite)
		})

		t.Run("mismatched purpose", func(t *testing.T) {
			v, err := NewVerifier(&mockSuiteInitializer{
				mockSuite: &mockSuite{},
				typeStr:   mockSuiteType,
			})

			require.NoError(t, err)

			mockProof := &models.Proof{
				Type:               mockSuiteType,
				VerificationMethod: "mock-vm",
				ProofPurpose:       "mock-purpose",
			}

			signedDoc, err := mockAddProof(mockDoc, mockProof)
			require.NoError(t, err)

			err = v.VerifyProof(signedDoc, &models.ProofOptions{
				Purpose: "different-purpose",
			})
			require.ErrorIs(t, err, ErrMismatchedPurpose)
		})

		t.Run("suite verification", func(t *testing.T) {
			v, err := NewVerifier(&mockSuiteInitializer{
				mockSuite: &mockSuite{
					VerifyProofErr: errExpected,
				},
				typeStr: mockSuiteType,
			})

			require.NoError(t, err)

			mockProof := &models.Proof{
				Type:               mockSuiteType,
				VerificationMethod: "mock-vm",
				ProofPurpose:       "mock-purpose",
			}

			signedDoc, err := mockAddProof(mockDoc, mockProof)
			require.NoError(t, err)

			err = v.VerifyProof(signedDoc, &models.ProofOptions{
				Purpose: "mock-purpose",
			})
			require.ErrorIs(t, err, errExpected)
		})

		t.Run("created time in wrong format", func(t *testing.T) {
			v, err := NewVerifier(&mockSuiteInitializer{
				mockSuite: &mockSuite{},
				typeStr:   mockSuiteType,
			})

			require.NoError(t, err)

			mockProof := &models.Proof{
				Type:               mockSuiteType,
				VerificationMethod: "mock-vm",
				ProofPurpose:       "mock-purpose",
				Created:            "Id. Mar. DCCX AUC",
			}

			signedDoc, err := mockAddProof(mockDoc, mockProof)
			require.NoError(t, err)

			err = v.VerifyProof(signedDoc, &models.ProofOptions{
				Purpose: "mock-purpose",
			})
			require.ErrorIs(t, err, ErrMalformedProof)
		})

		t.Run("out of date", func(t *testing.T) {
			v, err := NewVerifier(&mockSuiteInitializer{
				mockSuite: &mockSuite{},
				typeStr:   mockSuiteType,
			})

			createdTime := time.Now().Add(time.Duration(-50) * time.Second).Format(models.DateTimeFormat)

			require.NoError(t, err)

			mockProof := &models.Proof{
				Type:               mockSuiteType,
				VerificationMethod: "mock-vm",
				ProofPurpose:       "mock-purpose",
				Created:            createdTime,
			}

			signedDoc, err := mockAddProof(mockDoc, mockProof)
			require.NoError(t, err)

			err = v.VerifyProof(signedDoc, &models.ProofOptions{
				Purpose: "mock-purpose",
				MaxAge:  5,
			})
			require.ErrorIs(t, err, ErrOutOfDate)
		})

		t.Run("proof has wrong domain", func(t *testing.T) {
			v, err := NewVerifier(&mockSuiteInitializer{
				mockSuite: &mockSuite{},
				typeStr:   mockSuiteType,
			})

			require.NoError(t, err)

			mockProof := &models.Proof{
				Type:               mockSuiteType,
				VerificationMethod: "mock-vm",
				ProofPurpose:       "mock-purpose",
				Domain:             "wrong-domain",
			}

			signedDoc, err := mockAddProof(mockDoc, mockProof)
			require.NoError(t, err)

			err = v.VerifyProof(signedDoc, &models.ProofOptions{
				Purpose: "mock-purpose",
				Domain:  "mock-domain",
			})
			require.ErrorIs(t, err, ErrInvalidDomain)
		})

		t.Run("proof has wrong challenge", func(t *testing.T) {
			v, err := NewVerifier(&mockSuiteInitializer{
				mockSuite: &mockSuite{},
				typeStr:   mockSuiteType,
			})

			require.NoError(t, err)

			mockProof := &models.Proof{
				Type:               mockSuiteType,
				VerificationMethod: "mock-vm",
				ProofPurpose:       "mock-purpose",
				Challenge:          "wrong-challenge",
			}

			signedDoc, err := mockAddProof(mockDoc, mockProof)
			require.NoError(t, err)

			err = v.VerifyProof(signedDoc, &models.ProofOptions{
				Purpose:   "mock-purpose",
				Challenge: "mock-challenge",
			})
			require.ErrorIs(t, err, ErrInvalidChallenge)
		})
	})
}

func mockAddProof(doc []byte, proof *models.Proof) ([]byte, error) {
	proofRaw, err := json.Marshal(proof)
	if err != nil {
		return nil, ErrProofGeneration
	}

	out, err := sjson.SetRawBytes(doc, proofPath, proofRaw)
	if err != nil {
		return nil, ErrProofGeneration
	}

	return out, nil
}
