/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presexch

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

func TestPresentationDefinitions_Match(t *testing.T) {
	t.Run("match one credential", func(t *testing.T) {
		uri := randomURI()
		expected := newVC([]string{uri})
		defs := &PresentationDefinitions{
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: &Schema{
					URI: uri,
				},
			}},
		}

		matched, err := defs.Match(newVP(t,
			&PresentationSubmission{DescriptorMap: []*InputDescriptorMapping{{
				ID:   defs.InputDescriptors[0].ID,
				Path: "$.verifiableCredential[0]",
			}}},
			expected,
		), WithJSONLDDocumentLoader(jsonldContextLoader(t, uri)))
		require.NoError(t, err)
		require.Len(t, matched, 1)
		result, ok := matched[defs.InputDescriptors[0].ID]
		require.True(t, ok)
		require.Equal(t, expected.ID, result.ID)
	})

	t.Run("error if vp does not have the right context", func(t *testing.T) {
		uri := randomURI()
		defs := &PresentationDefinitions{
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: &Schema{
					URI: uri,
				},
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

		_, err := defs.Match(vp, WithJSONLDDocumentLoader(jsonldContextLoader(t, uri)))
		require.Error(t, err)
	})

	t.Run("error if vp does not have the right type", func(t *testing.T) {
		uri := randomURI()
		defs := &PresentationDefinitions{
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: &Schema{
					URI: uri,
				},
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

		_, err := defs.Match(vp, WithJSONLDDocumentLoader(jsonldContextLoader(t, uri)))
		require.Error(t, err)
	})

	t.Run("error if descriptor_map has an invalid ID", func(t *testing.T) {
		uri := randomURI()
		defs := &PresentationDefinitions{
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: &Schema{
					URI: uri,
				},
			}},
		}

		_, err := defs.Match(newVP(t,
			&PresentationSubmission{DescriptorMap: []*InputDescriptorMapping{{
				ID:   "INVALID",
				Path: "$.verifiableCredential[0]",
			}}},
			newVC([]string{uri}),
		), WithJSONLDDocumentLoader(jsonldContextLoader(t, uri)))
		require.Error(t, err)
	})

	t.Run("error if jsonpath in descriptor_map points to a nonexistent element", func(t *testing.T) {
		uri := randomURI()
		defs := &PresentationDefinitions{
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: &Schema{
					URI: uri,
				},
			}},
		}

		_, err := defs.Match(newVP(t,
			&PresentationSubmission{DescriptorMap: []*InputDescriptorMapping{{
				ID:   defs.InputDescriptors[0].ID,
				Path: "$.verifiableCredential[1]",
			}}}, nil,
		), WithJSONLDDocumentLoader(jsonldContextLoader(t, uri)))
		require.Error(t, err)
	})

	t.Run("error if cannot parse credential", func(t *testing.T) {
		uri := randomURI()
		defs := &PresentationDefinitions{
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: &Schema{
					URI: uri,
				},
			}},
		}

		_, err := defs.Match(newVP(t,
			&PresentationSubmission{DescriptorMap: []*InputDescriptorMapping{{
				ID:   defs.InputDescriptors[0].ID,
				Path: "$.verifiableCredential[0]",
			}}}, newVC([]string{uri}),
		))
		require.Error(t, err)
	})

	t.Run("error if embedded credential has a type different than the input descriptor schema uri", func(t *testing.T) {
		uri := randomURI()
		defs := &PresentationDefinitions{
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: &Schema{
					URI: uri,
				},
			}},
		}

		diffURI := randomURI()
		require.NotEqual(t, uri, diffURI)

		_, err := defs.Match(newVP(t,
			&PresentationSubmission{DescriptorMap: []*InputDescriptorMapping{{
				ID:   defs.InputDescriptors[0].ID,
				Path: "$.verifiableCredential[0]",
			}}},
			newVC([]string{diffURI}),
		), WithJSONLDDocumentLoader(jsonldContextLoader(t, diffURI)))
		require.Error(t, err)
	})

	t.Run("error when missing required credential", func(t *testing.T) {
		uriOne := randomURI()
		uriTwo := randomURI()
		defs := &PresentationDefinitions{
			InputDescriptors: []*InputDescriptor{
				{
					ID: uuid.New().String(),
					Schema: &Schema{
						URI: uriOne,
					},
				},
				{
					ID: uuid.New().String(),
					Schema: &Schema{
						URI: uriTwo,
					},
				},
			},
		}

		_, err := defs.Match(newVP(t,
			&PresentationSubmission{DescriptorMap: []*InputDescriptorMapping{{
				ID:   defs.InputDescriptors[0].ID,
				Path: "$.verifiableCredential[0]",
			}}},
			newVC([]string{uriOne}),
		), WithJSONLDDocumentLoader(jsonldContextLoader(t, uriOne)))
		require.Error(t, err)
	})

	t.Run("error if embedded credential has a type different than the input descriptor schema uri", func(t *testing.T) {
		uri := randomURI()
		defs := &PresentationDefinitions{
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: &Schema{
					URI: uri,
				},
			}},
		}

		_, err := defs.Match(newVP(t,
			nil,
			newVC([]string{uri}),
		), WithJSONLDDocumentLoader(jsonldContextLoader(t, uri)))
		require.Error(t, err)
	})

	t.Run("error if descriptor_map has an invalid ID", func(t *testing.T) {
		uri := randomURI()
		defs := &PresentationDefinitions{
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: &Schema{
					URI: uri,
				},
			}},
		}

		_, err := defs.Match(newVP(t,
			&PresentationSubmission{},
			newVC([]string{uri}),
		), WithJSONLDDocumentLoader(jsonldContextLoader(t, uri)))
		require.Error(t, err)
	})
}

func TestE2E(t *testing.T) {
	// verifier sends their presentation definitions to the holder
	verifierDefinitions := &PresentationDefinitions{
		InputDescriptors: []*InputDescriptor{{
			ID: uuid.New().String(),
			Schema: &Schema{
				URI: randomURI(),
			},
		}},
	}

	// holder builds their presentation submission against the verifier's definitions
	holderCredential := newVC([]string{verifierDefinitions.InputDescriptors[0].Schema.URI})
	vp := newVP(t,
		&PresentationSubmission{DescriptorMap: []*InputDescriptorMapping{{
			ID:   verifierDefinitions.InputDescriptors[0].ID,
			Path: "$.verifiableCredential[0]",
		}}},
		holderCredential,
	)

	// holder sends VP over the wire to the verifier
	vpBytes := marshal(t, vp)

	// verifier parses the vp
	receivedVP, err := verifiable.ParseUnverifiedPresentation(vpBytes)
	require.NoError(t, err)

	// verifier matches the received VP against their definitions
	matched, err := verifierDefinitions.Match(
		receivedVP,
		WithJSONLDDocumentLoader(
			jsonldContextLoader(t, verifierDefinitions.InputDescriptors[0].Schema.URI)))
	require.NoError(t, err)
	require.Len(t, matched, 1)
	result, ok := matched[verifierDefinitions.InputDescriptors[0].ID]
	require.True(t, ok)
	require.Equal(t, holderCredential.ID, result.ID)
}

func newVC(context []string) *verifiable.Credential {
	vc := &verifiable.Credential{
		ID:      "http://test.credential.com/123",
		Context: []string{"https://www.w3.org/2018/credentials/v1"},
		Types:   []string{"VerifiableCredential"},
		Issuer:  verifiable.Issuer{ID: "http://test.issuer.com"},
		Issued: &util.TimeWithTrailingZeroMsec{
			Time: time.Now(),
		},
		Subject: map[string]interface{}{
			"id": uuid.New().String(),
		},
	}

	if context != nil {
		vc.Context = append(vc.Context, context...)
	}

	return vc
}

func newVP(t *testing.T, submission *PresentationSubmission, vcs ...*verifiable.Credential) *verifiable.Presentation {
	vp := &verifiable.Presentation{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://identity.foundation/presentation-exchange/submission/v1",
		},
		Type: []string{
			"VerifiablePresentation",
			"PresentationSubmission",
		},
	}

	if submission != nil {
		vp.CustomFields = make(map[string]interface{})
		vp.CustomFields["presentation_submission"] = toMap(t, submission)
	}

	if len(vcs) > 0 {
		creds := make([]interface{}, len(vcs))

		for i := range vcs {
			creds[i] = vcs[i]
		}

		err := vp.SetCredentials(creds...)
		require.NoError(t, err)
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

func jsonldContextLoader(t *testing.T, contextURL string) *ld.CachingDocumentLoader {
	const jsonLDContext = `{
    "@context":{
      "@version":1.1,
      "@protected":true,
      "name":"http://schema.org/name",
      "ex":"https://example.org/examples#",
      "xsd":"http://www.w3.org/2001/XMLSchema#"
   }
}`

	reader, err := ld.DocumentFromReader(strings.NewReader(jsonLDContext))
	require.NoError(t, err)

	loader := verifiable.CachingJSONLDLoader()

	loader.AddDocument(contextURL, reader)

	return loader
}
