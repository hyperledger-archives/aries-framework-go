/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

// nolint: gochecknoglobals
var (
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

func TestGetQueryType(t *testing.T) {
	t.Run("test get query type by string", func(t *testing.T) {
		tests := []struct {
			name         string
			typeStr      []string
			expected     QueryType
			expectedName string
			error        string
		}{
			{
				name:         "test for QueryByExample",
				typeStr:      []string{"QueryByExample", "QuerybyExample", "querybyexample"},
				expected:     QueryByExample,
				expectedName: "QueryByExample",
			},
			{
				name:         "test for QueryByFrame",
				typeStr:      []string{"QueryByFrame", "Querybyframe", "querybyframe"},
				expected:     QueryByFrame,
				expectedName: "QueryByFrame",
			},
			{
				name:         "test for PresentationExchange",
				typeStr:      []string{"PresentationExchange", "Presentationexchange", "presentationExchange"},
				expected:     PresentationExchange,
				expectedName: "PresentationExchange",
			},
			{
				name:         "test for invalid types",
				typeStr:      []string{"", "QueryByFram", "QueryByExamples", "invalid"},
				error:        "unsupported query type",
				expectedName: "",
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.name, func(t *testing.T) {
				for _, str := range tc.typeStr {
					qType, err := GetQueryType(str)
					require.Equal(t, qType, tc.expected)
					if tc.error != "" {
						require.Error(t, err)
						require.Contains(t, err.Error(), tc.error)
					} else {
						require.NoError(t, err)
					}
				}
			})
		}
	})
}

func TestGeneratePresentation(t *testing.T) {
	vc1, err := (&verifiable.Credential{
		Context: []string{verifiable.ContextURI},
		Types:   []string{verifiable.VCType},
		ID:      "http://example.edu/credentials/9999",
		Schemas: []verifiable.TypedID{{
			ID:   schemaURI,
			Type: "JsonSchemaValidator2018",
		}},
		CustomFields: map[string]interface{}{
			"first_name": "Jesse",
		},
		Issued: &util.TimeWithTrailingZeroMsec{
			Time: time.Now(),
		},
		Issuer: verifiable.Issuer{
			ID: "did:example:76e12ec712ebc6f1c221ebfeb1f",
		},
		Subject: uuid.New().String(),
	}).MarshalJSON()
	require.NoError(t, err)

	pd := &presexch.PresentationDefinition{
		ID: uuid.New().String(),
		InputDescriptors: []*presexch.InputDescriptor{{
			ID: uuid.New().String(),
			Schema: []*presexch.Schema{{
				URI: schemaURI,
			}},
			Constraints: &presexch.Constraints{
				Fields: []*presexch.Field{{
					Path: []string{"$.first_name"},
				}},
			},
		}},
	}

	pdJSON, err := json.Marshal(pd)
	require.NoError(t, err)
	require.NotEmpty(t, pdJSON)

	t.Run("test query generate presentation", func(t *testing.T) {
		tests := []struct {
			name        string
			queryType   QueryType
			query       json.RawMessage
			creds       []json.RawMessage
			resultCount int
			error       string
		}{
			{
				name:        "query by presentation exchange - success",
				queryType:   PresentationExchange,
				query:       pdJSON,
				creds:       []json.RawMessage{vc1},
				resultCount: 1,
			},
			{
				name:      "query by presentation exchange - no results",
				queryType: PresentationExchange,
				query:     pdJSON,
				creds:     []json.RawMessage{[]byte(sampleUDCVC)},
				error:     "credentials do not satisfy requirements",
			},
			{
				name:      "query by presentation exchange - invalid frame",
				queryType: PresentationExchange,
				query:     []byte(sampleInvalidDIDContent),
				creds:     []json.RawMessage{[]byte(sampleUDCVC)},
				error:     "input_descriptors is required",
			},
			{
				name:      "query by presentation exchange - frame unmarshal error",
				queryType: PresentationExchange,
				query:     []byte("--"),
				creds:     []json.RawMessage{[]byte(sampleUDCVC)},
				error:     "invalid character",
			},
			{
				name:      "invalid credential",
				queryType: QueryByFrame,
				creds:     []json.RawMessage{[]byte(sampleInvalidDIDContent)},
				error:     "credential type of unknown structure",
			},
			{
				name:      "no record found",
				queryType: QueryByExample,
				creds:     []json.RawMessage{},
				error:     ErrQueryNoResultFound.Error(),
			},
			{
				name:      "unsupported query type",
				queryType: QueryType(0),
				creds:     []json.RawMessage{[]byte(sampleUDCVC)},
				error:     "unsupported query type",
			},
			{
				name:      "QueryByFrame - to be implemented",
				queryType: QueryByFrame,
				creds:     []json.RawMessage{[]byte(sampleUDCVC)},
				error:     "to be implemented",
			},
			{
				name:      "QueryByExample - to be implemented",
				queryType: QueryByExample,
				creds:     []json.RawMessage{[]byte(sampleUDCVC)},
				error:     "to be implemented",
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.name, func(t *testing.T) {
				presentation, err := tc.queryType.GeneratePresentation(tc.creds, tc.query)

				if tc.error != "" {
					require.Empty(t, presentation)
					require.Error(t, err)
					require.Contains(t, err.Error(), tc.error)

					return
				}

				require.NoError(t, err)
				require.NotEmpty(t, presentation)
				require.Empty(t, presentation.Proofs)
				require.Len(t, presentation.Credentials(), tc.resultCount)
			})
		}
	})
}
