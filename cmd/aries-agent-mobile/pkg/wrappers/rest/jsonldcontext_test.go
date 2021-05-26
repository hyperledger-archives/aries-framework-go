/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest/jsonld/context"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jsonld"
)

const sampleContext = `{
   "@context":{
      "name":"http://schema.org/name",
      "image":{
         "@id":"http://schema.org/image",
         "@type":"@id"
      },
      "homepage":{
         "@id":"http://schema.org/url",
         "@type":"@id"
      }
   }
}`

func getJSONLDContextController(t *testing.T) *JSONLDContext {
	a, err := getAgent()
	require.NotNil(t, a)
	require.NoError(t, err)

	controller, err := a.GetJSONLDContextController()
	require.NoError(t, err)
	require.NotNil(t, controller)

	c, ok := controller.(*JSONLDContext)
	require.Equal(t, ok, true)

	return c
}

func TestJSONLDContext_AddContext(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getJSONLDContextController(t)

		mockResponse := emptyJSON
		controller.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockAgentURL + context.AddContextPath,
		}

		contextJSON, err := json.Marshal(sampleContext)
		require.NoError(t, err)

		payload := struct {
			Documents []jsonld.ContextDocument `json:"documents"`
		}{
			Documents: []jsonld.ContextDocument{
				{
					URL:     "http://schema.org/name",
					Content: contextJSON,
				},
			},
		}

		b, err := json.Marshal(payload)
		require.NoError(t, err)

		req := &models.RequestEnvelope{Payload: b}
		resp := controller.AddContext(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}
