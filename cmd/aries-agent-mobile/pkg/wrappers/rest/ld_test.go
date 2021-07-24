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
	ldcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/ld"
	ldrest "github.com/hyperledger/aries-framework-go/pkg/controller/rest/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext"
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

func getLDController(t *testing.T) *LD {
	a, err := getAgent()
	require.NotNil(t, a)
	require.NoError(t, err)

	controller, err := a.GetLDController()
	require.NoError(t, err)
	require.NotNil(t, controller)

	c, ok := controller.(*LD)
	require.Equal(t, ok, true)

	return c
}

func TestLD_AddContexts(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getLDController(t)

		mockResponse := emptyJSON
		controller.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockAgentURL + ldrest.AddContextsPath,
		}

		contextJSON, err := json.Marshal(sampleContext)
		require.NoError(t, err)

		b, err := json.Marshal(ldcmd.AddContextsRequest{
			Documents: []ldcontext.Document{
				{
					URL:     "http://schema.org/name",
					Content: contextJSON,
				},
			},
		})
		require.NoError(t, err)

		req := &models.RequestEnvelope{Payload: b}
		resp := controller.AddContexts(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestLD_AddRemoteProvider(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getLDController(t)

		mockResponse := `"id":"provider_id"`
		controller.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockAgentURL + ldrest.AddRemoteProviderPath,
		}

		b, err := json.Marshal(ldcmd.AddRemoteProviderRequest{Endpoint: "endpoint"})
		require.NoError(t, err)

		req := &models.RequestEnvelope{Payload: b}

		resp := controller.AddRemoteProvider(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestLD_RefreshRemoteProvider(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getLDController(t)

		mockResponse := emptyJSON

		b, err := json.Marshal(ldcmd.ProviderID{ID: "id"})
		require.NoError(t, err)

		mockURL, err := parseURL(mockAgentURL, ldrest.RefreshRemoteProviderPath, string(b))
		require.NoError(t, err, "failed to parse test url")

		controller.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockURL,
		}

		req := &models.RequestEnvelope{Payload: b}

		resp := controller.RefreshRemoteProvider(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestLD_DeleteRemoteProvider(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getLDController(t)

		mockResponse := emptyJSON

		b, err := json.Marshal(ldcmd.ProviderID{ID: "id"})
		require.NoError(t, err)

		mockURL, err := parseURL(mockAgentURL, ldrest.DeleteRemoteProviderPath, string(b))
		require.NoError(t, err, "failed to parse test url")

		controller.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodDelete, url: mockURL,
		}

		req := &models.RequestEnvelope{Payload: b}

		resp := controller.DeleteRemoteProvider(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestLD_GetAllRemoteProviders(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getLDController(t)

		mockResponse := `{"providers": [{"id": "id", "endpoint": "endpoint"}]"}`
		controller.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodGet, url: mockAgentURL + ldrest.GetAllRemoteProvidersPath,
		}

		req := &models.RequestEnvelope{Payload: []byte("{}")}

		resp := controller.GetAllRemoteProviders(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestLD_RefreshAllRemoteProviders(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getLDController(t)

		mockResponse := emptyJSON
		controller.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockAgentURL + ldrest.RefreshAllRemoteProvidersPath,
		}

		req := &models.RequestEnvelope{Payload: []byte("{}")}

		resp := controller.RefreshAllRemoteProviders(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}
