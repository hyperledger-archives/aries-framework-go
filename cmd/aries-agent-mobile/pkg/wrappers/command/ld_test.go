/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/ld"
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

		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		controller.handlers[ld.AddContextsCommandMethod] = fakeHandler.exec

		contextJSON, err := json.Marshal(sampleContext)
		require.NoError(t, err)

		b, err := json.Marshal(ld.AddContextsRequest{
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
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestLD_AddRemoteProvider(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getLDController(t)

		mockResponse := `"id": "provider_id"`

		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		controller.handlers[ld.AddRemoteProviderCommandMethod] = fakeHandler.exec

		b, err := json.Marshal(ld.AddRemoteProviderRequest{Endpoint: "endpoint"})
		require.NoError(t, err)

		req := &models.RequestEnvelope{Payload: b}

		resp := controller.AddRemoteProvider(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestLD_RefreshRemoteProvider(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getLDController(t)

		mockResponse := emptyJSON

		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		controller.handlers[ld.RefreshRemoteProviderCommandMethod] = fakeHandler.exec

		b, err := json.Marshal(ld.ProviderID{ID: "id"})
		require.NoError(t, err)

		req := &models.RequestEnvelope{Payload: b}

		resp := controller.RefreshRemoteProvider(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestLD_DeleteRemoteProvider(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getLDController(t)

		mockResponse := emptyJSON

		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		controller.handlers[ld.DeleteRemoteProviderCommandMethod] = fakeHandler.exec

		b, err := json.Marshal(ld.ProviderID{ID: "id"})
		require.NoError(t, err)

		req := &models.RequestEnvelope{Payload: b}

		resp := controller.DeleteRemoteProvider(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestLD_GetAllRemoteProviders(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getLDController(t)

		mockResponse := `{"providers": [{"id": "id", "endpoint": "endpoint"}]"}`

		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		controller.handlers[ld.GetAllRemoteProvidersCommandMethod] = fakeHandler.exec

		req := &models.RequestEnvelope{Payload: []byte("{}")}

		resp := controller.GetAllRemoteProviders(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestLD_RefreshAllRemoteProviders(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getLDController(t)

		mockResponse := emptyJSON

		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		controller.handlers[ld.RefreshAllRemoteProvidersCommandMethod] = fakeHandler.exec

		req := &models.RequestEnvelope{Payload: []byte("{}")}

		resp := controller.RefreshAllRemoteProviders(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}
