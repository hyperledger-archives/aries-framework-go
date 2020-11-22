/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest/mediator"
)

const (
	sampleConnRequest        = `{"connectionID":"123-abc"}`
	sampleBatchPickupRequest = `{"connectionID":"123-abc", "batch_size": 100}`
)

func getMediatorController(t *testing.T) *Mediator {
	a, err := getAgent()
	require.NotNil(t, a)
	require.NoError(t, err)

	controller, err := a.GetMediatorController()
	require.NoError(t, err)
	require.NotNil(t, controller)

	m, ok := controller.(*Mediator)
	require.Equal(t, ok, true)

	return m
}

func TestMediator_BatchPickup(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getMediatorController(t)

		reqData := sampleBatchPickupRequest

		mockResponse := `{"message_count":64}`
		controller.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockAgentURL + mediator.BatchPickupPath,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := controller.BatchPickup(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestMediator_Connections(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getMediatorController(t)

		reqData := emptyJSON

		mockResponse := `{"connections":["conn-abc"]}`
		controller.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodGet, url: mockAgentURL + mediator.GetConnectionsPath,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := controller.Connections(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestMediator_Reconnect(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getMediatorController(t)

		reqData := sampleConnRequest

		mockResponse := emptyJSON
		controller.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockAgentURL + mediator.ReconnectPath,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := controller.Reconnect(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestMediator_ReconnectAll(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getMediatorController(t)

		mockResponse := emptyJSON
		controller.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodGet, url: mockAgentURL + mediator.ReconnectAllPath,
		}

		req := &models.RequestEnvelope{Payload: []byte("")}
		resp := controller.ReconnectAll(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestMediator_Register(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getMediatorController(t)

		reqData := sampleConnRequest

		mockResponse := emptyJSON
		controller.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockAgentURL + mediator.RegisterPath,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := controller.Register(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestMediator_Status(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getMediatorController(t)

		reqData := sampleConnRequest

		mockResponse := `{"@id":"sample-status-id","message_count":0,"last_added_time":"0001-01-01T00:00:00Z",
"last_delivered_time":"0001-01-01T00:00:00Z","last_removed_time":"0001-01-01T00:00:00Z","total_size":64}`
		controller.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockAgentURL + mediator.StatusPath,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := controller.Status(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestMediator_Unregister(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getMediatorController(t)

		reqData := emptyJSON

		mockResponse := emptyJSON
		controller.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodDelete, url: mockAgentURL + mediator.UnregisterPath,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := controller.Unregister(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}
