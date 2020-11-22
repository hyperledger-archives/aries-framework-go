/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/mediator"
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
		mediatorController := getMediatorController(t)

		mockResponse := `{"message_count":64}`
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		mediatorController.handlers[mediator.BatchPickupCommandMethod] = fakeHandler.exec

		payload := sampleBatchPickupRequest

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := mediatorController.BatchPickup(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestMediator_Connections(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mediatorController := getMediatorController(t)

		mockResponse := `{"connections":["conn-abc"]}`
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		mediatorController.handlers[mediator.GetConnectionsCommandMethod] = fakeHandler.exec

		payload := emptyJSON

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := mediatorController.Connections(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestMediator_Reconnect(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mediatorController := getMediatorController(t)

		mockResponse := emptyJSON
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		mediatorController.handlers[mediator.ReconnectCommandMethod] = fakeHandler.exec

		payload := sampleConnRequest

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := mediatorController.Reconnect(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestMediator_ReconnectAll(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mediatorController := getMediatorController(t)

		mockResponse := emptyJSON
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		mediatorController.handlers[mediator.ReconnectCommandMethod] = fakeHandler.exec

		req := &models.RequestEnvelope{Payload: []byte("")}
		resp := mediatorController.ReconnectAll(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Contains(t, string(resp.Payload), mockResponse)
	})
}

func TestMediator_Register(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mediatorController := getMediatorController(t)

		mockResponse := emptyJSON
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		mediatorController.handlers[mediator.RegisterCommandMethod] = fakeHandler.exec

		payload := sampleConnRequest

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := mediatorController.Register(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestMediator_Status(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mediatorController := getMediatorController(t)

		mockResponse := `{"@id":"sample-status-id","message_count":0,"last_added_time":"0001-01-01T00:00:00Z",
"last_delivered_time":"0001-01-01T00:00:00Z","last_removed_time":"0001-01-01T00:00:00Z","total_size":64}`
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		mediatorController.handlers[mediator.StatusCommandMethod] = fakeHandler.exec

		payload := sampleConnRequest

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := mediatorController.Status(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestMediator_Unregister(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mediatorController := getMediatorController(t)

		mockResponse := emptyJSON
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		mediatorController.handlers[mediator.UnregisterCommandMethod] = fakeHandler.exec

		payload := emptyJSON

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := mediatorController.Unregister(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}
