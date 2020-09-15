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
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest/messaging"
)

func getMessagingController(t *testing.T) *Messaging {
	a, err := getAgent()
	require.NotNil(t, a)
	require.NoError(t, err)

	controller, err := a.GetMessagingController()
	require.NoError(t, err)
	require.NotNil(t, controller)

	m, ok := controller.(*Messaging)
	require.Equal(t, ok, true)

	return m
}

func TestMessaging_RegisterHTTPService(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getMessagingController(t)

		reqData := `{"name":"json-msg-01", "purpose": ["prp-01","prp-02"]}`
		mockResponse := emptyJSON

		controller.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockAgentURL + messaging.RegisterHTTPOverDIDCommService,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := controller.RegisterHTTPService(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestMessaging_RegisterService(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getMessagingController(t)

		reqData := `{"name":"json-msg-01", "type": "https://didcomm.org/json/1.0/msg",
						"purpose": ["prp-01","prp-02"]}`
		mockResponse := emptyJSON

		controller.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockAgentURL + messaging.RegisterMsgService,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := controller.RegisterService(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestMessaging_Reply(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getMessagingController(t)

		reqData := `{"message_ID": "1234","message_body": {"msg":"Hello !!"}}`
		mockResponse := emptyJSON

		controller.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockAgentURL + messaging.SendReplyMsg,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := controller.Reply(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestMessaging_Send(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getMessagingController(t)

		reqData := `{"message_body": {"text":"sample"}, "connection_id": "sample-conn-ID-001"}`
		mockResponse := emptyJSON

		controller.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockAgentURL + messaging.SendNewMsg,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := controller.Send(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestMessaging_Services(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getMessagingController(t)

		reqData := emptyJSON
		mockResponse := `{"names":["svc-name-01","svc-name-02","svc-name-03","svc-name-04","svc-name-05"]}`

		controller.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodGet, url: mockAgentURL + messaging.MsgServiceList,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := controller.Services(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestMessaging_UnregisterService(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getMessagingController(t)

		reqData := `{"name":"svc-01"}`
		mockResponse := emptyJSON

		controller.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockAgentURL + messaging.UnregisterMsgService,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := controller.UnregisterService(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}
