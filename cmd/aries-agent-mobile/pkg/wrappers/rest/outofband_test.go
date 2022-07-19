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
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest/outofband"
)

const (
	PIID                 = "id"
	label                = "label"
	reason               = "reason"
	jsonPayload          = `{"piid":"` + PIID + `","label":"` + label + `","reason":"` + reason + `"}`
	mockConnectionIDJSON = `{"connection_id": "conn-id"}`
)

func getOutOfBandController(t *testing.T) *OutOfBand {
	a, err := getAgent()
	require.NotNil(t, a)
	require.NoError(t, err)

	controller, err := a.GetOutOfBandController()
	require.NoError(t, err)
	require.NotNil(t, controller)

	c, ok := controller.(*OutOfBand)
	require.Equal(t, ok, true)

	return c
}

func TestOutOfBand_AcceptInvitation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getOutOfBandController(t)

		reqData := `{"invitation":{},"my_label":"label"}`
		mockResponse := mockConnectionIDJSON

		controller.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockAgentURL + outofband.AcceptInvitation,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := controller.AcceptInvitation(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestOutOfBand_ActionContinue(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getOutOfBandController(t)

		reqData := jsonPayload
		mockResponse := emptyJSON

		mockURL, err := parseURL(mockAgentURL, outofband.ActionContinue, reqData)
		require.NoError(t, err, "failed to parse test url")

		controller.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockURL,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := controller.ActionContinue(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestOutOfBand_ActionStop(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getOutOfBandController(t)

		reqData := jsonPayload
		mockResponse := emptyJSON

		mockURL, err := parseURL(mockAgentURL, outofband.ActionStop, reqData)
		require.NoError(t, err, "failed to parse test url")

		controller.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockURL,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := controller.ActionStop(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestOutOfBand_Actions(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getOutOfBandController(t)

		reqData := `{"actions":[{"PIID":"ID1","Msg":null,"MyDID":"","TheirDID":""}]}`
		mockResponse := mockConnectionIDJSON

		controller.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodGet, url: mockAgentURL + outofband.Actions,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := controller.Actions(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestOutOfBand_CreateInvitation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getOutOfBandController(t)

		reqData := `{"label":"label","goal":"goal","goal_code":"goal_code","service":["s1"],"protocols":["s1"]}`
		mockResponse := `{"invitation":{"@id":"2429a5d3-c500-4647-9bb5-e34207bce406",
"@type":"https://didcomm.org/out-of-band/1.0/invitation","label":"label","goal":"goal",
"goal_code":"goal_code","service":["s1"],"protocols":["s1"]}}
`

		controller.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockAgentURL + outofband.CreateInvitation,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := controller.CreateInvitation(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestOutOfBand_CreateRequest(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getOutOfBandController(t)

		reqData := `{"label":"label","goal":"goal","goal_code":"goal_code","service":["s1"],
"attachments":[{"lastmod_time":"0001-01-01T00:00:00Z","data":{}}]}`
		mockResponse := `{"invitation":{"@id":"26169718-f261-48f1-addd-67018977a89f",
"@type":"https://didcomm.org/out-of-band/1.0/invitation","label":"label","goal":"goal","goal_code":"goal_code",
"request~attach":[{"lastmod_time":"0001-01-01T00:00:00Z","data":{}}],"service":["s1"]}}`

		controller.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockAgentURL + outofband.CreateInvitation,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := controller.CreateInvitation(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}
