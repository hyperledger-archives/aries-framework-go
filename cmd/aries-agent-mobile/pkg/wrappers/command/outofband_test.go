/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/outofband"
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

		mockResponse := mockConnectionIDJSON
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		controller.handlers[outofband.AcceptInvitation] = fakeHandler.exec

		payload := `{"invitation":{},"my_label":"label"}`

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := controller.AcceptInvitation(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestOutOfBand_ActionContinue(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getOutOfBandController(t)

		mockResponse := emptyJSON
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		controller.handlers[outofband.ActionContinue] = fakeHandler.exec

		payload := jsonPayload

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := controller.ActionContinue(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestOutOfBand_ActionStop(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getOutOfBandController(t)

		mockResponse := emptyJSON
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		controller.handlers[outofband.ActionStop] = fakeHandler.exec

		payload := jsonPayload

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := controller.ActionStop(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestOutOfBand_Actions(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getOutOfBandController(t)

		mockResponse := `{"actions":[{"PIID":"ID1","Msg":null,"MyDID":"","TheirDID":""}]}`
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		controller.handlers[outofband.Actions] = fakeHandler.exec

		payload := emptyJSON

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := controller.Actions(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestOutOfBand_CreateInvitation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getOutOfBandController(t)

		mockResponse := `{"invitation":{"@id":"2429a5d3-c500-4647-9bb5-e34207bce406",
"@type":"https://didcomm.org/out-of-band/1.0/invitation","label":"label","goal":"goal",
"goal_code":"goal_code","service":["s1"],"protocols":["s1"]}}
`
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		controller.handlers[outofband.CreateInvitation] = fakeHandler.exec

		payload := `{"label":"label","goal":"goal","goal_code":"goal_code","service":["s1"],"protocols":["s1"]}`

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := controller.CreateInvitation(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}
