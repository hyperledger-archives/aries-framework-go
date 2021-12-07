/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/outofbandv2"
)

func getOutOfBandV2Controller(t *testing.T) *OutOfBandV2 {
	a, err := getAgent()
	require.NotNil(t, a)
	require.NoError(t, err)

	controller, err := a.GetOutOfBandV2Controller()
	require.NoError(t, err)
	require.NotNil(t, controller)

	c, ok := controller.(*OutOfBandV2)
	require.Equal(t, ok, true)

	return c
}

func TestOutOfBandV2_AcceptInvitation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getOutOfBandV2Controller(t)

		mockResponse := mockConnectionIDJSON
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		controller.handlers[outofbandv2.AcceptInvitation] = fakeHandler.exec

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

func TestOutOfBandV2_CreateInvitation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getOutOfBandV2Controller(t)

		mockResponse := `{"invitation":{"@id":"2429a5d3-c500-4647-9bb5-e34207bce406",
"@type":"https://didcomm.org/out-of-band/2.0/invitation","label":"label","body":{
"goal":"goal","goal-code":"goal_code","accept":["didcomm/v2"]}}}
`
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		controller.handlers[outofbandv2.CreateInvitation] = fakeHandler.exec

		payload := `{"label":"label","body":{"goal":"goal","goal_code":"goal_code","accept":["didcomm/v2"]}}`

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := controller.CreateInvitation(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}
