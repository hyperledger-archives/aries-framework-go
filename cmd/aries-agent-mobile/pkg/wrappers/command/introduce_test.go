/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"encoding/json"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/config"
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	cmdintroduce "github.com/hyperledger/aries-framework-go/pkg/controller/command/introduce"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"
)

type mockCommandRunner struct {
	data json.RawMessage
}

func (m *mockCommandRunner) exec(rw io.Writer, _ io.Reader) command.Error {
	if _, err := rw.Write(m.data); err != nil {
		return command.NewExecuteError(command.Introduce, err)
	}

	return nil
}

func getAgent() (*Aries, error) {
	return getAgentWithOpts(&config.Options{})
}

func getAgentWithOpts(opts *config.Options) (*Aries, error) {
	return NewAries(opts)
}

func getIntroduceController(t *testing.T) *Introduce {
	a, err := getAgent()
	require.NotNil(t, a)
	require.NoError(t, err)

	ic, err := a.GetIntroduceController()
	require.NoError(t, err)
	require.NotNil(t, ic)

	i, ok := ic.(*Introduce)
	require.Equal(t, ok, true)

	return i
}

func TestIntroduce_Actions(t *testing.T) {
	t.Run("test it performs an actions request", func(t *testing.T) {
		i := getIntroduceController(t)

		fakeHandler := mockCommandRunner{data: []byte(`{"actions":[{"PIID":"ID1","Msg":null,"MyDID":"","TheirDID":""}]}`)}
		i.handlers[cmdintroduce.Actions] = fakeHandler.exec

		resp := i.Actions(&models.RequestEnvelope{})
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, `{"actions":[{"PIID":"ID1","Msg":null,"MyDID":"","TheirDID":""}]}`, string(resp.Payload))
	})
}

func TestIntroduce_SendProposal(t *testing.T) {
	t.Run("test it performs a send proposal request", func(t *testing.T) {
		i := getIntroduceController(t)

		fakeHandler := mockCommandRunner{data: []byte(`{"piid":"f749b739-1f3d-4213-9c33-c3878cdb6e24"}`)}
		i.handlers[cmdintroduce.SendProposal] = fakeHandler.exec

		req := &models.RequestEnvelope{Payload: []byte(`{
	"recipients": [
		{
			"to": {"name": "gopher1"},
			"my_did": "did:mydid:123",
			"their_did": "gopher1:example:001",
			"goal": "test",
			"goal_code": "FREEROUTES"
		},
		{
			"to": {"name": "gopher2"},
			"my_did": "my-public-did",
			"their_did": "gopher2:example:001",
			"goal": "test",
			"goal_code": "FREEROUTES"
		}
	]
}`)}
		resp := i.SendProposal(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, `{"piid":"f749b739-1f3d-4213-9c33-c3878cdb6e24"}`, string(resp.Payload))
	})
}

func TestIntroduce_SendProposalWithOOBInvitation(t *testing.T) {
	t.Run("test it performs a send proposal with out-of-band request", func(t *testing.T) {
		i := getIntroduceController(t)

		fakeHandler := mockCommandRunner{data: []byte(`{"piid":"a13832dc-88b8-4714-b697-e5410d23abe2"}`)}
		i.handlers[cmdintroduce.SendProposalWithOOBInvitation] = fakeHandler.exec

		reqData := fmt.Sprintf(`{
	"recipient": {
			"my_did": "did:mydid:123",
			"their_did": "gopher1:example:001"
	},
	"request":	{
			"@type": "%s"
	}
}`, outofband.InvitationMsgType)
		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := i.SendProposalWithOOBInvitation(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, `{"piid":"a13832dc-88b8-4714-b697-e5410d23abe2"}`, string(resp.Payload))
	})
}

func TestIntroduce_SendRequest(t *testing.T) {
	t.Run("test it performs a send request", func(t *testing.T) {
		i := getIntroduceController(t)

		fakeHandler := mockCommandRunner{data: []byte(`{"piid":"a13832dc-88b8-4714-b697-e5410d23abe2"}`)}
		i.handlers[cmdintroduce.SendRequest] = fakeHandler.exec

		reqData := `{
	"my_did": "did:mydid:123",
	"their_did": "gopher1:example:001",
	"please_introduce_to": {
		"to": {"name": "gopher1"}
	}
}`
		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := i.SendRequest(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, `{"piid":"a13832dc-88b8-4714-b697-e5410d23abe2"}`, string(resp.Payload))
	})
}

func TestIntroduce_AcceptProposalWithOOBRequest(t *testing.T) {
	t.Run("test it performs an accept proposal with out-of-band request", func(t *testing.T) {
		i := getIntroduceController(t)

		fakeHandler := mockCommandRunner{data: []byte(``)}
		i.handlers[cmdintroduce.AcceptProposalWithOOBInvitation] = fakeHandler.exec

		reqData := `{
	"request": {},
	"piid": "a13832dc-88b8-4714-b697-e5410d23abe2"
}`
		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := i.AcceptProposalWithOOBInvitation(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, "", string(resp.Payload))
	})
}

func TestIntroduce_AcceptProposal(t *testing.T) {
	t.Run("test it accepts a proposal", func(t *testing.T) {
		i := getIntroduceController(t)

		fakeHandler := mockCommandRunner{data: []byte(``)}
		i.handlers[cmdintroduce.AcceptProposal] = fakeHandler.exec

		reqData := `{
	"piid": "a13832dc-88b8-4714-b697-e5410d23abe2"
}`
		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := i.AcceptProposal(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, "", string(resp.Payload))
	})
}

func TestIntroduce_AcceptRequestWithPublicOOBRequest(t *testing.T) {
	t.Run("test it performs an accept request with a public out-of-band request", func(t *testing.T) {
		i := getIntroduceController(t)

		fakeHandler := mockCommandRunner{data: []byte(``)}
		i.handlers[cmdintroduce.AcceptRequestWithPublicOOBInvitation] = fakeHandler.exec

		reqData := `{
	"request": {},
	"piid": "a13832dc-88b8-4714-b697-e5410d23abe2",
	"to": {}
}`
		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := i.AcceptRequestWithPublicOOBInvitation(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, "", string(resp.Payload))
	})
}

func TestIntroduce_AcceptRequestWithRecipients(t *testing.T) {
	t.Run("test it accepts a request with recipients", func(t *testing.T) {
		i := getIntroduceController(t)

		fakeHandler := mockCommandRunner{data: []byte(``)}
		i.handlers[cmdintroduce.AcceptRequestWithRecipients] = fakeHandler.exec

		reqData := `{
	"request": {},
	"piid": "a13832dc-88b8-4714-b697-e5410d23abe2",
	"to": {}
}`
		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := i.AcceptRequestWithRecipients(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, "", string(resp.Payload))
	})
}

func TestIntroduce_DeclineProposal(t *testing.T) {
	t.Run("test it declines a proposal", func(t *testing.T) {
		i := getIntroduceController(t)

		fakeHandler := mockCommandRunner{data: []byte(``)}
		i.handlers[cmdintroduce.DeclineProposal] = fakeHandler.exec

		reqData := `{
	"reason": "not in agreement",
	"piid": "a13832dc-88b8-4714-b697-e5410d23abe2"
}`
		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := i.DeclineProposal(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, "", string(resp.Payload))
	})
}

func TestIntroduce_DeclineRequest(t *testing.T) {
	t.Run("test it declines a request", func(t *testing.T) {
		i := getIntroduceController(t)

		fakeHandler := mockCommandRunner{data: []byte(``)}
		i.handlers[cmdintroduce.DeclineRequest] = fakeHandler.exec

		reqData := `{
	"reason": "not valid",
	"piid": "a13832dc-88b8-4714-b697-e5410d23abe2"
}`
		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := i.DeclineRequest(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, "", string(resp.Payload))
	})
}

func TestIntroduce_AcceptProblemReport(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		i := getIntroduceController(t)

		fakeHandler := mockCommandRunner{data: []byte(``)}
		i.handlers[cmdintroduce.AcceptProblemReport] = fakeHandler.exec

		reqData := `{"piid": "a13832dc-88b8-4714-b697-e5410d23abe2"}`
		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := i.AcceptProblemReport(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, "", string(resp.Payload))
	})
}
