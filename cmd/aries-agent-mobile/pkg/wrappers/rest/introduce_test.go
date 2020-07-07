/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/api"
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"
)

var (
	mockPIID = "f749b739-1f3d-4213-9c33-c3878cdb6e24" //nolint:gochecknoglobals
)

type mockHTTPClient struct {
	data string
}

func (client *mockHTTPClient) Do(_ *http.Request) (*http.Response, error) {
	r := ioutil.NopCloser(bytes.NewReader([]byte(client.data)))

	return &http.Response{
		StatusCode: 200,
		Body:       r,
	}, nil
}

func TestIntroduceREST_Actions(t *testing.T) {
	t.Run("test it performs an actions request", func(t *testing.T) {
		opts := &api.Options{}
		a := NewAries(opts)
		ic, err := a.GetIntroduceController()
		require.NoError(t, err)
		require.NotNil(t, ic)

		mockResponse := `{"actions":[{"PIID":"ID1","Msg":null,"MyDID":"","TheirDID":""},
{"PIID":"ID2","Msg":null,"MyDID":"","TheirDID":""}]}`

		client := mockHTTPClient{data: mockResponse}
		i, ok := ic.(*IntroduceREST)
		require.Equal(t, ok, true)
		i.httpClient = &client

		req := &models.RequestEnvelope{}
		resp := i.Actions(req)
		require.NotNil(t, resp)

		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestIntroduceREST_SendProposal(t *testing.T) {
	t.Run("test it performs a send proposal request", func(t *testing.T) {
		opts := &api.Options{}
		a := NewAries(opts)
		ic, err := a.GetIntroduceController()
		require.NoError(t, err)
		require.NotNil(t, ic)

		client := mockHTTPClient{data: mockPIID}
		i, ok := ic.(*IntroduceREST)
		require.Equal(t, ok, true)
		i.httpClient = &client

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

		require.Equal(t, mockPIID, string(resp.Payload))
	})
}

func TestIntroduceREST_SendProposalWithOOBRequest(t *testing.T) {
	t.Run("test it performs a send proposal with out-of-band request", func(t *testing.T) {
		opts := &api.Options{}
		a := NewAries(opts)
		ic, err := a.GetIntroduceController()
		require.NoError(t, err)
		require.NotNil(t, ic)

		client := mockHTTPClient{data: mockPIID}
		i, ok := ic.(*IntroduceREST)
		require.Equal(t, ok, true)
		i.httpClient = &client

		reqData := fmt.Sprintf(`{
	"recipient": {
			"my_did": "did:mydid:123",
			"their_did": "gopher1:example:001"
	},
	"request":	{
			"@type": "%s"
	}
}`, outofband.RequestMsgType)
		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := i.SendProposalWithOOBRequest(req)
		require.NotNil(t, resp)

		require.Equal(t, mockPIID, string(resp.Payload))
	})
}

func TestIntroduceREST_SendRequest(t *testing.T) {
	t.Run("test it performs a send request", func(t *testing.T) {
		opts := &api.Options{}
		a := NewAries(opts)
		ic, err := a.GetIntroduceController()
		require.NoError(t, err)
		require.NotNil(t, ic)

		client := mockHTTPClient{data: mockPIID}
		i, ok := ic.(*IntroduceREST)
		require.Equal(t, ok, true)
		i.httpClient = &client

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

		require.Equal(t, mockPIID, string(resp.Payload))
	})
}

func TestIntroduceREST_AcceptProposalWithOOBRequest(t *testing.T) {
	t.Run("test it accepts a proposal with out-of-bound request", func(t *testing.T) {
		opts := &api.Options{}
		a := NewAries(opts)
		ic, err := a.GetIntroduceController()
		require.NoError(t, err)
		require.NotNil(t, ic)

		mockResponse := ``

		client := mockHTTPClient{data: mockResponse}
		i, ok := ic.(*IntroduceREST)
		require.Equal(t, ok, true)
		i.httpClient = &client

		reqData := `{
	"request": {},
	"piid": "a13832dc-88b8-4714-b697-e5410d23abe2"
}`
		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := i.AcceptProposalWithOOBRequest(req)
		require.NotNil(t, resp)

		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestIntroduceREST_AcceptProposal(t *testing.T) {
	t.Run("test it accepts a proposal", func(t *testing.T) {
		opts := &api.Options{}
		a := NewAries(opts)
		ic, err := a.GetIntroduceController()
		require.NoError(t, err)
		require.NotNil(t, ic)

		mockResponse := ``

		client := mockHTTPClient{data: mockResponse}
		i, ok := ic.(*IntroduceREST)
		require.Equal(t, ok, true)
		i.httpClient = &client

		reqData := `{
	"piid": "a13832dc-88b8-4714-b697-e5410d23abe2"
}`
		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := i.AcceptProposal(req)
		require.NotNil(t, resp)

		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestIntroduceREST_AcceptRequestWithPublicOOBRequest(t *testing.T) {
	t.Run("test it performs an accept request with a public out-of-bound request", func(t *testing.T) {
		opts := &api.Options{}
		a := NewAries(opts)
		ic, err := a.GetIntroduceController()
		require.NoError(t, err)
		require.NotNil(t, ic)

		mockResponse := ``

		client := mockHTTPClient{data: mockResponse}
		i, ok := ic.(*IntroduceREST)
		require.Equal(t, ok, true)
		i.httpClient = &client

		reqData := `{
	"request": {},
	"piid": "a13832dc-88b8-4714-b697-e5410d23abe2",
	"to": {}
}`
		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := i.AcceptRequestWithPublicOOBRequest(req)
		require.NotNil(t, resp)

		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestIntroduceREST_AcceptRequestWithRecipients(t *testing.T) {
	t.Run("test it accepts a request with recipients", func(t *testing.T) {
		opts := &api.Options{}
		a := NewAries(opts)
		ic, err := a.GetIntroduceController()
		require.NoError(t, err)
		require.NotNil(t, ic)

		mockResponse := ``

		client := mockHTTPClient{data: mockResponse}
		i, ok := ic.(*IntroduceREST)
		require.Equal(t, ok, true)
		i.httpClient = &client

		reqData := `{
	"request": {},
	"piid": "a13832dc-88b8-4714-b697-e5410d23abe2",
	"to": {}
}`
		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := i.AcceptRequestWithRecipients(req)
		require.NotNil(t, resp)

		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestIntroduce_DeclineProposal(t *testing.T) {
	t.Run("test it declines a proposal", func(t *testing.T) {
		a := NewAries(&api.Options{})

		ic, err := a.GetIntroduceController()
		require.NoError(t, err)
		require.NotNil(t, ic)

		mockResponse := ``

		client := mockHTTPClient{data: mockResponse}
		i, ok := ic.(*IntroduceREST)
		require.Equal(t, ok, true)
		i.httpClient = &client

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
		a := NewAries(&api.Options{})

		ic, err := a.GetIntroduceController()
		require.NoError(t, err)
		require.NotNil(t, ic)

		mockResponse := ``

		client := mockHTTPClient{data: mockResponse}
		i, ok := ic.(*IntroduceREST)
		require.Equal(t, ok, true)
		i.httpClient = &client

		reqData := `{
	"reason": "not in agreement",
	"piid": "a13832dc-88b8-4714-b697-e5410d23abe2"
}`
		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := i.DeclineRequest(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, "", string(resp.Payload))
	})
}
