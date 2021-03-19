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

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	opintroduce "github.com/hyperledger/aries-framework-go/pkg/controller/rest/introduce"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"
)

var mockPIID = "f749b739-1f3d-4213-9c33-c3878cdb6e24" //nolint:gochecknoglobals

type mockHTTPClient struct {
	data   string
	url    string
	method string
}

func (client *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if client.url != req.URL.String() {
		return nil, fmt.Errorf("wrong url: expected - %s got - %s", client.url, req.URL.String())
	}

	if client.method != req.Method {
		return nil, fmt.Errorf("wrong method: expected - %s got - %s", client.method, req.Method)
	}

	r := ioutil.NopCloser(bytes.NewReader([]byte(client.data)))

	return &http.Response{
		StatusCode: 200,
		Body:       r,
	}, nil
}

func getIntroduceController(t *testing.T) *Introduce {
	a, err := getAgent()
	require.NoError(t, err)
	require.NotNil(t, a)

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

		mockResponse := `{"actions":[{"PIID":"ID1","Msg":null,"MyDID":"","TheirDID":""},
{"PIID":"ID2","Msg":null,"MyDID":"","TheirDID":""}]}`

		i.httpClient = &mockHTTPClient{data: mockResponse, method: http.MethodGet, url: mockAgentURL + opintroduce.Actions}

		req := &models.RequestEnvelope{}
		resp := i.Actions(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestIntroduce_SendProposal(t *testing.T) {
	t.Run("test it performs a send proposal request", func(t *testing.T) {
		i := getIntroduceController(t)

		i.httpClient = &mockHTTPClient{
			data:   mockPIID,
			method: http.MethodPost, url: mockAgentURL + opintroduce.SendProposal,
		}

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
		require.Equal(t, mockPIID, string(resp.Payload))
	})
}

func TestIntroduce_SendProposalWithOOBInvitation(t *testing.T) {
	t.Run("test it performs a send proposal with out-of-band invitation", func(t *testing.T) {
		i := getIntroduceController(t)

		i.httpClient = &mockHTTPClient{
			data:   mockPIID,
			method: http.MethodPost, url: mockAgentURL + opintroduce.SendProposalWithOOBInvitation,
		}

		reqData := fmt.Sprintf(`{
	"recipient": {
			"my_did": "did:mydid:123",
			"their_did": "gopher1:example:001"
	},
	"invitation":	{
			"@type": "%s"
	}
}`, outofband.InvitationMsgType)
		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := i.SendProposalWithOOBInvitation(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockPIID, string(resp.Payload))
	})
}

func TestIntroduce_SendRequest(t *testing.T) {
	t.Run("test it performs a send request", func(t *testing.T) {
		i := getIntroduceController(t)

		i.httpClient = &mockHTTPClient{
			data:   mockPIID,
			method: http.MethodPost, url: mockAgentURL + opintroduce.SendRequest,
		}

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
		require.Equal(t, mockPIID, string(resp.Payload))
	})
}

func TestIntroduce_AcceptProposalWithOOBRequest(t *testing.T) {
	t.Run("test it accepts a proposal with out-of-band request", func(t *testing.T) {
		i := getIntroduceController(t)

		mockResponse := ``
		reqData := `{
	"request": {},
	"piid": "a13832dc-88b8-4714-b697-e5410d23abe2"
}`

		mockURL, err := parseURL(mockAgentURL, opintroduce.AcceptProposalWithOOBInvitation, reqData)
		require.NoError(t, err, "failed to parse test url")

		i.httpClient = &mockHTTPClient{data: mockResponse, method: http.MethodPost, url: mockURL}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := i.AcceptProposalWithOOBInvitation(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestIntroduce_AcceptProposal(t *testing.T) {
	t.Run("test it accepts a proposal", func(t *testing.T) {
		i := getIntroduceController(t)

		mockResponse := ``
		reqData := `{
	"piid": "a13832dc-88b8-4714-b697-e5410d23abe2"
}`

		mockURL, err := parseURL(mockAgentURL, opintroduce.AcceptProposal, reqData)
		require.NoError(t, err, "failed to parse test url")

		i.httpClient = &mockHTTPClient{data: mockResponse, method: http.MethodPost, url: mockURL}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := i.AcceptProposal(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestIntroduce_AcceptRequestWithPublicOOBRequest(t *testing.T) {
	t.Run("test it performs an accept request with a public out-of-band request", func(t *testing.T) {
		i := getIntroduceController(t)

		mockResponse := ``
		reqData := `{
	"request": {},
	"piid": "a13832dc-88b8-4714-b697-e5410d23abe2",
	"to": {}
}`

		mockURL, err := parseURL(mockAgentURL, opintroduce.AcceptRequestWithPublicOOBInvitation, reqData)
		require.NoError(t, err, "failed to parse test url")

		i.httpClient = &mockHTTPClient{data: mockResponse, method: http.MethodPost, url: mockURL}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := i.AcceptRequestWithPublicOOBInvitation(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestIntroduce_AcceptRequestWithRecipients(t *testing.T) {
	t.Run("test it accepts a request with recipients", func(t *testing.T) {
		i := getIntroduceController(t)

		mockResponse := ``
		reqData := `{
	"request": {},
	"piid": "a13832dc-88b8-4714-b697-e5410d23abe2",
	"to": {}
}`

		mockURL, err := parseURL(mockAgentURL, opintroduce.AcceptRequestWithRecipients, reqData)
		require.NoError(t, err, "failed to parse test url")

		i.httpClient = &mockHTTPClient{data: mockResponse, method: http.MethodPost, url: mockURL}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := i.AcceptRequestWithRecipients(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestIntroduce_DeclineProposal(t *testing.T) {
	t.Run("test it declines a proposal", func(t *testing.T) {
		i := getIntroduceController(t)

		mockResponse := ``
		reqData := `{
	"reason": "not in agreement",
	"piid": "a13832dc-88b8-4714-b697-e5410d23abe2"
}`

		mockURL, err := parseURL(mockAgentURL, opintroduce.DeclineProposal, reqData)
		require.NoError(t, err, "failed to parse test url")

		i.httpClient = &mockHTTPClient{data: mockResponse, method: http.MethodPost, url: mockURL}

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

		mockResponse := ``
		reqData := `{
	"reason": "not in agreement",
	"piid": "a13832dc-88b8-4714-b697-e5410d23abe2"
}`

		mockURL, err := parseURL(mockAgentURL, opintroduce.DeclineRequest, reqData)
		require.NoError(t, err, "failed to parse test url")

		i.httpClient = &mockHTTPClient{data: mockResponse, method: http.MethodPost, url: mockURL}

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

		mockResponse := ``
		reqData := `{"piid": "a13832dc-88b8-4714-b697-e5410d23abe2"}`

		mockURL, err := parseURL(mockAgentURL, opintroduce.AcceptProblemReport, reqData)
		require.NoError(t, err, "failed to parse test url")

		i.httpClient = &mockHTTPClient{data: mockResponse, method: http.MethodPost, url: mockURL}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := i.AcceptProblemReport(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, "", string(resp.Payload))
	})
}
