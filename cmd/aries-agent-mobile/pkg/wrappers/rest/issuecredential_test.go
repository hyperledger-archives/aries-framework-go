/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	opisscred "github.com/hyperledger/aries-framework-go/pkg/controller/rest/issuecredential"
)

func getIssueCredentialController(t *testing.T) *IssueCredential {
	a, err := getAgent()
	require.NotNil(t, a)
	require.NoError(t, err)

	controller, err := a.GetIssueCredentialController()
	require.NoError(t, err)
	require.NotNil(t, controller)

	ic, ok := controller.(*IssueCredential)
	require.Equal(t, ok, true)

	return ic
}

func TestIssueCredential_Actions(t *testing.T) {
	t.Run("test it performs a get actions request", func(t *testing.T) {
		ic := getIssueCredentialController(t)

		mockResponse := `{"actions":[{"PIID":"ID1"},{"PIID":"ID2"},{"PIID":"ID3"}]}`
		ic.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodGet, url: mockAgentURL + opisscred.Actions,
		}

		reqData := emptyJSON

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := ic.Actions(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestIssueCredential_SendOffer(t *testing.T) {
	t.Run("test it performs a send offer request", func(t *testing.T) {
		ic := getIssueCredentialController(t)

		mockResponse := fmt.Sprintf(`{"piid": "%s"}`, mockPIID)
		ic.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockAgentURL + opisscred.SendOffer,
		}

		reqData := `{"my_did":"id","their_did":"id","offer_credential":{}}`

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := ic.SendOffer(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestIssueCredential_SendProposal(t *testing.T) {
	t.Run("test it performs a send proposal request", func(t *testing.T) {
		ic := getIssueCredentialController(t)

		mockResponse := fmt.Sprintf(`{"piid": "%s"}`, mockPIID)
		ic.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockAgentURL + opisscred.SendProposal,
		}

		reqData := `{"my_did":"id","their_did":"id","propose_credential":{}}`

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := ic.SendProposal(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestIssueCredential_SendRequest(t *testing.T) {
	t.Run("test it sends a request", func(t *testing.T) {
		ic := getIssueCredentialController(t)

		mockResponse := fmt.Sprintf(`{"piid": "%s"}`, mockPIID)
		ic.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockAgentURL + opisscred.SendRequest,
		}

		reqData := `{"my_did":"id","their_did":"id","request_credential":{}}`

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := ic.SendRequest(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestIssueCredential_AcceptProposal(t *testing.T) {
	t.Run("test it makes an accept proposal request", func(t *testing.T) {
		ic := getIssueCredentialController(t)

		reqData := `{"piid":"id","offer_credential":{}}`
		mockURL, err := parseURL(mockAgentURL, opisscred.AcceptProposal, reqData)
		require.NoError(t, err, "failed to parse test url")

		mockResponse := emptyJSON
		ic.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockURL,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := ic.AcceptProposal(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestIssueCredential_NegotiateProposal(t *testing.T) {
	t.Run("test it makes a negotiate proposal request", func(t *testing.T) {
		ic := getIssueCredentialController(t)

		reqData := `{"piid":"id","propose_credential":{}}`
		mockURL, err := parseURL(mockAgentURL, opisscred.NegotiateProposal, reqData)
		require.NoError(t, err, "failed to parse test url")

		mockResponse := emptyJSON
		ic.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockURL,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := ic.NegotiateProposal(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestIssueCredential_DeclineProposal(t *testing.T) {
	t.Run("test it makes a decline proposal request", func(t *testing.T) {
		ic := getIssueCredentialController(t)

		reqData := fmt.Sprintf(`{"piid": "%s"}`, mockPIID)
		mockURL, err := parseURL(mockAgentURL, opisscred.DeclineProposal, reqData)
		require.NoError(t, err, "failed to parse test url")

		mockResponse := emptyJSON
		ic.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockURL,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := ic.DeclineProposal(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestIssueCredential_AcceptOffer(t *testing.T) {
	t.Run("test it makes a accept offer request", func(t *testing.T) {
		ic := getIssueCredentialController(t)

		reqData := fmt.Sprintf(`{"piid": "%s"}`, mockPIID)
		mockURL, err := parseURL(mockAgentURL, opisscred.AcceptOffer, reqData)
		require.NoError(t, err, "failed to parse test url")

		mockResponse := emptyJSON
		ic.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockURL,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := ic.AcceptOffer(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestIssueCredential_AcceptProblemReport(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ic := getIssueCredentialController(t)

		reqData := fmt.Sprintf(`{"piid": "%s"}`, mockPIID)
		mockURL, err := parseURL(mockAgentURL, opisscred.AcceptProblemReport, reqData)
		require.NoError(t, err, "failed to parse test url")

		mockResponse := emptyJSON
		ic.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockURL,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := ic.AcceptProblemReport(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestIssueCredential_DeclineOffer(t *testing.T) {
	t.Run("test it makes a decline offer request", func(t *testing.T) {
		ic := getIssueCredentialController(t)

		reqData := fmt.Sprintf(`{"piid": "%s"}`, mockPIID)
		mockURL, err := parseURL(mockAgentURL, opisscred.DeclineOffer, reqData)
		require.NoError(t, err, "failed to parse test url")

		mockResponse := emptyJSON
		ic.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockURL,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := ic.DeclineOffer(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestIssueCredential_AcceptRequest(t *testing.T) {
	t.Run("test it accepts a request", func(t *testing.T) {
		ic := getIssueCredentialController(t)

		reqData := `{"piid":"id","issue_credential":{}}`
		mockURL, err := parseURL(mockAgentURL, opisscred.AcceptRequest, reqData)
		require.NoError(t, err, "failed to parse test url")

		mockResponse := emptyJSON
		ic.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockURL,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := ic.AcceptRequest(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestIssueCredential_DeclineRequest(t *testing.T) {
	t.Run("test it declines a request", func(t *testing.T) {
		ic := getIssueCredentialController(t)

		reqData := fmt.Sprintf(`{"piid": "%s"}`, mockPIID)
		mockURL, err := parseURL(mockAgentURL, opisscred.DeclineRequest, reqData)
		require.NoError(t, err, "failed to parse test url")

		mockResponse := emptyJSON
		ic.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockURL,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := ic.DeclineRequest(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestIssueCredential_AcceptCredential(t *testing.T) {
	t.Run("test it accepts a credential", func(t *testing.T) {
		ic := getIssueCredentialController(t)

		reqData := fmt.Sprintf(`{"piid": "%s"}`, mockPIID)
		mockURL, err := parseURL(mockAgentURL, opisscred.AcceptCredential, reqData)
		require.NoError(t, err, "failed to parse test url")

		mockResponse := emptyJSON
		ic.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockURL,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := ic.AcceptCredential(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestIssueCredential_DeclineCredential(t *testing.T) {
	t.Run("test it declines a credential", func(t *testing.T) {
		ic := getIssueCredentialController(t)

		reqData := fmt.Sprintf(`{"piid": "%s"}`, mockPIID)
		mockURL, err := parseURL(mockAgentURL, opisscred.DeclineCredential, reqData)
		require.NoError(t, err, "failed to parse test url")

		mockResponse := emptyJSON
		ic.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockURL,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := ic.DeclineCredential(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}
