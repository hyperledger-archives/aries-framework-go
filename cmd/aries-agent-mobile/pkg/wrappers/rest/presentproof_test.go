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
	oppresproof "github.com/hyperledger/aries-framework-go/pkg/controller/rest/presentproof"
)

func getPresentProofController(t *testing.T) *PresentProof {
	a, err := getAgent()
	require.NotNil(t, a)
	require.NoError(t, err)

	controller, err := a.GetPresentProofController()
	require.NoError(t, err)
	require.NotNil(t, controller)

	p, ok := controller.(*PresentProof)
	require.Equal(t, ok, true)

	return p
}

func TestPresentProof_Actions(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p := getPresentProofController(t)

		mockResponse := `{"actions":[{"PIID":"ID1"},{"PIID":"ID2"},{"PIID":"ID3"}]}`
		p.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodGet, url: mockAgentURL + oppresproof.Actions,
		}

		reqData := emptyJSON

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := p.Actions(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestPresentProof_SendRequestPresentation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p := getPresentProofController(t)

		mockResponse := mockPIID
		p.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockAgentURL + oppresproof.SendRequestPresentation,
		}

		reqData := `{"my_did":"id","their_did":"id","request_presentation":{}}`

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := p.SendRequestPresentation(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestPresentProof_SendProposePresentation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p := getPresentProofController(t)

		mockResponse := mockPIID
		p.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockAgentURL + oppresproof.SendProposePresentation,
		}

		reqData := `{"my_did":"id","their_did":"id","propose_presentation":{}}`

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := p.SendProposePresentation(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestPresentProof_AcceptRequestPresentation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p := getPresentProofController(t)

		reqData := `{"piid":"id","presentation":{}}`
		mockURL, err := parseURL(mockAgentURL, oppresproof.AcceptRequestPresentation, reqData)
		require.NoError(t, err, "failed to parse test url")

		mockResponse := emptyJSON
		p.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockURL,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := p.AcceptRequestPresentation(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestPresentProof_NegotiateRequestPresentation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p := getPresentProofController(t)

		reqData := `{"piid":"id","propose_presentation":{}}`
		mockURL, err := parseURL(mockAgentURL, oppresproof.NegotiateRequestPresentation, reqData)
		require.NoError(t, err, "failed to parse test url")

		mockResponse := emptyJSON
		p.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockURL,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := p.NegotiateRequestPresentation(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestPresentProof_DeclineRequestPresentation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p := getPresentProofController(t)

		reqData := fmt.Sprintf(`{"piid": "%s"}`, mockPIID)
		mockURL, err := parseURL(mockAgentURL, oppresproof.DeclineRequestPresentation, reqData)
		require.NoError(t, err, "failed to parse test url")

		mockResponse := emptyJSON
		p.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockURL,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := p.DeclineRequestPresentation(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestPresentProof_AcceptProposePresentation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p := getPresentProofController(t)

		reqData := `{"piid":"id","request_presentation":{}}`
		mockURL, err := parseURL(mockAgentURL, oppresproof.AcceptProposePresentation, reqData)
		require.NoError(t, err, "failed to parse test url")

		mockResponse := emptyJSON
		p.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockURL,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := p.AcceptProposePresentation(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestPresentProof_DeclineProposePresentation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p := getPresentProofController(t)

		reqData := fmt.Sprintf(`{"piid": "%s"}`, mockPIID)
		mockURL, err := parseURL(mockAgentURL, oppresproof.DeclineProposePresentation, reqData)
		require.NoError(t, err, "failed to parse test url")

		mockResponse := emptyJSON
		p.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockURL,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := p.DeclineProposePresentation(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestPresentProof_AcceptPresentation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p := getPresentProofController(t)

		reqData := fmt.Sprintf(`{"piid": "%s"}`, mockPIID)
		mockURL, err := parseURL(mockAgentURL, oppresproof.AcceptPresentation, reqData)
		require.NoError(t, err, "failed to parse test url")

		mockResponse := emptyJSON
		p.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockURL,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := p.AcceptPresentation(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestPresentProof_AcceptProblemReport(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p := getPresentProofController(t)

		reqData := fmt.Sprintf(`{"piid": "%s"}`, mockPIID)
		mockURL, err := parseURL(mockAgentURL, oppresproof.AcceptProblemReport, reqData)
		require.NoError(t, err, "failed to parse test url")

		mockResponse := emptyJSON
		p.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockURL,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := p.AcceptProblemReport(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestPresentProof_DeclinePresentation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p := getPresentProofController(t)

		reqData := fmt.Sprintf(`{"piid": "%s"}`, mockPIID)
		mockURL, err := parseURL(mockAgentURL, oppresproof.DeclinePresentation, reqData)
		require.NoError(t, err, "failed to parse test url")

		mockResponse := emptyJSON
		p.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockURL,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := p.DeclinePresentation(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}
