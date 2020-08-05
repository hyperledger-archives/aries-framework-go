/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	cmdisscred "github.com/hyperledger/aries-framework-go/pkg/controller/command/issuecredential"
)

const (
	mockPIID = `{"piid":"12"}`
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
	t.Run("test it gets all actions", func(t *testing.T) {
		ic := getIssueCredentialController(t)

		mockResponse := `{"actions":[{"PIID":"ID1"},{"PIID":"ID2"},{"PIID":"ID3"}]}`
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		ic.handlers[cmdisscred.Actions] = fakeHandler.exec

		payload := ``

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := ic.Actions(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestIssueCredential_SendOffer(t *testing.T) {
	t.Run("test it sends an offer", func(t *testing.T) {
		ic := getIssueCredentialController(t)

		mockResponse := mockPIID
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		ic.handlers[cmdisscred.SendOffer] = fakeHandler.exec

		payload := `{"my_did":"id","their_did":"id","offer_credential":{}}`

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := ic.SendOffer(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestIssueCredential_SendProposal(t *testing.T) {
	t.Run("test it sends a proposal", func(t *testing.T) {
		ic := getIssueCredentialController(t)

		mockResponse := mockPIID
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		ic.handlers[cmdisscred.SendProposal] = fakeHandler.exec

		payload := `{"my_did":"id","their_did":"id","propose_credential":{}}`

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := ic.SendProposal(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestIssueCredential_SendRequest(t *testing.T) {
	t.Run("test it sends a request", func(t *testing.T) {
		ic := getIssueCredentialController(t)

		mockResponse := mockPIID
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		ic.handlers[cmdisscred.SendRequest] = fakeHandler.exec

		payload := `{"my_did":"id","their_did":"id","request_credential":{}}`

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := ic.SendRequest(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestIssueCredential_AcceptProposal(t *testing.T) {
	t.Run("test it accepts a proposal", func(t *testing.T) {
		ic := getIssueCredentialController(t)

		mockResponse := emptyJSON
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		ic.handlers[cmdisscred.AcceptProposal] = fakeHandler.exec

		payload := `{"piid":"id","offer_credential":{}}`

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := ic.AcceptProposal(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestIssueCredential_NegotiateProposal(t *testing.T) {
	t.Run("test it performs a negotiate proposal operation", func(t *testing.T) {
		ic := getIssueCredentialController(t)

		mockResponse := emptyJSON
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		ic.handlers[cmdisscred.NegotiateProposal] = fakeHandler.exec

		payload := `{"piid":"id","propose_credential":{}}`

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := ic.NegotiateProposal(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestIssueCredential_DeclineProposal(t *testing.T) {
	t.Run("test it performs a delete proposal operation", func(t *testing.T) {
		ic := getIssueCredentialController(t)

		mockResponse := emptyJSON
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		ic.handlers[cmdisscred.DeclineProposal] = fakeHandler.exec

		payload := mockPIID

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := ic.DeclineProposal(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestIssueCredential_AcceptOffer(t *testing.T) {
	t.Run("test it performs an accept offer operation", func(t *testing.T) {
		ic := getIssueCredentialController(t)

		mockResponse := emptyJSON
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		ic.handlers[cmdisscred.AcceptOffer] = fakeHandler.exec

		payload := mockPIID

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := ic.AcceptOffer(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestIssueCredential_AcceptProblemReport(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ic := getIssueCredentialController(t)

		mockResponse := emptyJSON
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		ic.handlers[cmdisscred.AcceptProblemReport] = fakeHandler.exec

		payload := mockPIID

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := ic.AcceptProblemReport(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestIssueCredential_DeclineOffer(t *testing.T) {
	t.Run("test it performs an decline offer operation", func(t *testing.T) {
		ic := getIssueCredentialController(t)

		mockResponse := emptyJSON
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		ic.handlers[cmdisscred.DeclineOffer] = fakeHandler.exec

		payload := mockPIID

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := ic.DeclineOffer(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestIssueCredential_AcceptRequest(t *testing.T) {
	t.Run("test it performs an accept request operation", func(t *testing.T) {
		ic := getIssueCredentialController(t)

		mockResponse := emptyJSON
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		ic.handlers[cmdisscred.AcceptRequest] = fakeHandler.exec

		payload := `{"piid":"id","issue_credential":{}}`

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := ic.AcceptRequest(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestIssueCredential_DeclineRequest(t *testing.T) {
	t.Run("test it performs a decline request operation", func(t *testing.T) {
		ic := getIssueCredentialController(t)

		mockResponse := emptyJSON
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		ic.handlers[cmdisscred.DeclineRequest] = fakeHandler.exec

		payload := mockPIID

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := ic.DeclineRequest(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestIssueCredential_AcceptCredential(t *testing.T) {
	t.Run("test it performs an accept credential operation", func(t *testing.T) {
		ic := getIssueCredentialController(t)

		mockResponse := emptyJSON
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		ic.handlers[cmdisscred.AcceptCredential] = fakeHandler.exec

		payload := mockPIID

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := ic.AcceptCredential(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestIssueCredential_DeclineCredential(t *testing.T) {
	t.Run("test it performs a decline credential operation", func(t *testing.T) {
		ic := getIssueCredentialController(t)

		mockResponse := emptyJSON
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		ic.handlers[cmdisscred.DeclineCredential] = fakeHandler.exec

		payload := mockPIID

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := ic.DeclineCredential(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}
