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
	opdidexch "github.com/hyperledger/aries-framework-go/pkg/controller/rest/didexchange"
)

const (
	publicDID         = "sample-public-did"
	mockRequestWithID = `{"id":"1234"}`
)

func getDIDExchangeController(t *testing.T) *DIDExchange {
	a, err := getAgent()
	require.NotNil(t, a)
	require.NoError(t, err)

	controller, err := a.GetDIDExchangeController()
	require.NoError(t, err)
	require.NotNil(t, controller)

	de, ok := controller.(*DIDExchange)
	require.Equal(t, ok, true)

	return de
}

func TestDIDExchange_CreateInvitation(t *testing.T) {
	t.Run("test it creates an invitation", func(t *testing.T) {
		de := getDIDExchangeController(t)

		mockResponse := `{
		"invitation":{
			"@id":"f39f9537-b6b6-4d2f-8122-3b09cb3c6c1e",
			"did":"sample-public-did",
			"@type":"https://didcomm.org/didexchange/1.0/invitation"},
		"alias":"myalias","invitation_url":""}`
		de.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockAgentURL + opdidexch.CreateInvitationPath,
		}

		reqData := fmt.Sprintf(`{"alias":"myalias", "public": "%s"}`, publicDID)
		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := de.CreateInvitation(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestDIDExchange_ReceiveInvitation(t *testing.T) {
	t.Run("test it receives an invitation", func(t *testing.T) {
		de := getDIDExchangeController(t)

		mockResponse := `{
		"state":"",
		"created_at":"0001-01-01T00:00:00Z",
		"updated_at":"0001-01-01T00:00:00Z",
		"connection_id":"5b995fda-69b3-4d04-8c60-cc80d14bfba7",
		"request_id":"","my_did":""}`
		de.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockAgentURL + opdidexch.ReceiveInvitationPath,
		}

		reqData := `{
		"serviceEndpoint":"http://alice.agent.example.com:8081",
		"recipientKeys":["FDmegH8upiNquathbHZiGBZKwcudNfNWPeGQFBt8eNNi"],
		"@id":"a35c0ac6-4fc3-46af-a072-c1036d036057",
		"label":"agent",
		"@type":"https://didcomm.org/didexchange/1.0/invitation"}`
		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := de.ReceiveInvitation(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestDIDExchange_AcceptInvitation(t *testing.T) {
	t.Run("test it accepts an invitation", func(t *testing.T) {
		de := getDIDExchangeController(t)

		reqData := mockRequestWithID
		mockURL, err := parseURL(mockAgentURL, opdidexch.AcceptInvitationPath, reqData)
		require.NoError(t, err, "failed to parse test url")

		mockResponse := `{"created_at":"0001-01-01T00:00:00Z","updated_at":"0001-01-01T00:00:00Z","connection_id":"1234"}`
		de.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockURL,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := de.AcceptInvitation(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestDIDExchange_CreateImplicitInvitation(t *testing.T) {
	t.Run("test it creates an implicit invitation", func(t *testing.T) {
		de := getDIDExchangeController(t)

		mockResponse := `{"connection_id":"connection-id"}`
		de.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockAgentURL + opdidexch.CreateImplicitInvitationPath,
		}

		reqData := `{"their_did":"sample-public-did"}`

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := de.CreateImplicitInvitation(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestDIDExchange_AcceptExchangeRequest(t *testing.T) {
	t.Run("test it accepts an exchange request", func(t *testing.T) {
		de := getDIDExchangeController(t)

		reqData := mockRequestWithID
		mockURL, err := parseURL(mockAgentURL, opdidexch.AcceptExchangeRequest, reqData)
		require.NoError(t, err, "failed to parse test url")

		mockResponse := `{
		"their_did":"","request_id":"","connection_id":"1234",
		"updated_at":"0001-01-01T00:00:00Z","created_at":"0001-01-01T00:00:00Z","state":""}`
		de.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockURL,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := de.AcceptExchangeRequest(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestDIDExchange_QueryConnections(t *testing.T) {
	t.Run("test it fetches all connections", func(t *testing.T) {
		de := getDIDExchangeController(t)

		mockResponse := `{"results":[{"ConnectionID":"1234","State":"requested","ThreadID":"th1234",
		"ParentThreadID":"","TheirLabel":"","TheirDID":"","MyDID":"","ServiceEndPoint":"","RecipientKeys":null,
		"RoutingKeys":null,"InvitationID":"","InvitationDID":"","Implicit":false,"Namespace":""}]}`
		de.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodGet, url: mockAgentURL + opdidexch.Connections,
		}

		reqData := `{"state":"requested"}`

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := de.QueryConnections(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestDIDExchange_QueryConnectionByID(t *testing.T) {
	t.Run("test it fetches a connection by its id", func(t *testing.T) {
		de := getDIDExchangeController(t)

		reqData := mockRequestWithID
		mockURL, err := parseURL(mockAgentURL, opdidexch.ConnectionsByID, reqData)
		require.NoError(t, err, "failed to parse test url")

		mockResponse := `{"result":{"ConnectionID":"1234","State":"complete","ThreadID":"th1234","ParentThreadID":"",
		"TheirLabel":"","TheirDID":"","MyDID":"","ServiceEndPoint":"","RecipientKeys":null,"RoutingKeys":null,
		"InvitationID":"","InvitationDID":"","Implicit":false,"Namespace":""}}`
		de.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodGet, url: mockURL,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := de.QueryConnectionByID(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestDIDExchange_CreateConnection(t *testing.T) {
	t.Run("test it creates a connection", func(t *testing.T) {
		de := getDIDExchangeController(t)

		mockResponse := `{"id":"80b55cec-0f49-4610-bda0-612b99bb1d45"}`
		de.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockAgentURL + opdidexch.CreateConnection,
		}

		reqData := `{"myDID":"did:peer:1zQmPdKt5VccAwZ2xmKD9tKeeRGAtQMV9X4uLpsRbGmaqAQ9",
		"theirDID":{"id":"did:peer:1zQmVVFUXT2NkSLRxNJDLkz82FNPiEtoDTWGkXxsxWc6s9u2",
		"contents":{"@context":["https://w3id.org/did/v1"],
		"id":"did:peer:1zQmVVFUXT2NkSLRxNJDLkz82FNPiEtoDTWGkXxsxWc6s9u2",
		"verificationMethod":[{"controller":"did:example:123","id":"e2cbb249-8c25-4e6e-8b92-b1ceee211c8c",
		"publicKeyBase58":"7qf5xCRSGP3NW6PAUonYLmq1LCz6Ux5ynek9nbzGgCnP","type":"Ed25519VerificationKey2018"}],
		"service":[{"id":"didcomm","priority":0,"recipientKeys":["7qf5xCRSGP3NW6PAUonYLmq1LCz6Ux5ynek9nbzGgCnP"],
		"routingKeys":null,"serviceEndpoint":"http://example.com","type":"did-communication"}],
		"authentication":[{"controller":"did:example:123","id":"e2cbb249-8c25-4e6e-8b92-b1ceee211c8c",
		"publicKeyBase58":"7qf5xCRSGP3NW6PAUonYLmq1LCz6Ux5ynek9nbzGgCnP","type":"Ed25519VerificationKey2018"}]}},
		"theirLabel":"alice","invitationID":"0e4dc947-f8e7-485f-a0da-e9936ca91a0d",
		"invitationDID":"did:peer:1zQmaxFktRrz5bX8DXEbkc2oh5Xgb738MWRpFav7oqobvu37",
		"parentThreadID":"c838be85-8126-4d2f-9116-7c0fac84c89f",
		"threadID":"96c40b11-a17c-4d89-a9f0-f6d9aa6d951f","implicit":true}`

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := de.CreateConnection(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestDIDExchange_RemoveConnection(t *testing.T) {
	t.Run("test it removes a connection by its id", func(t *testing.T) {
		de := getDIDExchangeController(t)

		reqData := `{"id":"1234", "myDid": "myDid", "theirDid": "theirDid"}`
		mockURL, err := parseURL(mockAgentURL, opdidexch.RemoveConnection, reqData)
		require.NoError(t, err, "failed to parse test url")

		mockResponse := ``
		de.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockURL,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := de.RemoveConnection(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}
