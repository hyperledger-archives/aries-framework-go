/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	mockwebhook "github.com/hyperledger/aries-framework-go/pkg/controller/internal/mocks/webhook"
	"github.com/hyperledger/aries-framework-go/pkg/controller/webnotifier"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	didexsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol"
	mockdidexchange "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/didexchange"
	mockroute "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/mediator"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms/legacykms"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdri "github.com/hyperledger/aries-framework-go/pkg/mock/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
)

const (
	mockSvcEndpoint = "endpoint"
)

func TestNew(t *testing.T) {
	t.Run("Successfully create new DID exchange command", func(t *testing.T) {
		cmd, err := New(mockProvider(), webnotifier.NewHTTPNotifier(nil), "", false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		handlers := cmd.GetHandlers()
		require.NotEmpty(t, handlers)
	})

	t.Run("Successfully create new DID exchange command with auto accept", func(t *testing.T) {
		cmd, err := New(mockProvider(), webnotifier.NewHTTPNotifier(nil), "", true)
		require.NoError(t, err)
		require.NotNil(t, cmd)
	})

	t.Run("Test create new DID exchange command failure", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{ServiceErr: errors.New("test-error")},
			webnotifier.NewHTTPNotifier(nil), "", false)
		require.Error(t, err)
		require.Nil(t, cmd)
	})
}

func TestCommand_CreateInvitation(t *testing.T) {
	t.Run("Successful CreateInvitation with label", func(t *testing.T) {
		cmd, err := New(mockProvider(), mockwebhook.NewMockWebhookNotifier(), "", false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		jsonReq := `{"alias":"myalias"}`
		var b bytes.Buffer
		cmdErr := cmd.CreateInvitation(&b, bytes.NewBufferString(jsonReq))
		require.NoError(t, cmdErr)

		response := CreateInvitationResponse{}
		err = json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response.Invitation)
		require.Equal(t, mockSvcEndpoint, response.Invitation.ServiceEndpoint)
		require.Empty(t, response.Invitation.Label)
		require.Equal(t, "myalias", response.Alias)
		require.NotEmpty(t, response.Invitation.ID)
		require.Equal(t, "https://didcomm.org/didexchange/1.0/invitation", response.Invitation.Type)
	})

	t.Run("Successful CreateInvitation with label and public DID", func(t *testing.T) {
		const publicDID = "sample-public-did"

		cmd, err := New(mockProvider(), mockwebhook.NewMockWebhookNotifier(), "", false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		jsonReq := fmt.Sprintf(`{"alias":"myalias", "public":"%s"}`, publicDID)

		var b bytes.Buffer
		cmdErr := cmd.CreateInvitation(&b, bytes.NewBufferString(jsonReq))
		require.NoError(t, cmdErr)

		response := CreateInvitationResponse{}
		err = json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response.Invitation)
		require.Empty(t, response.Invitation.ServiceEndpoint)
		require.Empty(t, response.Invitation.Label)
		require.NotEmpty(t, response.Alias)
		require.NotEmpty(t, response.Invitation.DID)
		require.Equal(t, publicDID, response.Invitation.DID)
	})

	t.Run("Successful CreateInvitation with default params", func(t *testing.T) {
		cmd, err := New(mockProvider(), mockwebhook.NewMockWebhookNotifier(), "", false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.CreateInvitation(&b, bytes.NewBufferString("{}"))
		require.NoError(t, cmdErr)

		response := CreateInvitationResponse{}
		err = json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response.Invitation)
		require.Equal(t, mockSvcEndpoint, response.Invitation.ServiceEndpoint)
		require.Empty(t, response.Invitation.Label)
		require.Empty(t, response.Alias)
		require.NotEmpty(t, response.Invitation.ID)
		require.Equal(t, "https://didcomm.org/didexchange/1.0/invitation", response.Invitation.Type)
	})

	t.Run("CreateInvitation failure", func(t *testing.T) {
		const errMsg = "sample-err-01"
		provider := mockProvider()
		provider.StorageProviderValue = mockstore.NewCustomMockStoreProvider(
			&mockstore.MockStore{
				ErrPut: fmt.Errorf(errMsg),
			},
		)

		cmd, err := New(provider, mockwebhook.NewMockWebhookNotifier(), "", false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.CreateInvitation(&b, bytes.NewBufferString("--"))
		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())

		b.Reset()
		cmdErr = cmd.CreateInvitation(&b, bytes.NewBufferString("{}"))
		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errMsg)
		require.Equal(t, CreateInvitationErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})
}

func TestCommand_ReceiveInvitation(t *testing.T) {
	t.Run("Successful ReceiveInvitation", func(t *testing.T) {
		var jsonStr = `{
		"serviceEndpoint":"http://alice.agent.example.com:8081",
		"recipientKeys":["FDmegH8upiNquathbHZiGBZKwcudNfNWPeGQFBt8eNNi"],
		"@id":"a35c0ac6-4fc3-46af-a072-c1036d036057",
		"label":"agent",
		"@type":"https://didcomm.org/didexchange/1.0/invitation"}`

		cmd, err := New(mockProvider(), mockwebhook.NewMockWebhookNotifier(), "", false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.ReceiveInvitation(&b, bytes.NewBufferString(jsonStr))
		require.NoError(t, cmdErr)

		response := ReceiveInvitationResponse{}
		err = json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.ConnectionID)
	})

	t.Run("ReceiveInvitation failure", func(t *testing.T) {
		var jsonStr = `{
    	"@type": "https://didcomm.org/connections/1.0/invitation",
    	"@id": "4e8650d9-6cc9-491e-b00e-7bf6cb5858fc",
    	"serviceEndpoint": "http://ip10-0-46-4-blikjbs9psqg8vrg4p10-8020.direct.play-with-von.vonx.io",
    	"label": "Faber Agent",
    	"recipientKeys": [
      		"6LE8yhZB8Xffc5vFgFntE3YLrxq5JVUsoAvUQgUyktGt"
    		]
  	}`
		const errMsg = "sample-err-01"

		prov := mockProvider()
		prov.ServiceMap[didexsvc.DIDExchange] = &mockdidexchange.MockDIDExchangeSvc{
			ProtocolName: "mockProtocolSvc",
			HandleFunc: func(msg service.DIDCommMsg) (string, error) {
				return uuid.New().String(), fmt.Errorf(errMsg)
			},
		}

		cmd, err := New(prov, mockwebhook.NewMockWebhookNotifier(), "", false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.ReceiveInvitation(&b, bytes.NewBufferString(jsonStr))
		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errMsg)
		require.Equal(t, ReceiveInvitationErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("ReceiveInvitation validation error", func(t *testing.T) {
		var jsonStr = `--`
		cmd, err := New(mockProvider(), mockwebhook.NewMockWebhookNotifier(), "", false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.ReceiveInvitation(&b, bytes.NewBufferString(jsonStr))
		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})
}

func TestCommand_QueryConnectionByID(t *testing.T) {
	t.Run("QueryConnectionByID success", func(t *testing.T) {
		// prepare data
		const connID = "1234"
		prov := mockProvider()
		store := mockstore.MockStore{Store: make(map[string][]byte)}
		connRec := &connection.Record{State: "complete", ConnectionID: "1234", ThreadID: "th1234"}

		connBytes, err := json.Marshal(connRec)
		require.NoError(t, err)
		require.NoError(t, store.Put("conn_"+connID, connBytes))
		prov.StorageProviderValue = &mockstore.MockStoreProvider{Store: &store}

		cmd, err := New(prov, mockwebhook.NewMockWebhookNotifier(), "", false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		jsoStr := fmt.Sprintf(`{"id":"%s"}`, connID)

		var b bytes.Buffer
		cmdErr := cmd.QueryConnectionByID(&b, bytes.NewBufferString(jsoStr))
		require.NoError(t, cmdErr)

		response := QueryConnectionResponse{}
		err = json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.Result.ConnectionID)
		require.Equal(t, connID, response.Result.ConnectionID)
	})

	t.Run("QueryConnectionByID validation error", func(t *testing.T) {
		cmd, err := New(mockProvider(), mockwebhook.NewMockWebhookNotifier(), "", false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.QueryConnectionByID(&b, bytes.NewBufferString("--"))
		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("QueryConnectionByID validation error", func(t *testing.T) {
		cmd, err := New(mockProvider(), mockwebhook.NewMockWebhookNotifier(), "", false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.QueryConnectionByID(&b, bytes.NewBufferString("{}"))
		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
		require.Contains(t, cmdErr.Error(), errEmptyConnID)
	})

	t.Run("QueryConnectionByID store failure", func(t *testing.T) {
		// prepare data
		const errMsg = "sample-err-01"
		prov := mockProvider()
		store := mockstore.MockStore{ErrGet: fmt.Errorf(errMsg)}
		prov.StorageProviderValue = &mockstore.MockStoreProvider{Store: &store}

		cmd, err := New(prov, mockwebhook.NewMockWebhookNotifier(), "", false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.QueryConnectionByID(&b, bytes.NewBufferString(`{"id":"xyz"}`))
		require.Error(t, cmdErr)
		require.Equal(t, QueryConnectionsErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
		require.Contains(t, cmdErr.Error(), errMsg)
	})
}

func TestCommand_QueryConnections(t *testing.T) {
	t.Run("test query connections with state filter", func(t *testing.T) {
		// prepare data
		const connID = "1234"
		const state = "requested"

		prov := mockProvider()
		store := mockstore.MockStore{Store: make(map[string][]byte)}
		connRec := &connection.Record{State: state, ConnectionID: connID, ThreadID: "th1234"}

		connBytes, err := json.Marshal(connRec)
		require.NoError(t, err)
		require.NoError(t, store.Put("conn_"+connID, connBytes))
		prov.StorageProviderValue = &mockstore.MockStoreProvider{Store: &store}

		cmd, err := New(prov, mockwebhook.NewMockWebhookNotifier(), "", false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		jsoStr := fmt.Sprintf(`{"state":"%s"}`, state)

		var b bytes.Buffer
		cmdErr := cmd.QueryConnections(&b, bytes.NewBufferString(jsoStr))
		require.NoError(t, cmdErr)

		response := QueryConnectionsResponse{}
		err = json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.Results)
		require.Len(t, response.Results, 1)
		require.NotEmpty(t, connID, response.Results[0].ConnectionID)
		require.NotEmpty(t, state, response.Results[0].State)

		// test for record not found
		b.Reset()
		cmdErr = cmd.QueryConnections(&b, bytes.NewBufferString(`{"state":"completed"}`))
		require.NoError(t, cmdErr)

		response = QueryConnectionsResponse{}
		err = json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)

		// verify response
		require.Empty(t, response)
	})

	t.Run("test query connections without state filter", func(t *testing.T) {
		// prepare data
		const connID = "1234"

		prov := mockProvider()
		store := mockstore.MockStore{Store: make(map[string][]byte)}
		connRec := &connection.Record{State: "completed", ConnectionID: connID, ThreadID: "th1234"}

		connBytes, err := json.Marshal(connRec)
		require.NoError(t, err)
		require.NoError(t, store.Put("conn_"+connID, connBytes))
		prov.StorageProviderValue = &mockstore.MockStoreProvider{Store: &store}

		cmd, err := New(prov, mockwebhook.NewMockWebhookNotifier(), "", false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.QueryConnections(&b, bytes.NewBufferString("{}"))
		require.NoError(t, cmdErr)

		response := QueryConnectionsResponse{}
		err = json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.Results)
		require.Len(t, response.Results, 1)
		require.NotEmpty(t, connID, response.Results[0].ConnectionID)
	})

	t.Run("test query connections validation error", func(t *testing.T) {
		cmd, err := New(mockProvider(), mockwebhook.NewMockWebhookNotifier(), "", false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.QueryConnections(&b, bytes.NewBufferString("--"))
		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})
}

func TestCommand_AcceptInvitation(t *testing.T) {
	t.Run("test accept invitation success", func(t *testing.T) {
		cmd, err := New(mockProvider(), mockwebhook.NewMockWebhookNotifier(), "", false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptInvitation(&b, bytes.NewBufferString(`{"id":"1234"}`))
		require.NoError(t, cmdErr)

		response := AcceptInvitationResponse{}
		err = json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)
		require.Equal(t, "1234", response.ConnectionID)
	})

	t.Run("test accept invitation validation error", func(t *testing.T) {
		cmd, err := New(mockProvider(), mockwebhook.NewMockWebhookNotifier(), "", false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptInvitation(&b, bytes.NewBufferString(`{"id":""}`))
		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
		require.Contains(t, cmdErr.Error(), errEmptyConnID)

		b.Reset()
		cmdErr = cmd.AcceptInvitation(&b, bytes.NewBufferString(`--`))
		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("test accept invitation failures", func(t *testing.T) {
		const errMsg = "sample-err-01"
		prov := mockProvider()
		prov.ServiceMap[didexsvc.DIDExchange] = &mockdidexchange.MockDIDExchangeSvc{
			ProtocolName: "mockProtocolSvc",
			HandleFunc: func(msg service.DIDCommMsg) (string, error) {
				return uuid.New().String(), nil
			},
			AcceptError: fmt.Errorf(errMsg),
		}

		cmd, err := New(prov, mockwebhook.NewMockWebhookNotifier(), "", false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptInvitation(&b, bytes.NewBufferString(`{"id":"1234"}`))
		require.Error(t, cmdErr)
		require.Equal(t, AcceptInvitationErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
		require.Contains(t, cmdErr.Error(), errMsg)
	})

	t.Run("test accept invitation complete flow", func(t *testing.T) {
		store := mockstore.NewMockStoreProvider()
		didExSvc, err := didexsvc.New(&protocol.MockProvider{
			TransientStoreProvider: store,
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})

		require.NoError(t, err)

		done := make(chan struct{})
		connID := make(chan string)

		// create the client
		cmd, err := New(&mockprovider.Provider{
			TransientStorageProviderValue: store,
			StorageProviderValue:          mockstore.NewMockStoreProvider(),
			ServiceMap: map[string]interface{}{
				didexsvc.DIDExchange:  didExSvc,
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			}},
			&mockwebhook.Notifier{
				NotifyFunc: func(topic string, message []byte) error {
					require.Equal(t, connectionsWebhookTopic, topic)
					conn := ConnectionMsg{}
					jsonErr := json.Unmarshal(message, &conn)
					require.NoError(t, jsonErr)

					if conn.State == "invited" {
						connID <- conn.ConnectionID
					}

					if conn.State == "requested" {
						close(done)
					}

					return nil
				},
			},
			"", false,
		)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		pubKey, _ := generateKeyPair()
		// send connection invitation message
		invitation, err := json.Marshal(
			&didexsvc.Invitation{
				Type:          didexsvc.InvitationMsgType,
				ID:            "abc",
				Label:         "test",
				RecipientKeys: []string{pubKey},
			},
		)
		require.NoError(t, err)

		msg, err := service.ParseDIDCommMsgMap(invitation)
		require.NoError(t, err)

		_, err = didExSvc.HandleInbound(msg, "", "")
		require.NoError(t, err)

		var cid string
		select {
		case cid = <-connID:
		case <-time.After(5 * time.Second):
			require.Fail(t, "tests are not validated")
		}

		jsonStr := fmt.Sprintf(`{"id":"%s"}`, cid)

		var b bytes.Buffer
		cmdErr := cmd.AcceptInvitation(&b, bytes.NewBufferString(jsonStr))
		require.NoError(t, cmdErr)

		response := AcceptInvitationResponse{}
		err = json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(1 * time.Second):
			require.Fail(t, "tests are not validated")
		}
	})
}

func TestCommand_CreateImplicitInvitation(t *testing.T) {
	t.Run("test create implicit invitation success", func(t *testing.T) {
		cmd, err := New(mockProvider(), mockwebhook.NewMockWebhookNotifier(), "", false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.CreateImplicitInvitation(&b, bytes.NewBufferString(`{"their_did":"samle-public-did"}`))
		require.NoError(t, cmdErr)

		response := ImplicitInvitationResponse{}
		err = json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)
		require.NotEmpty(t, response)
		require.Equal(t, "connection-id", response.ConnectionID)
	})

	t.Run("test create implicit invitation with DID success", func(t *testing.T) {
		const jsonStr = `{"their_did":"samle-public-did","my_did":"my-public-did"}`

		cmd, err := New(mockProvider(), mockwebhook.NewMockWebhookNotifier(), "", false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.CreateImplicitInvitation(&b, bytes.NewBufferString(jsonStr))
		require.NoError(t, cmdErr)

		response := ImplicitInvitationResponse{}
		err = json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)
		require.NotEmpty(t, response)
		require.Equal(t, "connection-id", response.ConnectionID)
	})

	t.Run("test create implicit invitation validation error", func(t *testing.T) {
		cmd, err := New(mockProvider(), mockwebhook.NewMockWebhookNotifier(), "", false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.CreateImplicitInvitation(&b, bytes.NewBufferString(`{}`))
		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("test handler failure", func(t *testing.T) {
		const errMsg = "sample-err-01"
		prov := mockProvider()
		prov.ServiceMap[didexsvc.DIDExchange] = &mockdidexchange.MockDIDExchangeSvc{
			ProtocolName: "mockProtocolSvc",
			HandleFunc: func(msg service.DIDCommMsg) (string, error) {
				return uuid.New().String(), nil
			},
			ImplicitInvitationErr: fmt.Errorf(errMsg),
		}

		cmd, err := New(prov, mockwebhook.NewMockWebhookNotifier(), "", false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.CreateImplicitInvitation(&b, bytes.NewBufferString(`{"their_did":"samle-public-did"}`))
		require.Error(t, cmdErr)
		require.Equal(t, CreateImplicitInvitationErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})
}

func TestCommand_AcceptExchangeRequest(t *testing.T) {
	t.Run("test accept exchange request success", func(t *testing.T) {
		cmd, err := New(mockProvider(), mockwebhook.NewMockWebhookNotifier(), "", false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptExchangeRequest(&b, bytes.NewBufferString(`{"id":"1234"}`))
		require.NoError(t, cmdErr)

		response := ExchangeResponse{}
		err = json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)
		require.Equal(t, "1234", response.ConnectionID)
	})

	t.Run("test accept exchange request validation error", func(t *testing.T) {
		cmd, err := New(mockProvider(), mockwebhook.NewMockWebhookNotifier(), "", false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptExchangeRequest(&b, bytes.NewBufferString(`{"id":""}`))
		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
		require.Contains(t, cmdErr.Error(), errEmptyConnID)

		b.Reset()
		cmdErr = cmd.AcceptExchangeRequest(&b, bytes.NewBufferString(`--`))
		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("test accept exchange request failures", func(t *testing.T) {
		const errMsg = "sample-err-01"
		prov := mockProvider()
		prov.ServiceMap[didexsvc.DIDExchange] = &mockdidexchange.MockDIDExchangeSvc{
			ProtocolName: "mockProtocolSvc",
			HandleFunc: func(msg service.DIDCommMsg) (string, error) {
				return uuid.New().String(), nil
			},
			AcceptError: fmt.Errorf(errMsg),
		}

		cmd, err := New(prov, mockwebhook.NewMockWebhookNotifier(), "", false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptExchangeRequest(&b, bytes.NewBufferString(`{"id":"1234"}`))
		require.Error(t, cmdErr)
		require.Equal(t, AcceptExchangeRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
		require.Contains(t, cmdErr.Error(), errMsg)
	})

	t.Run("test accept exchange request complete flow", func(t *testing.T) {
		transientStore := mockstore.NewMockStoreProvider()
		store := mockstore.NewMockStoreProvider()
		didExSvc, err := didexsvc.New(
			&protocol.MockProvider{
				TransientStoreProvider: transientStore, StoreProvider: store,
				ServiceMap: map[string]interface{}{
					mediator.Coordination: &mockroute.MockMediatorSvc{},
				},
			},
		)

		require.NoError(t, err)

		done := make(chan struct{})
		connID := make(chan string)

		// create the client
		cmd, err := New(&mockprovider.Provider{
			TransientStorageProviderValue: transientStore,
			StorageProviderValue:          store,
			ServiceMap: map[string]interface{}{
				didexsvc.DIDExchange:  didExSvc,
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
			LegacyKMSValue: &mockkms.CloseableKMS{CreateSigningKeyValue: "sample-key"}},
			&mockwebhook.Notifier{
				NotifyFunc: func(topic string, message []byte) error {
					require.Equal(t, connectionsWebhookTopic, topic)

					conn := ConnectionMsg{}
					jsonErr := json.Unmarshal(message, &conn)
					require.NoError(t, jsonErr)

					if conn.State == "requested" {
						connID <- conn.ConnectionID
					}

					if conn.State == "responded" {
						close(done)
					}

					return nil
				},
			},
			"", false,
		)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		// send connection request message
		id := "valid-thread-id"
		newDidDoc, err := (&mockvdri.MockVDRIRegistry{}).Create("peer")
		require.NoError(t, err)

		invitation, err := cmd.client.CreateInvitation("test")
		require.NoError(t, err)

		request, err := json.Marshal(
			&didexsvc.Request{
				Type:  didexsvc.RequestMsgType,
				ID:    id,
				Label: "test",
				Thread: &decorator.Thread{
					PID: invitation.ID,
				},
				Connection: &didexsvc.Connection{
					DID:    newDidDoc.ID,
					DIDDoc: newDidDoc,
				},
			},
		)
		require.NoError(t, err)

		msg, err := service.ParseDIDCommMsgMap(request)
		require.NoError(t, err)

		_, err = didExSvc.HandleInbound(msg, "", "")
		require.NoError(t, err)

		cid := <-connID

		jsonStr := fmt.Sprintf(`{"id":"%s"}`, cid)

		var b bytes.Buffer
		cmdErr := cmd.AcceptExchangeRequest(&b, bytes.NewBufferString(jsonStr))
		require.NoError(t, cmdErr)

		response := ExchangeResponse{}
		err = json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			require.Fail(t, "tests are not validated")
		}
	})
}

func TestCommand_RemoveConnection(t *testing.T) {
	t.Run("test remove connection", func(t *testing.T) {
		// prepare data
		const connID = "1234"
		prov := mockProvider()
		store := mockstore.MockStore{Store: make(map[string][]byte)}
		connRec := &connection.Record{State: "complete", ConnectionID: "1234", ThreadID: "th1234"}

		connBytes, err := json.Marshal(connRec)
		require.NoError(t, err)
		require.NoError(t, store.Put("conn_"+connID, connBytes))
		prov.StorageProviderValue = &mockstore.MockStoreProvider{Store: &store}

		cmd, err := New(prov, mockwebhook.NewMockWebhookNotifier(), "", false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer

		cmdErr := cmd.QueryConnectionByID(&b, bytes.NewBufferString(`{"id":"1234"}`))
		require.NoError(t, cmdErr)

		b.Reset()

		cmdErr = cmd.RemoveConnection(&b, bytes.NewBufferString(`{"id":"1234", "myDid": "myDid", "theirDid": "theirDid"}`))
		require.NoError(t, cmdErr)

		b.Reset()

		cmdErr = cmd.QueryConnectionByID(&b, bytes.NewBufferString(`{"id":"1234"}`))
		require.Error(t, cmdErr)
	})

	t.Run("test remove connection validation error", func(t *testing.T) {
		cmd, err := New(mockProvider(), mockwebhook.NewMockWebhookNotifier(), "", false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.RemoveConnection(&b, bytes.NewBufferString(`{"id":""}`))
		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
		require.Contains(t, cmdErr.Error(), errEmptyConnID)

		b.Reset()
		cmdErr = cmd.RemoveConnection(&b, bytes.NewBufferString(`--`))
		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})
}

func TestOperationEventError(t *testing.T) {
	const errMsg = "channel is already registered for the action event"

	t.Run("message event registration failed", func(t *testing.T) {
		client, err := didexchange.New(&mockprovider.Provider{
			TransientStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:          mockstore.NewMockStoreProvider(),
			ServiceMap: map[string]interface{}{
				didexsvc.DIDExchange: &mockdidexchange.MockDIDExchangeSvc{
					RegisterMsgEventErr: errors.New(errMsg),
				},
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			}})

		require.NoError(t, err)
		cmd := &Command{client: client, msgCh: make(chan service.StateMsg)}
		err = cmd.startClientEventListener()
		require.Error(t, err)
		require.Contains(t, err.Error(), "didexchange message event registration failed: "+errMsg)
	})
}

func TestHandleMessageEvent(t *testing.T) {
	storeProv := &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: make(map[string][]byte)}}
	op, err := New(&mockprovider.Provider{
		TransientStorageProviderValue: storeProv,
		StorageProviderValue: &mockstore.MockStoreProvider{
			Store: &mockstore.MockStore{Store: make(map[string][]byte)}},
		ServiceMap: map[string]interface{}{
			didexsvc.DIDExchange:  &mockdidexchange.MockDIDExchangeSvc{},
			mediator.Coordination: &mockroute.MockMediatorSvc{},
		}},
		webnotifier.NewHTTPNotifier(nil), "", false)
	require.NoError(t, err)
	require.NotNil(t, op)

	e := didExEvent{}
	connRec := connection.Record{ConnectionID: e.ConnectionID(), ThreadID: "xyz", State: "completed"}
	connBytes, err := json.Marshal(connRec)
	require.NoError(t, err)
	require.NoError(t, storeProv.Store.Put("conn_"+e.ConnectionID(), connBytes))

	err = op.handleMessageEvents(service.StateMsg{Type: service.PostState, Properties: nil})
	require.Error(t, err)
	require.Contains(t, err.Error(), "event is not of DIDExchange event type")

	err = op.handleMessageEvents(service.StateMsg{
		Type:       service.PostState,
		Properties: mockError{error: errors.New("err type")},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "service processing failed : err type")

	err = op.handleMessageEvents(service.StateMsg{Type: service.PostState, Properties: &didExEvent{}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "send connection notification failed : "+
		"connection notification webhook :")
}

type mockError struct {
	error
}

func (mockError) All() map[string]interface{} {
	return nil
}

func TestSendConnectionNotification(t *testing.T) {
	const (
		connID   = "id1"
		threadID = "xyz"
	)

	storeProv := &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: make(map[string][]byte)}}
	connRec := connection.Record{ConnectionID: connID, ThreadID: threadID, State: "completed"}
	connBytes, err := json.Marshal(connRec)
	require.NoError(t, err)
	require.NoError(t, storeProv.Store.Put("conn_id1", connBytes))
	require.NoError(t, storeProv.Store.Put("connstate_id1"+"completed", connBytes))

	t.Run("send notification success", func(t *testing.T) {
		const testState = "completed"
		store := &mockstore.MockStore{Store: make(map[string][]byte)}
		connRec := &connection.Record{State: testState, ConnectionID: connID, ThreadID: "th1234"}
		connBytes, err := json.Marshal(connRec)
		require.NoError(t, err)
		require.NoError(t, store.Put(stateKey(connID, testState), connBytes))

		op, err := New(&mockprovider.Provider{
			TransientStorageProviderValue: &mockstore.MockStoreProvider{Store: store},
			StorageProviderValue:          &mockstore.MockStoreProvider{Store: store},
			ServiceMap: map[string]interface{}{
				didexsvc.DIDExchange:  &mockdidexchange.MockDIDExchangeSvc{},
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			}},
			webnotifier.NewHTTPNotifier(nil), "", false)
		require.NoError(t, err)
		err = op.sendConnectionNotification(connID, "completed")
		require.NoError(t, err)
	})
	t.Run("send notification connection not found error", func(t *testing.T) {
		op, err := New(&mockprovider.Provider{
			TransientStorageProviderValue: storeProv,
			StorageProviderValue: &mockstore.MockStoreProvider{
				Store: &mockstore.MockStore{Store: make(map[string][]byte)}},
			ServiceMap: map[string]interface{}{
				didexsvc.DIDExchange:  &mockdidexchange.MockDIDExchangeSvc{},
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			}},
			webnotifier.NewHTTPNotifier(nil), "", false)
		require.NoError(t, err)
		err = op.sendConnectionNotification("id2", "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "connection notification webhook : cannot fetch state from store:")
	})
	t.Run("send notification webhook error", func(t *testing.T) {
		const testState = "completed"
		store := &mockstore.MockStore{Store: make(map[string][]byte)}
		connRec := &connection.Record{State: testState, ConnectionID: connID, ThreadID: "th1234"}
		connBytes, err := json.Marshal(connRec)
		require.NoError(t, err)
		require.NoError(t, store.Put(stateKey(connID, testState), connBytes))

		op, err := New(&mockprovider.Provider{
			TransientStorageProviderValue: &mockstore.MockStoreProvider{Store: store},
			StorageProviderValue:          &mockstore.MockStoreProvider{Store: store},
			ServiceMap: map[string]interface{}{
				didexsvc.DIDExchange:  &mockdidexchange.MockDIDExchangeSvc{},
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			}},
			&mockwebhook.Notifier{NotifyFunc: func(topic string, message []byte) error {
				return errors.New("webhook error")
			}},
			"", false)
		require.NoError(t, err)
		require.NotNil(t, op)
		err = op.sendConnectionNotification(connID, testState)
		require.Error(t, err)
		require.Contains(t, err.Error(), "connection notification webhook : webhook error")
	})
}

func mockProvider() *mockprovider.Provider {
	return &mockprovider.Provider{
		TransientStorageProviderValue: mockstore.NewMockStoreProvider(),
		StorageProviderValue:          mockstore.NewMockStoreProvider(),
		ServiceMap: map[string]interface{}{
			didexsvc.DIDExchange:  &mockdidexchange.MockDIDExchangeSvc{},
			mediator.Coordination: &mockroute.MockMediatorSvc{},
		},
		LegacyKMSValue:       &mockkms.CloseableKMS{},
		ServiceEndpointValue: mockSvcEndpoint,
	}
}

func stateKey(connID, state string) string {
	return fmt.Sprintf("connstate_%s_%s", connID, state)
}

type didExEvent struct {
}

func (e *didExEvent) ConnectionID() string {
	return "abc"
}

func (e *didExEvent) InvitationID() string {
	return "xyz"
}

func (e *didExEvent) All() map[string]interface{} {
	return map[string]interface{}{
		"connectionID": e.ConnectionID(),
		"invitationID": e.InvitationID(),
	}
}

func generateKeyPair() (string, []byte) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	return base58.Encode(pubKey[:]), privKey
}
