/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package route

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	mockdispatcher "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/dispatcher"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/internal/mock/kms"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// mock route coordination provider
type mockProvider struct {
	openStoreErr error
	outbound     dispatcher.Outbound
	endpoint     string
}

func (p *mockProvider) OutboundDispatcher() dispatcher.Outbound {
	if p.outbound != nil {
		return p.outbound
	}

	return &mockdispatcher.MockOutbound{}
}

func (p *mockProvider) StorageProvider() storage.Provider {
	if p.openStoreErr != nil {
		return &mockstore.MockStoreProvider{ErrOpenStoreHandle: p.openStoreErr}
	}

	return mockstore.NewMockStoreProvider()
}

func (p *mockProvider) InboundTransportEndpoint() string {
	if p.endpoint != "" {
		return p.endpoint
	}

	return "ws://example.com"
}

func (p *mockProvider) KMS() kms.KeyManager {
	return &mockkms.CloseableKMS{CreateEncryptionKeyValue: "sample-key"}
}

// mock outbound
type mockOutbound struct {
	validateSend func(msg interface{}) error
}

func (m *mockOutbound) Send(msg interface{}, senderVerKey string, des *service.Destination) error {
	return m.validateSend(msg)
}

func (m *mockOutbound) SendToDID(msg interface{}, myDID, theirDID string) error {
	return nil
}

func generateRequestMsgPayload(t *testing.T, id string) *service.DIDCommMsg {
	requestBytes, err := json.Marshal(&Request{
		Type: RequestMsgType,
		ID:   id,
	})
	require.NoError(t, err)

	didMsg, err := service.NewDIDCommMsg(requestBytes)
	require.NoError(t, err)

	return didMsg
}

func generateGrantMsgPayload(t *testing.T, id string) *service.DIDCommMsg {
	grantBytes, err := json.Marshal(&Grant{
		Type: GrantMsgType,
		ID:   id,
	})
	require.NoError(t, err)

	didMsg, err := service.NewDIDCommMsg(grantBytes)
	require.NoError(t, err)

	return didMsg
}

func generateKeyUpdateListMsgPayload(t *testing.T, id string, updates []Update) *service.DIDCommMsg {
	requestBytes, err := json.Marshal(&KeylistUpdate{
		Type:    KeylistUpdateMsgType,
		ID:      id,
		Updates: updates,
	})
	require.NoError(t, err)

	didMsg, err := service.NewDIDCommMsg(requestBytes)
	require.NoError(t, err)

	return didMsg
}

func generateKeylistUpdateResponseMsgPayload(t *testing.T, id string, updates []UpdateResponse) *service.DIDCommMsg {
	respBytes, err := json.Marshal(&KeylistUpdateResponse{
		Type:    KeylistUpdateResponseMsgType,
		ID:      id,
		Updated: updates,
	})
	require.NoError(t, err)

	didMsg, err := service.NewDIDCommMsg(respBytes)
	require.NoError(t, err)

	return didMsg
}

func randomID() string {
	return uuid.New().String()
}
