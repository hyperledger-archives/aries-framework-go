/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofbandv2

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	oobv2 "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofbandv2"
	mockroute "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/mediator"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
)

// Ensure Client can emit events.
var _ service.Event = (*Client)(nil)

func TestNew(t *testing.T) {
	t.Run("returns client", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		require.NotNil(t, c)
		require.NotNil(t, c.Event)
	})
}

func TestCreateInvitation(t *testing.T) {
	t.Run("sets an id", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		inv, err := c.CreateInvitation()
		require.NoError(t, err)
		require.NotEmpty(t, inv.ID)
	})
	t.Run("sets correct type", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		inv, err := c.CreateInvitation()
		require.NoError(t, err)
		require.Equal(t, "https://didcomm.org/out-of-band/2.0/invitation", inv.Type)
	})
	t.Run("WithLabel", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		expected := uuid.New().String()
		inv, err := c.CreateInvitation(WithLabel(expected))
		require.NoError(t, err)
		require.Equal(t, expected, inv.Label)
	})
	t.Run("WithGoal", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		expectedGoal := uuid.New().String()
		expectedGoalCode := uuid.New().String()
		inv, err := c.CreateInvitation(WithGoal(expectedGoal, expectedGoalCode))
		require.NoError(t, err)
		require.Equal(t, expectedGoal, inv.Body.Goal)
		require.Equal(t, expectedGoalCode, inv.Body.GoalCode)
	})
	t.Run("WithAttachments", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		expected := dummyAttachment(t)
		inv, err := c.CreateInvitation(WithAttachments(expected))
		require.NoError(t, err)
		require.Contains(t, inv.Requests, expected)
	})
	t.Run("WithAttachments", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		expected := dummyAttachment(t)
		inv, err := c.CreateInvitation(WithAttachments(expected))
		require.NoError(t, err)
		require.Contains(t, inv.Requests, expected)
	})
}

func TestAcceptInvitation(t *testing.T) {
	t.Run("returns connection ID", func(t *testing.T) {
		provider := withTestProvider()
		provider.ServiceMap = map[string]interface{}{
			oobv2.Name: &stubOOBService{
				acceptInvFunc: func(*oobv2.Invitation, oobv2.Options) error {
					return nil
				},
			},
		}
		c, err := New(provider)
		require.NoError(t, err)
		err = c.AcceptInvitation(&oobv2.Invitation{}, nil)
		require.NoError(t, err)
	})
	t.Run("wraps error from outofband service", func(t *testing.T) {
		expected := errors.New("test")
		provider := withTestProvider()
		provider.ServiceMap = map[string]interface{}{
			oobv2.Name: &stubOOBService{
				acceptInvFunc: func(*oobv2.Invitation, oobv2.Options) error {
					return expected
				},
			},
		}
		c, err := New(provider)
		require.NoError(t, err)
		err = c.AcceptInvitation(&oobv2.Invitation{}, nil)
		require.Error(t, err)
	})
}

func dummyAttachment(t *testing.T) *decorator.AttachmentV2 {
	t.Helper()

	return base64Attachment(t, &didcommMsg{
		ID:   uuid.New().String(),
		Type: uuid.New().String(),
	})
}

func base64Attachment(t *testing.T, data interface{}) *decorator.AttachmentV2 {
	t.Helper()

	bytes, err := json.Marshal(data)
	require.NoError(t, err)

	return &decorator.AttachmentV2{
		ID:          uuid.New().String(),
		Description: uuid.New().String(),
		FileName:    uuid.New().String(),
		MediaType:   uuid.New().String(),
		LastModTime: time.Now(),
		ByteCount:   0,
		Data: decorator.AttachmentData{
			Base64: base64.StdEncoding.EncodeToString(bytes),
		},
	}
}

type didcommMsg struct {
	ID   string
	Type string
}

func withTestProvider() *mockprovider.Provider {
	mockKey, err := mockkms.CreateMockED25519KeyHandle()
	if err != nil {
		return nil
	}

	return &mockprovider.Provider{
		ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
		StorageProviderValue:              mockstore.NewMockStoreProvider(),
		KMSValue:                          &mockkms.KeyManager{CreateKeyValue: mockKey},
		ServiceMap: map[string]interface{}{
			mediator.Coordination: &mockroute.MockMediatorSvc{Connections: []string{"xyz"}},
			oobv2.Name:            &stubOOBService{},
		},
		ServiceEndpointValue: "endpoint",
	}
}

type stubOOBService struct {
	service.Event
	acceptInvFunc func(*oobv2.Invitation, oobv2.Options) error
}

func (s *stubOOBService) AcceptInvitation(i *oobv2.Invitation, o oobv2.Options) error {
	if s.acceptInvFunc != nil {
		return s.acceptInvFunc(i, o)
	}

	return nil
}
