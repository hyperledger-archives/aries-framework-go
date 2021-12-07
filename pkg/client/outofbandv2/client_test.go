/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofbandv2

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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

func TestNew(t *testing.T) {
	t.Run("returns client", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		require.NotNil(t, c)
	})

	t.Run("client creation fails with empty service map", func(t *testing.T) {
		badProvider := withTestProvider()
		badProvider.ServiceMap = map[string]interface{}{}

		c, err := New(badProvider)
		require.EqualError(t, err, "failed to cast service out-of-band/2.0 as a dependency")
		require.Empty(t, c)
	})

	t.Run("client creation fails with service call returning error", func(t *testing.T) {
		badProvider := withTestProvider()
		badProvider.ServiceErr = fmt.Errorf("service error")

		c, err := New(badProvider)
		require.EqualError(t, err, "failed to look up service out-of-band/2.0 : service error")
		require.Empty(t, c)
	})
}

func TestCreateInvitation(t *testing.T) {
	t.Run("sets an id", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		inv := c.CreateInvitation()
		require.NotEmpty(t, inv.ID)
	})
	t.Run("sets correct type", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		inv := c.CreateInvitation()
		require.Equal(t, "https://didcomm.org/out-of-band/2.0/invitation", inv.Type)
	})
	t.Run("WithLabel", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		expected := uuid.New().String()
		inv := c.CreateInvitation(WithLabel(expected))
		require.Equal(t, expected, inv.Label)
	})
	t.Run("WithGoal", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		expectedGoal := uuid.New().String()
		expectedGoalCode := uuid.New().String()
		inv := c.CreateInvitation(WithGoal(expectedGoal, expectedGoalCode))
		require.Equal(t, expectedGoal, inv.Body.Goal)
		require.Equal(t, expectedGoalCode, inv.Body.GoalCode)
	})
	t.Run("WithAttachments", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		expected := dummyAttachment(t)
		inv := c.CreateInvitation(WithAttachments(expected))
		require.Contains(t, inv.Requests, expected)
	})
	t.Run("WithAttachments", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		expected := dummyAttachment(t)
		inv := c.CreateInvitation(WithAttachments(expected))
		require.Contains(t, inv.Requests, expected)
	})
}

func TestAcceptInvitation(t *testing.T) {
	t.Run("returns connection ID", func(t *testing.T) {
		provider := withTestProvider()
		provider.ServiceMap = map[string]interface{}{
			oobv2.Name: &stubOOBService{
				acceptInvFunc: func(*oobv2.Invitation) error {
					return nil
				},
				connID: "123",
			},
		}
		c, err := New(provider)
		require.NoError(t, err)
		connID, err := c.AcceptInvitation(&oobv2.Invitation{})
		require.NoError(t, err)
		require.NotEmpty(t, connID)
	})
	t.Run("wraps error from outofband service", func(t *testing.T) {
		expected := errors.New("test")
		provider := withTestProvider()
		provider.ServiceMap = map[string]interface{}{
			oobv2.Name: &stubOOBService{
				acceptInvFunc: func(*oobv2.Invitation) error {
					return expected
				},
			},
		}
		c, err := New(provider)
		require.NoError(t, err)
		connID, err := c.AcceptInvitation(&oobv2.Invitation{})
		require.Error(t, err)
		require.Empty(t, connID)
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
	acceptInvFunc func(*oobv2.Invitation) error
	connID        string
}

func (s *stubOOBService) AcceptInvitation(i *oobv2.Invitation) (string, error) {
	if s.acceptInvFunc != nil {
		return s.connID, s.acceptInvFunc(i)
	}

	return "", nil
}
