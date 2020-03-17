/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofband

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/route"
	mockroute "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol/route"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/internal/mock/provider"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms/legacykms"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

func TestNew(t *testing.T) {
	t.Run("returns client", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		require.NotNil(t, c)
	})
	t.Run("wraps persistent store error when opening it", func(t *testing.T) {
		expected := errors.New("test")
		provider := withTestProvider()
		provider.StorageProviderValue = &mockstore.MockStoreProvider{ErrOpenStoreHandle: expected}
		_, err := New(provider)
		require.Error(t, err)
	})
	t.Run("wraps transient store error when opening it", func(t *testing.T) {
		expected := errors.New("test")
		provider := withTestProvider()
		provider.TransientStorageProviderValue = &mockstore.MockStoreProvider{ErrOpenStoreHandle: expected}
		_, err := New(provider)
		require.Error(t, err)
	})
}

func TestCreateRequest(t *testing.T) {
	t.Run("fails with no attachment", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		_, err = c.CreateRequest()
		require.Error(t, err)
	})
	t.Run("sets an id", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		req, err := c.CreateRequest(WithAttachments(dummyAttachment(t)))
		require.NoError(t, err)
		require.NotEmpty(t, req.ID)
	})
	t.Run("sets correct type", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		req, err := c.CreateRequest(WithAttachments(dummyAttachment(t)))
		require.NoError(t, err)
		require.Equal(t, "https://didcomm.org/oob-request/1.0/request", req.Type)
	})
	t.Run("WithAttachments", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		first := dummyAttachment(t)
		second := dummyAttachment(t)
		req, err := c.CreateRequest(WithAttachments(first, second))
		require.NoError(t, err)
		require.Len(t, req.Requests, 2)
		require.Contains(t, req.Requests, first)
		require.Contains(t, req.Requests, second)
	})
	t.Run("includes the diddoc Service block returned by provider", func(t *testing.T) {
		expected := &did.Service{
			ID:              uuid.New().String(),
			Type:            uuid.New().String(),
			Priority:        0,
			RecipientKeys:   []string{uuid.New().String()},
			RoutingKeys:     []string{uuid.New().String()},
			ServiceEndpoint: uuid.New().String(),
			Properties:      nil,
		}
		c, err := New(withTestProvider())
		require.NoError(t, err)
		c.didDocSvcFunc = func() (*did.Service, error) {
			return expected, nil
		}
		req, err := c.CreateRequest(WithAttachments(dummyAttachment(t)))
		require.NoError(t, err)
		require.Len(t, req.Service, 1)
		require.Equal(t, expected, req.Service[0])
	})
	t.Run("WithLabel", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		expected := uuid.New().String()
		req, err := c.CreateRequest(
			WithAttachments(dummyAttachment(t)),
			WithLabel(expected))
		require.NoError(t, err)
		require.Equal(t, expected, req.Label)
	})
	t.Run("WithGoal", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		expectedGoal := uuid.New().String()
		expectedGoalCode := uuid.New().String()
		req, err := c.CreateRequest(
			WithAttachments(dummyAttachment(t)),
			WithGoal(expectedGoal, expectedGoalCode))
		require.NoError(t, err)
		require.Equal(t, expectedGoal, req.Goal)
		require.Equal(t, expectedGoalCode, req.GoalCode)
	})
	t.Run("WithServices diddoc service blocks", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		expected := &did.Service{
			ID:              uuid.New().String(),
			Type:            uuid.New().String(),
			Priority:        0,
			RecipientKeys:   []string{uuid.New().String()},
			RoutingKeys:     []string{uuid.New().String()},
			ServiceEndpoint: uuid.New().String(),
			Properties:      nil,
		}
		req, err := c.CreateRequest(
			WithAttachments(dummyAttachment(t)),
			WithServices(expected))
		require.NoError(t, err)
		require.Len(t, req.Service, 1)
		require.Equal(t, expected, req.Service[0])
	})
	t.Run("WithServices dids", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		expected := "did:example:123"
		req, err := c.CreateRequest(
			WithAttachments(dummyAttachment(t)),
			WithServices(expected))
		require.NoError(t, err)
		require.Len(t, req.Service, 1)
		require.Equal(t, expected, req.Service[0])
	})
	t.Run("WithServices dids and diddoc service blocks", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		didRef := "did:example:123"
		svc := &did.Service{
			ID:              uuid.New().String(),
			Type:            uuid.New().String(),
			Priority:        0,
			RecipientKeys:   []string{uuid.New().String()},
			RoutingKeys:     []string{uuid.New().String()},
			ServiceEndpoint: uuid.New().String(),
			Properties:      nil,
		}
		req, err := c.CreateRequest(
			WithAttachments(dummyAttachment(t)),
			WithServices(svc, didRef))
		require.NoError(t, err)
		require.Len(t, req.Service, 2)
		require.Contains(t, req.Service, didRef)
		require.Contains(t, req.Service, svc)
	})
	t.Run("WithServices rejects invalid dids", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		didRef := "123"
		_, err = c.CreateRequest(
			WithAttachments(dummyAttachment(t)),
			WithServices(didRef))
		require.Error(t, err)
	})
	t.Run("WithServices rejects unsupported service data types", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		unsupported := &struct{ foo string }{foo: "bar"}
		_, err = c.CreateRequest(
			WithAttachments(dummyAttachment(t)),
			WithServices(unsupported))
		require.Error(t, err)
	})
	t.Run("wraps connection recorder error", func(t *testing.T) {
		expected := errors.New("test")
		provider := withTestProvider()
		provider.StorageProviderValue = mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
			ErrPut: expected,
		})
		c, err := New(provider)
		require.NoError(t, err)
		_, err = c.CreateRequest(WithAttachments(dummyAttachment(t)))
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
	t.Run("wraps did service block creation error when KMS fails", func(t *testing.T) {
		expected := errors.New("test")
		provider := withTestProvider()
		provider.KMSValue = &mockkms.CloseableKMS{CreateKeyErr: expected}
		c, err := New(provider)
		require.NoError(t, err)
		_, err = c.CreateRequest(WithAttachments(dummyAttachment(t)))
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
	t.Run("fails when the routing svc implementation cannot be casted to route.ProtocolService", func(t *testing.T) {
		provider := withTestProvider()
		provider.ServiceMap[route.Coordination] = &struct{}{}
		c, err := New(provider)
		require.NoError(t, err)
		_, err = c.CreateRequest(WithAttachments(dummyAttachment(t)))
		require.Error(t, err)
	})
	t.Run("wraps did service block creation error when service lookup fails", func(t *testing.T) {
		expected := errors.New("test")
		provider := withTestProvider()
		provider.ServiceErr = expected
		c, err := New(provider)
		require.NoError(t, err)
		_, err = c.CreateRequest(WithAttachments(dummyAttachment(t)))
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
	t.Run("wraps did service block creation error when route service config fails", func(t *testing.T) {
		expected := errors.New("test")
		provider := withTestProvider()
		routeSvc, ok := provider.ServiceMap[route.Coordination].(*mockroute.MockRouteSvc)
		require.True(t, ok)
		routeSvc.ConfigErr = expected
		c, err := New(provider)
		require.NoError(t, err)
		_, err = c.CreateRequest(WithAttachments(dummyAttachment(t)))
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
	t.Run("wraps did service block creation error when registering a new key with the routing service fails", func(t *testing.T) { //nolint:lll
		expected := errors.New("test")
		provider := withTestProvider()
		routeSvc, ok := provider.ServiceMap[route.Coordination].(*mockroute.MockRouteSvc)
		require.True(t, ok)
		routeSvc.AddKeyErr = expected
		c, err := New(provider)
		require.NoError(t, err)
		_, err = c.CreateRequest(WithAttachments(dummyAttachment(t)))
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
}

func dummyAttachment(t *testing.T) *decorator.Attachment {
	return base64Attachment(t, &didcommMsg{
		ID:   uuid.New().String(),
		Type: uuid.New().String(),
	})
}

func base64Attachment(t *testing.T, data interface{}) *decorator.Attachment {
	bytes, err := json.Marshal(data)
	require.NoError(t, err)

	return &decorator.Attachment{
		ID:          uuid.New().String(),
		Description: uuid.New().String(),
		FileName:    uuid.New().String(),
		MimeType:    uuid.New().String(),
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
	return &mockprovider.Provider{
		TransientStorageProviderValue: mockstore.NewMockStoreProvider(),
		StorageProviderValue:          mockstore.NewMockStoreProvider(),
		KMSValue:                      &mockkms.CloseableKMS{CreateEncryptionKeyValue: "sample-key"},
		ServiceMap: map[string]interface{}{
			route.Coordination: &mockroute.MockRouteSvc{},
		},
		ServiceEndpointValue: "endpoint",
	}
}
