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

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

func TestNew(t *testing.T) {
	t.Run("returns client", func(t *testing.T) {
		c := New(
			&mockProvider{
				didDocSvcFunc: func() (*did.Service, error) {
					return &did.Service{}, nil
				},
				connRecorder: connRecorder(),
			},
		)
		require.NotNil(t, c)
	})
}

func TestCreateRequest(t *testing.T) {
	t.Run("fails with no attachment", func(t *testing.T) {
		c := New(
			&mockProvider{
				didDocSvcFunc: func() (*did.Service, error) {
					return &did.Service{}, nil
				},
				connRecorder: connRecorder(),
			},
		)
		_, err := c.CreateRequest()
		require.Error(t, err)
	})
	t.Run("sets an id", func(t *testing.T) {
		c := New(
			&mockProvider{
				didDocSvcFunc: func() (*did.Service, error) {
					return &did.Service{}, nil
				},
				connRecorder: connRecorder(),
			},
		)
		req, err := c.CreateRequest(WithAttachments(dummyAttachment(t)))
		require.NoError(t, err)
		require.NotEmpty(t, req.ID)
	})
	t.Run("sets correct type", func(t *testing.T) {
		c := New(
			&mockProvider{
				didDocSvcFunc: func() (*did.Service, error) {
					return &did.Service{}, nil
				},
				connRecorder: connRecorder(),
			},
		)
		req, err := c.CreateRequest(WithAttachments(dummyAttachment(t)))
		require.NoError(t, err)
		require.Equal(t, "https://didcomm.org/oob-request/1.0/request", req.Type)
	})
	t.Run("WithAttachments", func(t *testing.T) {
		c := New(
			&mockProvider{
				didDocSvcFunc: func() (*did.Service, error) {
					return &did.Service{}, nil
				},
				connRecorder: connRecorder(),
			},
		)
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
		c := New(
			&mockProvider{
				didDocSvcFunc: func() (*did.Service, error) {
					return expected, nil
				},
				connRecorder: connRecorder(),
			},
		)
		req, err := c.CreateRequest(WithAttachments(dummyAttachment(t)))
		require.NoError(t, err)
		require.Len(t, req.Service, 1)
		require.Equal(t, expected, req.Service[0])
	})
	t.Run("WithLabel", func(t *testing.T) {
		c := New(
			&mockProvider{
				didDocSvcFunc: func() (*did.Service, error) {
					return &did.Service{}, nil
				},
				connRecorder: connRecorder(),
			},
		)
		expected := uuid.New().String()
		req, err := c.CreateRequest(
			WithAttachments(dummyAttachment(t)),
			WithLabel(expected))
		require.NoError(t, err)
		require.Equal(t, expected, req.Label)
	})
	t.Run("WithGoal", func(t *testing.T) {
		c := New(
			&mockProvider{
				didDocSvcFunc: func() (*did.Service, error) {
					return &did.Service{}, nil
				},
				connRecorder: connRecorder(),
			},
		)
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
		c := New(
			&mockProvider{
				didDocSvcFunc: func() (*did.Service, error) {
					return &did.Service{}, nil
				},
				connRecorder: connRecorder(),
			},
		)
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
		c := New(
			&mockProvider{
				didDocSvcFunc: func() (*did.Service, error) {
					return &did.Service{}, nil
				},
				connRecorder: connRecorder(),
			},
		)
		expected := "did:example:123"
		req, err := c.CreateRequest(
			WithAttachments(dummyAttachment(t)),
			WithServices(expected))
		require.NoError(t, err)
		require.Len(t, req.Service, 1)
		require.Equal(t, expected, req.Service[0])
	})
	t.Run("WithServices dids and diddoc service blocks", func(t *testing.T) {
		c := New(
			&mockProvider{
				didDocSvcFunc: func() (*did.Service, error) {
					return &did.Service{}, nil
				},
				connRecorder: connRecorder(),
			},
		)
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
		c := New(
			&mockProvider{
				didDocSvcFunc: func() (*did.Service, error) {
					return &did.Service{}, nil
				},
				connRecorder: connRecorder(),
			},
		)
		didRef := "123"
		_, err := c.CreateRequest(
			WithAttachments(dummyAttachment(t)),
			WithServices(didRef))
		require.Error(t, err)
	})
	t.Run("WithServices rejects unsupported service data types", func(t *testing.T) {
		c := New(
			&mockProvider{
				didDocSvcFunc: func() (*did.Service, error) {
					return &did.Service{}, nil
				},
				connRecorder: connRecorder(),
			},
		)
		unsupported := &struct{ foo string }{foo: "bar"}
		_, err := c.CreateRequest(
			WithAttachments(dummyAttachment(t)),
			WithServices(unsupported))
		require.Error(t, err)
	})
	t.Run("wraps error from diddoc service func", func(t *testing.T) {
		expected := errors.New("test")
		c := New(
			&mockProvider{
				didDocSvcFunc: func() (*did.Service, error) {
					return nil, expected
				},
				connRecorder: connRecorder(),
			},
		)
		_, err := c.CreateRequest(WithAttachments(dummyAttachment(t)))
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
	t.Run("wraps error from the connection recorder", func(t *testing.T) {
		expected := errors.New("test")
		c := New(
			&mockProvider{
				didDocSvcFunc: func() (*did.Service, error) {
					return &did.Service{}, nil
				},
				connRecorder: &mockConnRecorder{
					saveInvFunc: func(string, interface{}) error {
						return expected
					},
				},
			},
		)
		_, err := c.CreateRequest(WithAttachments(dummyAttachment(t)))
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
}

type mockProvider struct {
	didDocSvcFunc func() (*did.Service, error)
	connRecorder  ConnectionRecorder
}

func (m *mockProvider) DidDocServiceFunc() func() (*did.Service, error) {
	return m.didDocSvcFunc
}

func (m *mockProvider) ConnRecorder() ConnectionRecorder {
	return m.connRecorder
}

func connRecorder() ConnectionRecorder {
	return &mockConnRecorder{
		saveInvFunc: func(string, interface{}) error {
			return nil
		},
	}
}

type mockConnRecorder struct {
	saveInvFunc func(id string, i interface{}) error
}

func (m *mockConnRecorder) SaveInvitation(id string, i interface{}) error {
	return m.saveInvFunc(id, i)
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
