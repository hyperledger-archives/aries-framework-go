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

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
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

func TestCreateRequest(t *testing.T) {
	t.Run("fails with no attachment", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		_, err = c.CreateRequest(nil)
		require.Error(t, err)
	})
	t.Run("sets an id", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		req, err := c.CreateRequest([]*decorator.Attachment{dummyAttachment(t)})
		require.NoError(t, err)
		require.NotEmpty(t, req.ID)
	})
	t.Run("sets correct type", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		req, err := c.CreateRequest([]*decorator.Attachment{dummyAttachment(t)})
		require.NoError(t, err)
		require.Equal(t, "https://didcomm.org/oob-request/1.0/request", req.Type)
	})
	t.Run("WithAttachments", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		first := dummyAttachment(t)
		second := dummyAttachment(t)
		req, err := c.CreateRequest([]*decorator.Attachment{first, second})
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
		req, err := c.CreateRequest([]*decorator.Attachment{dummyAttachment(t)})
		require.NoError(t, err)
		require.Len(t, req.Service, 1)
		require.Equal(t, expected, req.Service[0])
	})
	t.Run("WithLabel", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		expected := uuid.New().String()
		req, err := c.CreateRequest(
			[]*decorator.Attachment{dummyAttachment(t)},
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
			[]*decorator.Attachment{dummyAttachment(t)},
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
			[]*decorator.Attachment{dummyAttachment(t)},
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
			[]*decorator.Attachment{dummyAttachment(t)},
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
			[]*decorator.Attachment{dummyAttachment(t)},
			WithServices(svc, didRef))
		require.NoError(t, err)
		require.Len(t, req.Service, 2)
		require.Contains(t, req.Service, didRef)
		require.Contains(t, req.Service, svc)
	})
	t.Run("WithServices rejects unsupported service data types", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		unsupported := &struct{ foo string }{foo: "bar"}
		_, err = c.CreateRequest(
			[]*decorator.Attachment{dummyAttachment(t)},
			WithServices(unsupported))
		require.Error(t, err)
	})
	t.Run("wraps did service block creation error when KMS fails", func(t *testing.T) {
		expected := errors.New("test")
		provider := withTestProvider()
		provider.KMSValue = &mockkms.KeyManager{CrAndExportPubKeyErr: expected}
		c, err := New(provider)
		require.NoError(t, err)
		_, err = c.CreateRequest([]*decorator.Attachment{dummyAttachment(t)})
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
	t.Run("fails when the routing svc implementation cannot be casted to route.ProtocolService", func(t *testing.T) {
		provider := withTestProvider()
		provider.ServiceMap[mediator.Coordination] = &struct{}{}
		c, err := New(provider)
		require.NoError(t, err)
		_, err = c.CreateRequest([]*decorator.Attachment{dummyAttachment(t)})
		require.Error(t, err)
	})
	t.Run("wraps did service block creation error when route service config fails", func(t *testing.T) {
		expected := errors.New("test")
		provider := withTestProvider()
		routeSvc, ok := provider.ServiceMap[mediator.Coordination].(*mockroute.MockMediatorSvc)
		require.True(t, ok)
		routeSvc.ConfigErr = expected
		c, err := New(provider)
		require.NoError(t, err)
		_, err = c.CreateRequest([]*decorator.Attachment{dummyAttachment(t)})
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
	t.Run("wraps did service block creation error when registering a new key with the routing service fails", func(t *testing.T) { //nolint:lll
		expected := errors.New("test")
		provider := withTestProvider()
		routeSvc, ok := provider.ServiceMap[mediator.Coordination].(*mockroute.MockMediatorSvc)
		require.True(t, ok)
		routeSvc.AddKeyErr = expected
		c, err := New(provider)
		require.NoError(t, err)
		_, err = c.CreateRequest([]*decorator.Attachment{dummyAttachment(t)})
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
}

func TestCreateInvitation(t *testing.T) {
	t.Run("sets an id", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		inv, err := c.CreateInvitation(nil)
		require.NoError(t, err)
		require.NotEmpty(t, inv.ID)
	})
	t.Run("sets correct type", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		inv, err := c.CreateInvitation(nil)
		require.NoError(t, err)
		require.Equal(t, "https://didcomm.org/oob-invitation/1.0/invitation", inv.Type)
	})
	t.Run("sets explicit protocols", func(t *testing.T) {
		expected := []string{"protocol1", "protocol2"}
		c, err := New(withTestProvider())
		require.NoError(t, err)
		inv, err := c.CreateInvitation(expected)
		require.NoError(t, err)
		require.Equal(t, expected, inv.Protocols)
	})
	t.Run("sets default protocols", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		inv, err := c.CreateInvitation(nil)
		require.NoError(t, err)
		require.Equal(t, []string{didexchange.PIURI}, inv.Protocols)
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
		inv, err := c.CreateInvitation(nil)
		require.NoError(t, err)
		require.Len(t, inv.Service, 1)
		require.Equal(t, expected, inv.Service[0])
	})
	t.Run("WithLabel", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		expected := uuid.New().String()
		inv, err := c.CreateInvitation(nil, WithLabel(expected))
		require.NoError(t, err)
		require.Equal(t, expected, inv.Label)
	})
	t.Run("WithGoal", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		expectedGoal := uuid.New().String()
		expectedGoalCode := uuid.New().String()
		inv, err := c.CreateInvitation(nil, WithGoal(expectedGoal, expectedGoalCode))
		require.NoError(t, err)
		require.Equal(t, expectedGoal, inv.Goal)
		require.Equal(t, expectedGoalCode, inv.GoalCode)
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
		inv, err := c.CreateInvitation(nil, WithServices(expected))
		require.NoError(t, err)
		require.Len(t, inv.Service, 1)
		require.Equal(t, expected, inv.Service[0])
	})
	t.Run("WithServices dids", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		expected := "did:example:234"
		inv, err := c.CreateInvitation(nil, WithServices(expected))
		require.NoError(t, err)
		require.Len(t, inv.Service, 1)
		require.Equal(t, expected, inv.Service[0])
	})
	t.Run("WithServices dids and diddoc service blocks", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		didRef := "did:example:234"
		svc := &did.Service{
			ID:              uuid.New().String(),
			Type:            uuid.New().String(),
			Priority:        0,
			RecipientKeys:   []string{uuid.New().String()},
			RoutingKeys:     []string{uuid.New().String()},
			ServiceEndpoint: uuid.New().String(),
			Properties:      nil,
		}
		inv, err := c.CreateInvitation(nil, WithServices(svc, didRef))
		require.NoError(t, err)
		require.Len(t, inv.Service, 2)
		require.Contains(t, inv.Service, didRef)
		require.Contains(t, inv.Service, svc)
	})
}

func TestClient_ActionContinue(t *testing.T) {
	const (
		PIID  = "piid"
		label = "label"
	)

	provider := withTestProvider()
	provider.ServiceMap = map[string]interface{}{
		outofband.Name: &stubOOBService{
			actionContinueFunc: func(piid string, options outofband.Options) error {
				require.Equal(t, PIID, piid)
				require.Equal(t, &EventOptions{Label: label}, options)

				return nil
			},
		},
	}
	c, err := New(provider)
	require.NoError(t, err)
	require.NoError(t, c.ActionContinue(PIID, label))
}

func TestClient_ActionStop(t *testing.T) {
	const PIID = "piid"

	provider := withTestProvider()
	provider.ServiceMap = map[string]interface{}{
		outofband.Name: &stubOOBService{
			actionStopFunc: func(piid string, err error) error {
				require.Equal(t, PIID, piid)
				require.Nil(t, err)

				return nil
			},
		},
	}

	c, err := New(provider)
	require.NoError(t, err)
	require.NoError(t, c.ActionStop(PIID, nil))
}

func TestClient_Actions(t *testing.T) {
	t.Run("Error", func(t *testing.T) {
		provider := withTestProvider()
		provider.ServiceMap = map[string]interface{}{
			outofband.Name: &stubOOBService{
				actionsFunc: func() ([]outofband.Action, error) {
					return nil, errors.New("test")
				},
			},
		}

		c, err := New(provider)
		require.NoError(t, err)
		actions, err := c.Actions()
		require.EqualError(t, err, "test")
		require.Nil(t, actions)
	})
	t.Run("Success", func(t *testing.T) {
		expected := []outofband.Action{{}, {}}
		provider := withTestProvider()
		provider.ServiceMap = map[string]interface{}{
			outofband.Name: &stubOOBService{
				actionsFunc: func() ([]outofband.Action, error) {
					return expected, nil
				},
			},
		}

		c, err := New(provider)
		require.NoError(t, err)
		actions, err := c.Actions()
		require.NoError(t, err)
		require.Equal(t, len(expected), len(actions))
	})
}

func TestAcceptRequest(t *testing.T) {
	t.Run("returns connection ID", func(t *testing.T) {
		expected := "123456"
		provider := withTestProvider()
		provider.ServiceMap = map[string]interface{}{
			outofband.Name: &stubOOBService{
				acceptReqFunc: func(*outofband.Request, string) (string, error) {
					return expected, nil
				},
			},
		}
		c, err := New(provider)
		require.NoError(t, err)
		result, err := c.AcceptRequest(&Request{}, "")
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})
	t.Run("wraps error from outofband service", func(t *testing.T) {
		expected := errors.New("test")
		provider := withTestProvider()
		provider.ServiceMap = map[string]interface{}{
			outofband.Name: &stubOOBService{
				acceptReqFunc: func(*outofband.Request, string) (string, error) {
					return "", expected
				},
			},
		}
		c, err := New(provider)
		require.NoError(t, err)
		_, err = c.AcceptRequest(&Request{}, "")
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
}

func TestAcceptInvitation(t *testing.T) {
	t.Run("returns connection ID", func(t *testing.T) {
		expected := "123456"
		provider := withTestProvider()
		provider.ServiceMap = map[string]interface{}{
			outofband.Name: &stubOOBService{
				acceptInvFunc: func(*outofband.Invitation, string) (string, error) {
					return expected, nil
				},
			},
		}
		c, err := New(provider)
		require.NoError(t, err)
		result, err := c.AcceptInvitation(&Invitation{}, "")
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})
	t.Run("wraps error from outofband service", func(t *testing.T) {
		expected := errors.New("test")
		provider := withTestProvider()
		provider.ServiceMap = map[string]interface{}{
			outofband.Name: &stubOOBService{
				acceptInvFunc: func(*outofband.Invitation, string) (string, error) {
					return "", expected
				},
			},
		}
		c, err := New(provider)
		require.NoError(t, err)
		_, err = c.AcceptInvitation(&Invitation{}, "")
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
	mockKey, err := mockkms.CreateMockED25519KeyHandle()
	if err != nil {
		return nil
	}

	return &mockprovider.Provider{
		ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
		StorageProviderValue:              mockstore.NewMockStoreProvider(),
		KMSValue:                          &mockkms.KeyManager{CreateKeyValue: mockKey},
		ServiceMap: map[string]interface{}{
			mediator.Coordination: &mockroute.MockMediatorSvc{},
			outofband.Name:        &stubOOBService{},
		},
		ServiceEndpointValue: "endpoint",
	}
}

type stubOOBService struct {
	service.Event
	acceptReqFunc      func(*outofband.Request, string) (string, error)
	acceptInvFunc      func(*outofband.Invitation, string) (string, error)
	saveReqFunc        func(*outofband.Request) error
	saveInvFunc        func(*outofband.Invitation) error
	actionsFunc        func() ([]outofband.Action, error)
	actionContinueFunc func(string, outofband.Options) error
	actionStopFunc     func(piid string, err error) error
}

func (s *stubOOBService) AcceptRequest(request *outofband.Request, myLabel string) (string, error) {
	if s.acceptReqFunc != nil {
		return s.acceptReqFunc(request, myLabel)
	}

	return "", nil
}

func (s *stubOOBService) AcceptInvitation(i *outofband.Invitation, myLabel string) (string, error) {
	if s.acceptInvFunc != nil {
		return s.acceptInvFunc(i, myLabel)
	}

	return "", nil
}

func (s *stubOOBService) SaveRequest(request *outofband.Request) error {
	if s.saveReqFunc != nil {
		return s.saveReqFunc(request)
	}

	return nil
}

func (s *stubOOBService) SaveInvitation(i *outofband.Invitation) error {
	if s.saveInvFunc != nil {
		return s.saveInvFunc(i)
	}

	return nil
}

func (s *stubOOBService) Actions() ([]outofband.Action, error) {
	if s.actionsFunc != nil {
		return s.actionsFunc()
	}

	return nil, nil
}

func (s *stubOOBService) ActionContinue(piid string, opts outofband.Options) error {
	if s.actionContinueFunc != nil {
		return s.actionContinueFunc(piid, opts)
	}

	return nil
}

func (s *stubOOBService) ActionStop(piid string, err error) error {
	if s.actionStopFunc != nil {
		return s.actionStopFunc(piid, err)
	}

	return nil
}
