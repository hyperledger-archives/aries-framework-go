/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofband

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	commonmodel "github.com/hyperledger/aries-framework-go/pkg/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
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
		inv, err := c.CreateInvitation(nil)
		require.NoError(t, err)
		require.NotEmpty(t, inv.ID)
	})
	t.Run("sets correct type", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		inv, err := c.CreateInvitation(nil)
		require.NoError(t, err)
		require.Equal(t, "https://didcomm.org/out-of-band/1.0/invitation", inv.Type)
	})
	t.Run("sets explicit protocols", func(t *testing.T) {
		expected := []string{"protocol1", "protocol2"}
		c, err := New(withTestProvider())
		require.NoError(t, err)
		inv, err := c.CreateInvitation(nil, WithHandshakeProtocols(expected...))
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
			ServiceEndpoint: commonmodel.NewDIDCommV1Endpoint(uuid.New().String()),
			RoutingKeys:     []string{uuid.New().String()},
			Properties:      nil,
		}
		c, err := New(withTestProvider())
		require.NoError(t, err)
		c.didDocSvcFunc = func(_ string, _ []string) (*did.Service, error) {
			return expected, nil
		}
		inv, err := c.CreateInvitation(nil)
		require.NoError(t, err)
		require.Len(t, inv.Services, 1)
		require.Equal(t, expected, inv.Services[0])
	})
	t.Run("includes didDocSvcFunc returning error", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		c.didDocSvcFunc = func(_ string, _ []string) (*did.Service, error) {
			return nil, fmt.Errorf("error didDocServiceFunction")
		}
		_, err = c.CreateInvitation(nil)
		require.EqualError(t, err, "failed to create a new inlined did doc service block : error didDocServiceFunction")
	})
	t.Run("create invitation with invalid service", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)

		_, err = c.CreateInvitation([]interface{}{"invalid"})
		require.EqualError(t, err, "invalid service: invalid DID [invalid]: invalid did: invalid. Make sure it "+
			"conforms to the DID syntax: https://w3c.github.io/did-core/#did-syntax")
	})
	t.Run("WithLabel", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		expected := uuid.New().String()
		inv, err := c.CreateInvitation(nil, WithLabel(expected))
		require.NoError(t, err)
		require.Equal(t, expected, inv.Label)
	})
	t.Run("with router connection", func(t *testing.T) {
		const expectedConn = "conn-xyz"

		c, err := New(withTestProvider())
		require.NoError(t, err)

		c.didDocSvcFunc = func(conn string, accept []string) (*did.Service, error) {
			require.Equal(t, expectedConn, conn)

			var svc *did.Service

			if isDIDCommV2(accept) {
				svc = &did.Service{
					ServiceEndpoint: commonmodel.NewDIDCommV2Endpoint([]commonmodel.DIDCommV2Endpoint{
						{URI: expectedConn, Accept: accept},
					}),
					Type: vdr.DIDCommV2ServiceType,
				}
			} else {
				svc = &did.Service{
					ServiceEndpoint: commonmodel.NewDIDCommV1Endpoint(expectedConn),
					Accept:          accept,
					Type:            vdr.DIDCommServiceType,
				}
			}

			return svc, nil
		}

		inv, err := c.CreateInvitation(nil, WithRouterConnections(expectedConn))
		require.NoError(t, err)
		uri, err := inv.Services[0].(*did.Service).ServiceEndpoint.URI()
		require.NoError(t, err)
		require.Equal(t, expectedConn, uri)
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
			ServiceEndpoint: commonmodel.NewDIDCommV1Endpoint(uuid.New().String()),
			RoutingKeys:     []string{uuid.New().String()},
			Properties:      nil,
		}
		inv, err := c.CreateInvitation([]interface{}{expected})
		require.NoError(t, err)
		require.Len(t, inv.Services, 1)
		require.Equal(t, expected, inv.Services[0])
	})
	t.Run("WithServices dids", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		expected := "did:example:234"
		inv, err := c.CreateInvitation([]interface{}{expected})
		require.NoError(t, err)
		require.Len(t, inv.Services, 1)
		require.Equal(t, expected, inv.Services[0])
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
			ServiceEndpoint: commonmodel.NewDIDCommV1Endpoint(uuid.New().String()),
			RoutingKeys:     []string{uuid.New().String()},
			Properties:      nil,
		}
		inv, err := c.CreateInvitation([]interface{}{svc, didRef})
		require.NoError(t, err)
		require.Len(t, inv.Services, 2)
		require.Contains(t, inv.Services, didRef)
		require.Contains(t, inv.Services, svc)
	})
	t.Run("WithAttachments", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		expected := dummyAttachment(t)
		inv, err := c.CreateInvitation(
			nil,
			WithAttachments(expected),
		)
		require.NoError(t, err)
		require.Contains(t, inv.Requests, expected)
	})
	t.Run("WithAttachments", func(t *testing.T) {
		c, err := New(withTestProvider())
		require.NoError(t, err)
		expected := dummyAttachment(t)
		inv, err := c.CreateInvitation(
			nil,
			WithAttachments(expected),
		)
		require.NoError(t, err)
		require.Contains(t, inv.Requests, expected)
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

func TestAcceptInvitation(t *testing.T) {
	t.Run("returns connection ID", func(t *testing.T) {
		expected := "123456"
		provider := withTestProvider()
		provider.ServiceMap = map[string]interface{}{
			outofband.Name: &stubOOBService{
				acceptInvFunc: func(*outofband.Invitation, outofband.Options) (string, error) {
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
				acceptInvFunc: func(*outofband.Invitation, outofband.Options) (string, error) {
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
	t.Helper()

	return base64Attachment(t, &didcommMsg{
		ID:   uuid.New().String(),
		Type: uuid.New().String(),
	})
}

func base64Attachment(t *testing.T, data interface{}) *decorator.Attachment {
	t.Helper()

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
			mediator.Coordination: &mockroute.MockMediatorSvc{Connections: []string{"xyz"}},
			outofband.Name:        &stubOOBService{},
		},
		ServiceEndpointValue: "endpoint",
	}
}

type stubOOBService struct {
	service.Event
	acceptInvFunc      func(*outofband.Invitation, outofband.Options) (string, error)
	saveInvFunc        func(*outofband.Invitation) error
	actionsFunc        func() ([]outofband.Action, error)
	actionContinueFunc func(string, outofband.Options) error
	actionStopFunc     func(piid string, err error) error
}

func (s *stubOOBService) AcceptInvitation(i *outofband.Invitation, o outofband.Options) (string, error) {
	if s.acceptInvFunc != nil {
		return s.acceptInvFunc(i, o)
	}

	return "", nil
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
