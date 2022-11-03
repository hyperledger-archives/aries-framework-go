/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofband

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	commonmodel "github.com/hyperledger/aries-framework-go/pkg/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	"github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol"
	mockdidexchange "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/didexchange"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	myDID    = "did:example:mine"
	theirDID = "did:example:theirs"
)

func TestNew(t *testing.T) {
	t.Run("returns the service", func(t *testing.T) {
		s, err := New(testProvider())
		require.NoError(t, err)
		require.NotNil(t, s)
	})
	t.Run("fails if no didexchange service is registered", func(t *testing.T) {
		provider := testProvider()
		provider.ServiceErr = api.ErrSvcNotFound
		_, err := New(provider)
		require.Error(t, err)
	})
	t.Run("fails if the didexchange service cannot be cast to an inboundhandler", func(t *testing.T) {
		provider := testProvider()
		provider.ServiceMap[didexchange.DIDExchange] = &struct{}{}
		_, err := New(provider)
		require.Error(t, err)
	})
	t.Run("wraps error thrown from protocol state store when it cannot be opened", func(t *testing.T) {
		expected := errors.New("test")
		provider := testProvider()
		provider.ProtocolStateStoreProvider = &mockstore.MockStoreProvider{
			ErrOpenStoreHandle: expected,
		}
		_, err := New(provider)
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
	t.Run("wraps error thrown from persistent store when it cannot be opened", func(t *testing.T) {
		expected := errors.New("test")
		provider := testProvider()
		provider.StoreProvider = &mockstore.MockStoreProvider{
			ErrOpenStoreHandle: expected,
		}
		_, err := New(provider)
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
	t.Run("fails if the didexchange service cannot be cast to service.Event", func(t *testing.T) {
		provider := testProvider()
		provider.ServiceMap[didexchange.DIDExchange] = &struct{ service.InboundHandler }{}
		_, err := New(provider)
		require.Error(t, err)
	})
	t.Run("wraps error thrown when attempting to register to listen for didexchange events", func(t *testing.T) {
		expected := errors.New("test")
		provider := testProvider()
		provider.ServiceMap = map[string]interface{}{
			didexchange.DIDExchange: &mockdidexchange.MockDIDExchangeSvc{
				RegisterMsgEventErr: expected,
			},
		}
		_, err := New(provider)
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
}

func TestService_Initialize(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		prov := testProvider()
		svc := Service{}

		err := svc.Initialize(prov)
		require.NoError(t, err)

		// second init is no-op
		err = svc.Initialize(prov)
		require.NoError(t, err)
	})

	t.Run("failure, not given a valid provider", func(t *testing.T) {
		svc := Service{}

		err := svc.Initialize("not a provider")
		require.Error(t, err)
		require.Contains(t, err.Error(), "expected provider of type")
	})
}

func TestName(t *testing.T) {
	s, err := New(testProvider())
	require.NoError(t, err)
	require.Equal(t, s.Name(), "out-of-band")
}

func TestAccept(t *testing.T) {
	t.Run("accepts out-of-band invitation messages", func(t *testing.T) {
		s, err := New(testProvider())
		require.NoError(t, err)
		require.True(t, s.Accept("https://didcomm.org/out-of-band/1.0/invitation"))
	})
	t.Run("rejects unsupported messages", func(t *testing.T) {
		s, err := New(testProvider())
		require.NoError(t, err)
		require.False(t, s.Accept("unsupported"))
	})
}

func TestHandleInbound(t *testing.T) {
	t.Run("accepts out-of-band invitation messages", func(t *testing.T) {
		s := newAutoService(t, testProvider())
		_, err := s.HandleInbound(service.NewDIDCommMsgMap(newInvitation()), service.NewDIDCommContext(myDID, theirDID, nil))
		require.NoError(t, err)
	})

	t.Run("accepts out-of-band invitation messages with service as map[string]interface{} and serviceEndpoint as "+
		"string (DIDCommV1)", func(t *testing.T) {
		s := newAutoService(t, testProvider())
		customServiceMap := map[string]interface{}{
			"recipientKeys":   []string{"did:key:123"},
			"serviceEndpoint": "http://user.agent.aries.js.example.com:10081",
			"type":            "did-communication",
		}
		_, err := s.HandleInbound(service.NewDIDCommMsgMap(newInvitationWithService(customServiceMap)),
			service.NewDIDCommContext(myDID, theirDID, nil))
		require.NoError(t, err)
	})

	t.Run("accepts out-of-band invitation messages with service as map[string]interface{} and serviceEndpoint as "+
		"list (DIDCommV2)", func(t *testing.T) {
		s := newAutoService(t, testProvider())
		customServiceMap := map[string]interface{}{
			"recipientKeys": []string{"did:key:123"},
			"serviceEndpoint": []interface{}{
				map[string]interface{}{
					"accept": []interface{}{
						"didcomm/v2", "didcomm/aip2;env=rfc19", "didcomm/aip2;env=rfc587",
					},
					"uri": "https://alice.aries.example.com:8081",
				},
			},
			"type": "DIDCommMessaging",
		}
		_, err := s.HandleInbound(service.NewDIDCommMsgMap(newInvitationWithService(customServiceMap)),
			service.NewDIDCommContext(myDID, theirDID, nil))
		require.NoError(t, err)
	})

	t.Run("rejects unsupported message types", func(t *testing.T) {
		s, err := New(testProvider())
		require.NoError(t, err)
		req := newInvitation()
		req.Type = "invalid"
		_, err = s.HandleInbound(service.NewDIDCommMsgMap(req), service.NewDIDCommContext(myDID, theirDID, nil))
		require.Error(t, err)
	})
	t.Run("fires off an action event", func(t *testing.T) {
		expected := service.NewDIDCommMsgMap(newInvitation())
		s, err := New(testProvider())
		require.NoError(t, err)
		events := make(chan service.DIDCommAction)
		err = s.RegisterActionEvent(events)
		require.NoError(t, err)
		_, err = s.HandleInbound(expected, service.NewDIDCommContext(myDID, theirDID, nil))
		require.NoError(t, err)
		select {
		case e := <-events:
			require.Equal(t, Name, e.ProtocolName)
			require.Equal(t, expected, e.Message)
			require.Nil(t, e.Properties)
		case <-time.After(1 * time.Second):
			t.Error("timeout waiting for action event")
		}
	})
	t.Run("ThreadID not found", func(t *testing.T) {
		expected := service.NewDIDCommMsgMap(&HandshakeReuseAccepted{
			Type: HandshakeReuseAcceptedMsgType,
		})
		s, err := New(testProvider())
		require.NoError(t, err)
		events := make(chan service.DIDCommAction)
		err = s.RegisterActionEvent(events)
		require.NoError(t, err)
		_, err = s.HandleInbound(expected, service.NewDIDCommContext(myDID, theirDID, nil))
		require.Error(t, err)
		require.Contains(t, err.Error(), "threadID not found")
	})
	t.Run("Load context (error)", func(t *testing.T) {
		expected := service.NewDIDCommMsgMap(newInvitation())
		s := &Service{
			transientStore: &mockstore.MockStore{
				Store:  make(map[string]mockstore.DBEntry),
				ErrPut: fmt.Errorf("db error"),
			},
		}
		events := make(chan service.DIDCommAction)
		err := s.RegisterActionEvent(events)
		require.NoError(t, err)
		_, err = s.HandleInbound(expected, service.NewDIDCommContext(myDID, theirDID, nil))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to load current context")
	})
	t.Run("sends pre-state msg event", func(t *testing.T) {
		expected := service.NewDIDCommMsgMap(&HandshakeReuseAccepted{
			ID:   uuid.New().String(),
			Type: HandshakeReuseAcceptedMsgType,
		})
		provider := testProvider()
		provider.ProtocolStateStoreProvider = &mockstore.MockStoreProvider{
			Store: &mockstore.MockStore{
				Store: map[string]mockstore.DBEntry{
					fmt.Sprintf(contextKey, expected.ID()): {
						Value: marshal(t, &context{
							CurrentStateName: StateNameAwaitResponse,
							Inbound:          true,
							Invitation:       newInvitation(),
							Action: Action{
								Msg: expected,
							},
						}),
					},
				},
			},
		}
		s, err := New(provider)
		require.NoError(t, err)
		stateMsgs := make(chan service.StateMsg)
		err = s.RegisterMsgEvent(stateMsgs)
		require.NoError(t, err)
		err = s.RegisterActionEvent(make(chan service.DIDCommAction))
		require.NoError(t, err)
		_, err = s.HandleInbound(expected, service.NewDIDCommContext(myDID, theirDID, nil))
		require.NoError(t, err)

		done := false

		for !done {
			select {
			case result := <-stateMsgs:
				if result.Type != service.PreState || result.StateID != StateNameAwaitResponse {
					continue
				}

				done = true

				require.Equal(t, Name, result.ProtocolName)
				require.Equal(t, expected, result.Msg)
				props, ok := result.Properties.(*eventProps)
				require.True(t, ok)
				require.Empty(t, props.ConnectionID())
				require.Nil(t, props.Error())
			case <-time.After(time.Second):
				t.Error("timeout waiting for action event")
			}
		}
	})
	t.Run("fails if no listeners have been registered for action events", func(t *testing.T) {
		s, err := New(testProvider())
		require.NoError(t, err)
		_, err = s.HandleInbound(service.NewDIDCommMsgMap(newInvitation()), service.NewDIDCommContext(myDID, theirDID, nil))
		require.Error(t, err)
	})
}

func TestService_ActionContinue(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		msg := service.NewDIDCommMsgMap(&HandshakeReuse{
			ID:   uuid.New().String(),
			Type: HandshakeReuseMsgType,
		})
		provider := testProvider()
		connID := uuid.New().String()

		// Note: copied from store/connection/connection_lookup.go
		mockDIDTagFunc := func(dids ...string) string {
			for i, v := range dids {
				dids[i] = strings.ReplaceAll(v, ":", "$")
			}

			return strings.Join(dids, "|")
		}

		provider.StoreProvider = &mockstore.MockStoreProvider{
			Store: &mockstore.MockStore{
				Store: map[string]mockstore.DBEntry{
					fmt.Sprintf("didconn_%s_%s", myDID, theirDID): {
						Value: []byte(connID),
					},
					fmt.Sprintf("conn_%s", connID): {
						Value: marshal(t, &connection.Record{
							ConnectionID: connID,
							State:        "completed",
						}),
						Tags: []storage.Tag{
							{
								Name:  "bothDIDs",
								Value: mockDIDTagFunc(myDID, theirDID),
							},
						},
					},
				},
			},
		}
		s, err := New(provider)
		require.NoError(t, err)

		states := make(chan service.StateMsg, 50)
		actions := make(chan service.DIDCommAction)

		require.NoError(t, err, s.RegisterMsgEvent(states))
		require.NoError(t, s.RegisterActionEvent(actions))
		_, err = s.HandleInbound(msg, service.NewDIDCommContext(myDID, theirDID, nil))
		require.NoError(t, err)

		var remainingActions []Action

		select {
		case <-actions:
			remainingActions, err = s.Actions()
			require.NoError(t, err)
			require.Equal(t, 1, len(remainingActions))
			require.NoError(t, s.ActionContinue(remainingActions[0].PIID, &userOptions{}))
		case <-time.After(time.Second):
			t.Error("timeout")
		}

		done := false

		for !done {
			select {
			case s := <-states:
				if s.Type == service.PostState && s.StateID == StateNameDone {
					done = true
				}
			case <-time.After(5 * time.Second):
				require.Fail(t, "timeout waiting for state done")
			}
		}

		remainingActions, err = s.Actions()
		require.NoError(t, err)
		require.Equal(t, 0, len(remainingActions))
	})
	t.Run("Error", func(t *testing.T) {
		require.EqualError(t, (&Service{
			transientStore: &mockstore.MockStore{
				Store:  make(map[string]mockstore.DBEntry),
				ErrGet: fmt.Errorf("db error"),
			},
		}).ActionContinue("piid", nil), "load context: transientStore get: db error")
	})
}

func TestService_ActionStop(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		msg := service.NewDIDCommMsgMap(newInvitation())
		s, err := New(testProvider())
		require.NoError(t, err)

		actions := make(chan service.DIDCommAction)

		require.NoError(t, s.RegisterActionEvent(actions))
		s.callbackChannel = make(chan *callback, 2)
		_, err = s.HandleInbound(msg, service.NewDIDCommContext(myDID, theirDID, nil))
		require.NoError(t, err)

		var remainingActions []Action

		select {
		case <-actions:
			remainingActions, err = s.Actions()
			require.NoError(t, err)
			require.Equal(t, 1, len(remainingActions))
			require.NoError(t, s.ActionStop(remainingActions[0].PIID, nil))
		case <-time.After(1 * time.Second):
			t.Error("timeout")
		}

		remainingActions, err = s.Actions()
		require.NoError(t, err)
		require.Equal(t, 0, len(remainingActions))
	})

	t.Run("Error", func(t *testing.T) {
		require.EqualError(t, (&Service{
			transientStore: &mockstore.MockStore{
				Store:  make(map[string]mockstore.DBEntry),
				ErrGet: fmt.Errorf("db error"),
			},
		}).ActionStop("piid", nil), "get context: transientStore get: db error")
	})
}

func TestServiceStop(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		msg := service.NewDIDCommMsgMap(newInvitation())
		s, err := New(testProvider())
		require.NoError(t, err)

		actions := make(chan service.DIDCommAction)

		require.NoError(t, s.RegisterActionEvent(actions))
		s.callbackChannel = make(chan *callback, 2)
		_, err = s.HandleInbound(msg, service.NewDIDCommContext(myDID, theirDID, nil))
		require.NoError(t, err)

		select {
		case action := <-actions:
			action.Stop(nil)
		case <-time.After(1 * time.Second):
			t.Error("timeout")
		}

		remainingActions, err := s.Actions()
		require.NoError(t, err)
		require.Equal(t, 0, len(remainingActions))
	})
}

func TestServiceContinue(t *testing.T) {
	t.Run("enqueues callback", func(t *testing.T) {
		msg := service.NewDIDCommMsgMap(newInvitation())
		s, err := New(testProvider())
		require.NoError(t, err)

		actions := make(chan service.DIDCommAction)

		require.NoError(t, s.RegisterActionEvent(actions))
		s.callbackChannel = make(chan *callback, 2)
		_, err = s.HandleInbound(msg, service.NewDIDCommContext(myDID, theirDID, nil))
		require.NoError(t, err)

		select {
		case action := <-actions:
			action.Continue(nil)
		case <-time.After(1 * time.Second):
			t.Error("timeout")
		}

		select {
		case c := <-s.callbackChannel:
			require.Equal(t, msg, c.msg)
			require.Equal(t, myDID, c.myDID)
			require.Equal(t, theirDID, c.theirDID)
		case <-time.After(1 * time.Second):
			t.Error("timeout")
		}
	})
}

func TestHandleRequestCallback(t *testing.T) {
	t.Run("invokes the didexchange service", func(t *testing.T) {
		invoked := make(chan struct{}, 2)
		c := newCallback()
		provider := testProvider()
		provider.ServiceMap = map[string]interface{}{
			didexchange.DIDExchange: &mockdidexchange.MockDIDExchangeSvc{
				RespondToFunc: func(*didexchange.OOBInvitation, []string) (string, error) {
					invoked <- struct{}{}
					return "", nil
				},
			},
		}

		s := newAutoService(t, provider)

		_, err := s.handleInvitationCallback(c)
		require.NoError(t, err)
		select {
		case <-invoked:
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})
	t.Run("passes a didexchange.OOBInvitation to the didexchange service", func(t *testing.T) {
		provider := testProvider()
		provider.ServiceMap = map[string]interface{}{
			didexchange.DIDExchange: &mockdidexchange.MockDIDExchangeSvc{
				RespondToFunc: func(i *didexchange.OOBInvitation, _ []string) (string, error) {
					require.NotNil(t, i)
					return "", nil
				},
			},
		}
		s := newAutoService(t, provider)
		_, err := s.handleInvitationCallback(newCallback())
		require.NoError(t, err)
	})
	t.Run("wraps error thrown when decoding the message", func(t *testing.T) {
		expected := errors.New("test")
		s := newAutoService(t, testProvider())
		_, err := s.handleInvitationCallback(&callback{
			msg: &testDIDCommMsg{errDecode: expected},
			ctx: &context{},
		})
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
	t.Run("wraps error returned by the didexchange service", func(t *testing.T) {
		expected := errors.New("test")
		provider := testProvider()
		provider.ServiceMap = map[string]interface{}{
			didexchange.DIDExchange: &mockdidexchange.MockDIDExchangeSvc{
				RespondToFunc: func(_ *didexchange.OOBInvitation, _ []string) (string, error) {
					return "", expected
				},
			},
		}
		s := newAutoService(t, provider)
		_, err := s.handleInvitationCallback(newCallback())
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
	t.Run("wraps error returned by the protocol state store", func(t *testing.T) {
		expected := errors.New("test")
		provider := testProvider()
		provider.ProtocolStateStoreProvider = &mockstore.MockStoreProvider{
			Store: &mockstore.MockStore{
				ErrPut: expected,
			},
		}
		s := newAutoService(t, provider)
		_, err := s.handleInvitationCallback(newCallback())
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
}

func TestHandleDIDEvent(t *testing.T) {
	t.Run("invokes inbound msg handler", func(t *testing.T) {
		invoked := make(chan struct{}, 2)
		connID := uuid.New().String()
		pthid := uuid.New().String()

		provider := testProvider()
		provider.InboundDIDCommMsgHandlerFunc = func() service.InboundHandler {
			return &inboundMsgHandler{handleFunc: func(service.DIDCommMsg, service.DIDCommContext) (string, error) {
				invoked <- struct{}{}
				return "", nil
			}}
		}

		// setup connection state
		r, err := connection.NewRecorder(provider)
		require.NoError(t, err)
		err = r.SaveConnectionRecord(&connection.Record{
			ConnectionID:   connID,
			MyDID:          myDID,
			TheirDID:       theirDID,
			ParentThreadID: pthid,
		})
		require.NoError(t, err)

		s := newAutoService(t, provider,
			withState(t, &attachmentHandlingState{
				ID:           pthid,
				ConnectionID: connID,
				Invitation:   newInvitation(),
				Done:         false,
			},
			))

		err = s.handleDIDEvent(service.StateMsg{
			ProtocolName: didexchange.DIDExchange,
			Type:         service.PostState,
			Msg:          service.NewDIDCommMsgMap(newAck(pthid)),
			StateID:      didexchange.StateIDCompleted,
			Properties:   &mockdidexchange.MockEventProperties{ConnID: connID},
		})
		require.NoError(t, err)

		select {
		case <-invoked:
		case <-time.After(1 * time.Second):
			t.Error("timeout")
		}
	})
	t.Run("wraps error returned by the protocol state store", func(t *testing.T) {
		expected := errors.New("test")
		const connID = "123"
		provider := testProvider()
		provider.ProtocolStateStoreProvider = &mockstore.MockStoreProvider{
			Store: &mockstore.MockStore{
				Store:  make(map[string]mockstore.DBEntry),
				ErrGet: expected,
			},
		}
		r, err := connection.NewRecorder(provider)
		require.NoError(t, err)
		err = r.SaveConnectionRecord(&connection.Record{
			ConnectionID: connID,
		})
		require.NoError(t, err)
		s := newAutoService(t, provider)
		err = s.handleDIDEvent(service.StateMsg{
			ProtocolName: didexchange.DIDExchange,
			Type:         service.PostState,
			Msg:          service.NewDIDCommMsgMap(newAck()),
			StateID:      didexchange.StateIDCompleted,
			Properties:   &mockdidexchange.MockEventProperties{},
		})
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
	t.Run("wraps error returned by the persistent store", func(t *testing.T) {
		expected := errors.New("test")
		pthid := uuid.New().String()

		provider := testProvider()
		provider.StoreProvider = &mockstore.MockStoreProvider{
			Store: &mockstore.MockStore{
				ErrGet: expected,
			},
		}
		s := newAutoService(t, provider,
			withState(t, &attachmentHandlingState{
				ID:           pthid,
				ConnectionID: uuid.New().String(),
				Invitation:   newInvitation(),
				Done:         false,
			},
			))
		err := s.handleDIDEvent(service.StateMsg{
			ProtocolName: didexchange.DIDExchange,
			Type:         service.PostState,
			Msg:          service.NewDIDCommMsgMap(newAck(pthid)),
			StateID:      didexchange.StateIDCompleted,
			Properties:   &mockdidexchange.MockEventProperties{},
		})
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
	t.Run("wraps error thrown by the dispatcher", func(t *testing.T) {
		expected := errors.New("test")
		pthid := uuid.New().String()
		connID := uuid.New().String()

		provider := testProvider()
		provider.InboundDIDCommMsgHandlerFunc = func() service.InboundHandler {
			return &inboundMsgHandler{
				handleFunc: func(service.DIDCommMsg, service.DIDCommContext) (string, error) {
					return "", expected
				},
			}
		}

		// setup connection state
		r, err := connection.NewRecorder(provider)
		require.NoError(t, err)
		err = r.SaveConnectionRecord(&connection.Record{
			ConnectionID:   connID,
			MyDID:          myDID,
			TheirDID:       theirDID,
			ParentThreadID: pthid,
		})
		require.NoError(t, err)

		s := newAutoService(t, provider,
			withState(t, &attachmentHandlingState{
				ID:           pthid,
				ConnectionID: connID,
				Invitation:   newInvitation(),
				Done:         false,
			},
			))
		err = s.handleDIDEvent(service.StateMsg{
			ProtocolName: didexchange.DIDExchange,
			Type:         service.PostState,
			Msg:          service.NewDIDCommMsgMap(newAck(pthid)),
			StateID:      didexchange.StateIDCompleted,
			Properties:   &mockdidexchange.MockEventProperties{ConnID: connID},
		})
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
	t.Run("wraps error from store when saving state", func(t *testing.T) {
		expected := errors.New("test")
		pthid := uuid.New().String()
		connID := uuid.New().String()

		protocolStateStoreProvider := mockstore.NewMockStoreProvider()
		provider := &protocol.MockProvider{
			StoreProvider:              mockstore.NewMockStoreProvider(),
			ProtocolStateStoreProvider: protocolStateStoreProvider,
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: &mockdidexchange.MockDIDExchangeSvc{},
			},
		}
		provider.InboundMsgHandler = func(envelope *transport.Envelope) error {
			return nil
		}

		// setup connection state
		r, err := connection.NewRecorder(provider)
		require.NoError(t, err)
		err = r.SaveConnectionRecord(&connection.Record{
			ConnectionID:   connID,
			MyDID:          myDID,
			TheirDID:       theirDID,
			ParentThreadID: pthid,
		})
		require.NoError(t, err)

		s := newAutoService(t, provider,
			withState(t, &attachmentHandlingState{
				ID:           pthid,
				ConnectionID: connID,
				Invitation:   newInvitation(),
				Done:         false,
			},
			))

		s.transientStore = &mockstore.MockStore{
			Store:  protocolStateStoreProvider.Store.Store,
			ErrPut: expected,
		}

		err = s.handleDIDEvent(service.StateMsg{
			ProtocolName: didexchange.DIDExchange,
			Type:         service.PostState,
			Msg:          service.NewDIDCommMsgMap(newAck(pthid)),
			StateID:      didexchange.StateIDCompleted,
			Properties:   &mockdidexchange.MockEventProperties{ConnID: connID},
		})
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
	t.Run("ignores non-poststate did events", func(t *testing.T) {
		s := newAutoService(t, testProvider())
		err := s.handleDIDEvent(service.StateMsg{
			ProtocolName: didexchange.DIDExchange,
			Type:         service.PreState,
		})
		require.Error(t, err)
		require.True(t, errors.Is(err, errIgnoredDidEvent))
	})
	t.Run("ignores msgs that are not didexchange acks", func(t *testing.T) {
		s := newAutoService(t, testProvider())
		err := s.handleDIDEvent(service.StateMsg{
			ProtocolName: didexchange.DIDExchange,
			Type:         service.PostState,
			Msg:          service.NewDIDCommMsgMap(&didexchange.Request{}),
		})
		require.Error(t, err)
		require.True(t, errors.Is(err, errIgnoredDidEvent))
	})
	t.Run("ignores acks with no parent thread id", func(t *testing.T) {
		s := newAutoService(t, testProvider())
		err := s.handleDIDEvent(service.StateMsg{
			ProtocolName: didexchange.DIDExchange,
			Type:         service.PostState,
			Msg: service.NewDIDCommMsgMap(&model.Ack{
				Type:   didexchange.AckMsgType,
				ID:     uuid.New().String(),
				Status: "great",
				Thread: &decorator.Thread{
					ID: uuid.New().String(),
				},
			}),
		})
		require.Error(t, err)
		require.True(t, errors.Is(err, errIgnoredDidEvent))
	})
	t.Run("ignores did event if no more requests are to be dispatched", func(t *testing.T) {
		pthid := uuid.New().String()
		connID := uuid.New().String()

		s := newAutoService(t, testProvider(),
			withState(t, &attachmentHandlingState{
				ID:           pthid,
				ConnectionID: connID,
				Invitation:   newInvitation(),
				Done:         false,
			}),
		)
		s.chooseAttachmentFunc = func(*attachmentHandlingState) (*decorator.Attachment, error) {
			return nil, nil
		}
		err := s.handleDIDEvent(service.StateMsg{
			ProtocolName: didexchange.DIDExchange,
			Type:         service.PostState,
			Msg:          service.NewDIDCommMsgMap(newAck(pthid)),
		})
		require.Error(t, err)
		require.True(t, errors.Is(err, errIgnoredDidEvent))
	})
	t.Run("wraps error thrown while extracting didcomm msg bytes from request", func(t *testing.T) {
		expected := errors.New("test")
		pthid := uuid.New().String()
		connID := uuid.New().String()

		provider := testProvider()

		// setup connection state
		r, err := connection.NewRecorder(provider)
		require.NoError(t, err)
		err = r.SaveConnectionRecord(&connection.Record{
			ConnectionID:   connID,
			MyDID:          myDID,
			TheirDID:       theirDID,
			ParentThreadID: pthid,
		})

		require.NoError(t, err)
		s := newAutoService(t, provider,
			withState(t, &attachmentHandlingState{
				ID:           pthid,
				ConnectionID: connID,
				Invitation:   newInvitation(),
				Done:         false,
			}),
		)
		s.extractDIDCommMsgBytesFunc = func(*decorator.Attachment) ([]byte, error) {
			return nil, expected
		}
		err = s.handleDIDEvent(service.StateMsg{
			ProtocolName: didexchange.DIDExchange,
			Type:         service.PostState,
			Msg:          service.NewDIDCommMsgMap(newAck(pthid)),
			StateID:      didexchange.StateIDCompleted,
			Properties:   &mockdidexchange.MockEventProperties{ConnID: connID},
		})
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
}

func TestListener(t *testing.T) {
	t.Run("invokes handleReqFunc", func(t *testing.T) {
		invoked := make(chan struct{})
		callbacks := make(chan *callback)
		handleReqFunc := func(*callback) (string, error) {
			invoked <- struct{}{}
			return "", nil
		}
		go listener(callbacks, nil, handleReqFunc, nil)()

		callbacks <- &callback{
			msg: service.NewDIDCommMsgMap(newInvitation()),
		}

		select {
		case <-invoked:
		case <-time.After(1 * time.Second):
			t.Error("timeout")
		}
	})
	t.Run("invokes handleDidEventFunc", func(t *testing.T) {
		invoked := make(chan struct{})
		didEvents := make(chan service.StateMsg)
		handleDidEventFunc := func(msg service.StateMsg) error {
			invoked <- struct{}{}
			return nil
		}
		go listener(nil, didEvents, nil, handleDidEventFunc)()
		didEvents <- service.StateMsg{}

		select {
		case <-invoked:
		case <-time.After(1 * time.Second):
			t.Error("timeout")
		}
	})
}

func TestAcceptInvitation(t *testing.T) {
	t.Run("returns connectionID", func(t *testing.T) {
		expected := "123456"
		provider := testProvider()
		provider.ServiceMap = map[string]interface{}{
			didexchange.DIDExchange: &mockdidexchange.MockDIDExchangeSvc{
				RespondToFunc: func(_ *didexchange.OOBInvitation, _ []string) (string, error) {
					return expected, nil
				},
			},
		}
		s := newAutoService(t, provider)
		result, err := s.AcceptInvitation(newInvitation(), &userOptions{})
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})
	t.Run("wraps error from didexchange service", func(t *testing.T) {
		expected := errors.New("test")
		provider := testProvider()
		provider.ServiceMap = map[string]interface{}{
			didexchange.DIDExchange: &mockdidexchange.MockDIDExchangeSvc{
				RespondToFunc: func(_ *didexchange.OOBInvitation, _ []string) (string, error) {
					return "", expected
				},
			},
		}
		s := newAutoService(t, provider)
		_, err := s.AcceptInvitation(newInvitation(), &userOptions{})
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
	t.Run("error if invitation has invalid accept values", func(t *testing.T) {
		provider := testProvider()
		s := newAutoService(t, provider)
		inv := newInvitation()
		inv.Accept = []string{"INVALID"}
		_, err := s.AcceptInvitation(inv, &userOptions{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "no acceptable media type profile found in invitation")
	})
}

func TestSaveInvitation(t *testing.T) {
	t.Run("saves invitation", func(t *testing.T) {
		savedInStore := false
		savedInDidSvc := false
		expected := newInvitation()
		provider := testProvider()
		provider.StoreProvider = mockstore.NewCustomMockStoreProvider(&stubStore{
			putFunc: func(k string, v []byte) error {
				savedInStore = true
				result := &Invitation{}
				err := json.Unmarshal(v, result)
				require.NoError(t, err)
				require.Equal(t, expected, result)
				return nil
			},
		})
		provider.ServiceMap[didexchange.DIDExchange] = &mockdidexchange.MockDIDExchangeSvc{
			SaveFunc: func(i *didexchange.OOBInvitation) error {
				savedInDidSvc = true
				require.NotNil(t, i)
				require.NotEmpty(t, i.ID)
				require.Equal(t, expected.ID, i.ThreadID)
				require.Equal(t, expected.Label, i.TheirLabel)
				require.Equal(t, expected.Services[0], i.Target)
				return nil
			},
		}
		s := newAutoService(t, provider)
		err := s.SaveInvitation(expected)
		require.NoError(t, err)
		require.True(t, savedInStore)
		require.True(t, savedInDidSvc)
	})
	t.Run("wraps error from store", func(t *testing.T) {
		expected := errors.New("test")
		provider := testProvider()
		provider.StoreProvider = &mockstore.MockStoreProvider{
			Store: &mockstore.MockStore{
				ErrPut: expected,
			},
		}
		s := newAutoService(t, provider)
		err := s.SaveInvitation(newInvitation())
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
	t.Run("fails when invitation does not have services", func(t *testing.T) {
		inv := newInvitation()
		inv.Services = []interface{}{}
		s := newAutoService(t, testProvider())
		err := s.SaveInvitation(inv)
		require.Error(t, err)
	})
	t.Run("wraps error from didexchange service", func(t *testing.T) {
		expected := errors.New("test")
		provider := testProvider()
		provider.ServiceMap[didexchange.DIDExchange] = &mockdidexchange.MockDIDExchangeSvc{
			SaveFunc: func(*didexchange.OOBInvitation) error {
				return expected
			},
		}
		s := newAutoService(t, provider)
		err := s.SaveInvitation(newInvitation())
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
}

func TestChooseTarget(t *testing.T) {
	t.Run("chooses a string", func(t *testing.T) {
		expected := "abc123"
		result, err := chooseTarget([]interface{}{expected})
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})
	t.Run("chooses a did service entry", func(t *testing.T) {
		expected := &did.Service{
			ID:              uuid.New().String(),
			Type:            "did-communication",
			Priority:        0,
			RecipientKeys:   []string{"my ver key"},
			ServiceEndpoint: commonmodel.NewDIDCommV1Endpoint("my service endpoint"),
			RoutingKeys:     []string{"my routing key"},
		}
		result, err := chooseTarget([]interface{}{expected})
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})
	t.Run("chooses a map-type service", func(t *testing.T) {
		expected := map[string]interface{}{
			"id":              uuid.New().String(),
			"type":            "did-communication",
			"priority":        0,
			"recipientKeys":   []string{"my ver key"},
			"serviceEndpoint": commonmodel.NewDIDCommV1Endpoint("my service endpoint"),
			"RoutingKeys":     []string{"my routing key"},
		}
		svc, err := chooseTarget([]interface{}{expected})
		require.NoError(t, err)
		result, ok := svc.(*did.Service)
		require.True(t, ok)
		require.Equal(t, expected["id"], result.ID)
		require.Equal(t, expected["type"], result.Type)
		require.Equal(t, expected["priority"], result.Priority)
		require.Equal(t, expected["recipientKeys"], result.RecipientKeys)
		require.Equal(t, expected["serviceEndpoint"], result.ServiceEndpoint)
	})
	t.Run("fails if not services are specified", func(t *testing.T) {
		_, err := chooseTarget([]interface{}{})
		require.Error(t, err)
	})
}

func testProvider() *protocol.MockProvider {
	return &protocol.MockProvider{
		StoreProvider:              mockstore.NewMockStoreProvider(),
		ProtocolStateStoreProvider: mockstore.NewMockStoreProvider(),
		ServiceMap: map[string]interface{}{
			didexchange.DIDExchange: &mockdidexchange.MockDIDExchangeSvc{},
		},
	}
}

func newInvitation() *Invitation {
	return newInvitationWithService("did:example:1235")
}

func newInvitationWithService(svc interface{}) *Invitation {
	return &Invitation{
		ID:        uuid.New().String(),
		Type:      InvitationMsgType,
		Label:     "test",
		Goal:      "test",
		GoalCode:  "test",
		Services:  []interface{}{svc},
		Protocols: []string{didexchange.PIURI},
		Requests: []*decorator.Attachment{
			{
				ID:          uuid.New().String(),
				Description: "test",
				FileName:    "dont_open_this.exe",
				MimeType:    "text/plain",
				Data: decorator.AttachmentData{
					JSON: map[string]interface{}{
						"@id":   "123",
						"@type": "test-type",
					},
				},
			},
		},
	}
}

func newCallback() *callback {
	inv := newInvitation()

	return &callback{
		myDID:    fmt.Sprintf("did:example:%s", uuid.New().String()),
		theirDID: fmt.Sprintf("did:example:%s", uuid.New().String()),
		msg:      service.NewDIDCommMsgMap(inv),
		ctx: &context{
			CurrentStateName: StateNameInitial,
			Inbound:          true,
			Invitation:       inv,
		},
	}
}

func withState(t *testing.T, states ...*attachmentHandlingState) func(*Service) {
	return func(s *Service) {
		for i := range states {
			err := s.save(states[i])
			require.NoError(t, err)
		}
	}
}

func newAutoService(t *testing.T,
	provider *protocol.MockProvider, opts ...func(*Service)) *Service {
	s, err := New(provider)
	require.NoError(t, err)

	for i := range opts {
		opts[i](s)
	}

	events := make(chan service.DIDCommAction)
	require.NoError(t, s.RegisterActionEvent(events))

	go service.AutoExecuteActionEvent(events)

	return s
}

func newAck(pthid ...string) *model.Ack {
	a := &model.Ack{
		Type:   didexchange.AckMsgType,
		ID:     uuid.New().String(),
		Status: "good",
		Thread: &decorator.Thread{
			ID:  uuid.New().String(),
			PID: uuid.New().String(),
		},
	}

	if len(pthid) > 0 {
		a.Thread.PID = pthid[0]
	}

	return a
}

type testDIDCommMsg struct {
	msgType   string
	errDecode error
}

func (t *testDIDCommMsg) ID() string {
	panic("implement me")
}

func (t *testDIDCommMsg) SetID(id string, opts ...service.Opt) {
	panic("implement me")
}

func (t *testDIDCommMsg) SetThread(tid, pid string, opts ...service.Opt) {
	panic("implement me")
}

func (t *testDIDCommMsg) UnsetThread() {
	panic("implement me")
}

func (t *testDIDCommMsg) Type() string {
	return t.msgType
}

func (t *testDIDCommMsg) ThreadID() (string, error) {
	panic("implement me")
}

func (t *testDIDCommMsg) ParentThreadID() string {
	panic("implement me")
}

func (t *testDIDCommMsg) Clone() service.DIDCommMsgMap {
	panic("implement me")
}

func (t *testDIDCommMsg) Metadata() map[string]interface{} {
	panic("implement me")
}

func (t *testDIDCommMsg) Decode(v interface{}) error {
	return t.errDecode
}

type stubStore struct {
	putFunc func(k string, v []byte) error
}

func (s *stubStore) GetTags(key string) ([]storage.Tag, error) {
	panic("implement me")
}

func (s *stubStore) GetBulk(keys ...string) ([][]byte, error) {
	panic("implement me")
}

func (s *stubStore) Query(expression string, options ...storage.QueryOption) (storage.Iterator, error) {
	panic("implement me")
}

func (s *stubStore) Batch(operations []storage.Operation) error {
	panic("implement me")
}

func (s *stubStore) Flush() error {
	panic("implement me")
}

func (s *stubStore) Close() error {
	panic("implement me")
}

func (s *stubStore) Put(k string, v []byte, tags ...storage.Tag) error {
	if s.putFunc != nil {
		return s.putFunc(k, v)
	}

	return nil
}

func (s *stubStore) Get(k string) ([]byte, error) {
	panic("implement me")
}

func (s *stubStore) Iterator(start, limit string) storage.Iterator {
	panic("implement me")
}

func (s *stubStore) Delete(k string) error {
	panic("implement me")
}

type inboundMsgHandler struct {
	handleFunc func(msg service.DIDCommMsg, ctx service.DIDCommContext) (string, error)
}

func (i *inboundMsgHandler) HandleInbound(msg service.DIDCommMsg, ctx service.DIDCommContext) (string, error) {
	return i.handleFunc(msg, ctx)
}

func marshal(t *testing.T, v interface{}) []byte {
	t.Helper()

	raw, err := json.Marshal(v)
	require.NoError(t, err)

	return raw
}
