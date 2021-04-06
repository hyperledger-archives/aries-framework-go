/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofband

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

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
		expected := service.NewDIDCommMsgMap(&Invitation{
			Type: InvitationMsgType,
		})
		s, err := New(testProvider())
		require.NoError(t, err)
		events := make(chan service.DIDCommAction)
		err = s.RegisterActionEvent(events)
		require.NoError(t, err)
		_, err = s.HandleInbound(expected, service.NewDIDCommContext(myDID, theirDID, nil))
		require.EqualError(t, err, "threadID: threadID not found")
	})
	t.Run("Save transitional payload (error)", func(t *testing.T) {
		expected := service.NewDIDCommMsgMap(newInvitation())
		s := &Service{
			store: &mockstore.MockStore{
				Store:  make(map[string]mockstore.DBEntry),
				ErrPut: fmt.Errorf("db error"),
			},
		}
		events := make(chan service.DIDCommAction)
		err := s.RegisterActionEvent(events)
		require.NoError(t, err)
		_, err = s.HandleInbound(expected, service.NewDIDCommContext(myDID, theirDID, nil))
		require.EqualError(t, err, "save transitional payload: db error")
	})
	t.Run("sends pre-state msg event", func(t *testing.T) {
		expected := service.NewDIDCommMsgMap(newInvitation())
		s, err := New(testProvider())
		require.NoError(t, err)
		stateMsgs := make(chan service.StateMsg)
		err = s.RegisterMsgEvent(stateMsgs)
		require.NoError(t, err)
		err = s.RegisterActionEvent(make(chan service.DIDCommAction))
		require.NoError(t, err)
		_, err = s.HandleInbound(expected, service.NewDIDCommContext(myDID, theirDID, nil))
		require.NoError(t, err)
		select {
		case result := <-stateMsgs:
			require.Equal(t, service.PreState, result.Type)
			require.Equal(t, Name, result.ProtocolName)
			require.Equal(t, StateInvited, result.StateID)
			require.Equal(t, expected, result.Msg)
			props, ok := result.Properties.(*eventProps)
			require.True(t, ok)
			require.Empty(t, props.ConnectionID())
			require.Nil(t, props.Error())
		case <-time.After(1 * time.Second):
			t.Error("timeout waiting for action event")
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
			require.NoError(t, s.ActionContinue(remainingActions[0].PIID, &userOptions{}))
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

		remainingActions, err = s.Actions()
		require.NoError(t, err)
		require.Equal(t, 0, len(remainingActions))
	})
	t.Run("Error", func(t *testing.T) {
		require.EqualError(t, (&Service{
			store: &mockstore.MockStore{
				Store:  make(map[string]mockstore.DBEntry),
				ErrGet: fmt.Errorf("db error"),
			},
		}).ActionContinue("piid", nil), "get transitional payload: store get: db error")
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
			store: &mockstore.MockStore{
				Store:  make(map[string]mockstore.DBEntry),
				ErrGet: fmt.Errorf("db error"),
			},
		}).ActionStop("piid", nil), "get transitional payload: store get: db error")
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
		provider := testProvider()
		provider.ServiceMap = map[string]interface{}{
			didexchange.DIDExchange: &mockdidexchange.MockDIDExchangeSvc{
				RespondToFunc: func(_ *didexchange.OOBInvitation, _ []string) (string, error) {
					invoked <- struct{}{}
					return "", nil
				},
			},
		}
		s := newAutoService(t, provider)
		_, err := s.handleInvitationCallback(newReqCallback())
		require.NoError(t, err)
		select {
		case <-invoked:
		case <-time.After(1 * time.Second):
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
		_, err := s.handleInvitationCallback(newReqCallback())
		require.NoError(t, err)
	})
	t.Run("wraps error thrown when decoding the message", func(t *testing.T) {
		expected := errors.New("test")
		s := newAutoService(t, testProvider())
		_, err := s.handleInvitationCallback(&callback{msg: &testDIDCommMsg{errDecode: expected}})
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
		_, err := s.handleInvitationCallback(newReqCallback())
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
		_, err := s.handleInvitationCallback(newReqCallback())
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
}

func TestHandleDIDEvent(t *testing.T) {
	t.Run("invokes outbound msg handler", func(t *testing.T) {
		invoked := make(chan struct{}, 2)
		connID := uuid.New().String()
		pthid := uuid.New().String()

		provider := testProvider()
		provider.OutboundMsgHandler = &outboundMsgHandlerStub{
			handleFunc: func(service.DIDCommMsg, string, string) (string, error) {
				invoked <- struct{}{}
				return "", nil
			},
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
			withState(t, &myState{
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
			withState(t, &myState{
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
		provider.OutboundMsgHandler = &outboundMsgHandlerStub{
			handleFunc: func(service.DIDCommMsg, string, string) (string, error) {
				return "", expected
			},
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
			withState(t, &myState{
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
			withState(t, &myState{
				ID:           pthid,
				ConnectionID: connID,
				Invitation:   newInvitation(),
				Done:         false,
			},
			))

		s.store = &mockstore.MockStore{
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
			withState(t, &myState{
				ID:           pthid,
				ConnectionID: connID,
				Invitation:   newInvitation(),
				Done:         false,
			}),
		)
		s.chooseRequestFunc = func(*myState) (*decorator.Attachment, bool) {
			return nil, false
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
			withState(t, &myState{
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
		go listener(callbacks, nil, handleReqFunc, nil, &service.Message{})()

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
		go listener(nil, didEvents, nil, handleDidEventFunc, nil)()
		didEvents <- service.StateMsg{}

		select {
		case <-invoked:
		case <-time.After(1 * time.Second):
			t.Error("timeout")
		}
	})
	t.Run("sends post-state event for oob invitation", func(t *testing.T) {
		connID := uuid.New().String()
		expected := service.NewDIDCommMsgMap(newInvitation())
		handler := make(chan service.StateMsg)
		handlers := &service.Message{}
		err := handlers.RegisterMsgEvent(handler)
		require.NoError(t, err)
		callbacks := make(chan *callback)
		handleReqFunc := func(*callback) (string, error) { return connID, nil }

		go listener(callbacks, nil, handleReqFunc, nil, handlers)()
		callbacks <- &callback{msg: expected}

		select {
		case result := <-handler:
			require.Equal(t, service.PostState, result.Type)
			require.Equal(t, "invited", result.StateID)
			require.Equal(t, "out-of-band", result.ProtocolName)
			require.Equal(t, expected, result.Msg)
			props, ok := result.Properties.(*eventProps)
			require.True(t, ok)
			require.Equal(t, connID, props.ConnectionID())
			require.Nil(t, props.Error())
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})
	t.Run("sends post-state event with error for oob invitation", func(t *testing.T) {
		expectedMsg := service.NewDIDCommMsgMap(newInvitation())
		expectedErr := errors.New("test")
		handler := make(chan service.StateMsg)
		handlers := &service.Message{}
		err := handlers.RegisterMsgEvent(handler)
		require.NoError(t, err)
		callbacks := make(chan *callback)
		handleReqFunc := func(*callback) (string, error) { return "", expectedErr }

		go listener(callbacks, nil, handleReqFunc, nil, handlers)()
		callbacks <- &callback{msg: expectedMsg}

		select {
		case result := <-handler:
			require.Equal(t, service.PostState, result.Type)
			require.Equal(t, "invited", result.StateID)
			require.Equal(t, "out-of-band", result.ProtocolName)
			require.Equal(t, expectedMsg, result.Msg)
			props, ok := result.Properties.(*eventProps)
			require.True(t, ok)
			require.Empty(t, props.ConnectionID())
			require.Error(t, props.Error())
			require.Equal(t, expectedErr, props.Error())
		case <-time.After(time.Second):
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
		result, err := s.AcceptInvitation(newInvitation(), "", nil)
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
		_, err := s.AcceptInvitation(newInvitation(), "", nil)
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
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
				require.Equal(t, expected.Service[0], i.Target)
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
		inv.Service = []interface{}{}
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
			RoutingKeys:     []string{"my routing key"},
			ServiceEndpoint: "my service endpoint",
		}
		result, err := chooseTarget([]interface{}{expected})
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})
	t.Run("chooses a map-type service", func(t *testing.T) {
		expected := map[string]interface{}{
			"id":              uuid.New().String(),
			"type":            "did-communication",
			"priority":        uint(0),
			"recipientKeys":   []string{"my ver key"},
			"routingKeys":     []string{"my routing key"},
			"serviceEndpoint": "my service endpoint",
		}
		svc, err := chooseTarget([]interface{}{expected})
		require.NoError(t, err)
		result, ok := svc.(*did.Service)
		require.True(t, ok)
		require.Equal(t, expected["id"], result.ID)
		require.Equal(t, expected["type"], result.Type)
		require.Equal(t, expected["priority"], result.Priority)
		require.Equal(t, expected["recipientKeys"], result.RecipientKeys)
		require.Equal(t, expected["routingKeys"], result.RoutingKeys)
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
	return &Invitation{
		ID:        uuid.New().String(),
		Type:      InvitationMsgType,
		Label:     "test",
		Goal:      "test",
		GoalCode:  "test",
		Service:   []interface{}{"did:example:1235"},
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

func newReqCallback() *callback {
	return &callback{
		myDID:    fmt.Sprintf("did:example:%s", uuid.New().String()),
		theirDID: fmt.Sprintf("did:example:%s", uuid.New().String()),
		msg:      service.NewDIDCommMsgMap(newInvitation()),
		options:  &userOptions{},
	}
}

func withState(t *testing.T, states ...*myState) func(*Service) {
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
	errDecode error
}

func (t *testDIDCommMsg) ID() string {
	panic("implement me")
}

func (t *testDIDCommMsg) SetID(id string) error {
	panic("implement me")
}

func (t *testDIDCommMsg) Type() string {
	panic("implement me")
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

type outboundMsgHandlerStub struct {
	handleFunc func(service.DIDCommMsg, string, string) (string, error)
}

func (o *outboundMsgHandlerStub) HandleOutbound(msg service.DIDCommMsg, myDID, theirDID string) (string, error) {
	if o.handleFunc != nil {
		return o.handleFunc(msg, myDID, theirDID)
	}

	return "", nil
}
