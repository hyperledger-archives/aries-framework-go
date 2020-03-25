/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofband

import (
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
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol"
	mockdidexchange "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol/didexchange"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
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
	t.Run("wraps error thrown from transient store when it cannot be opened", func(t *testing.T) {
		expected := errors.New("test")
		provider := testProvider()
		provider.TransientStoreProvider = &mockstore.MockStoreProvider{
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
	t.Run("accepts out-of-band request messages", func(t *testing.T) {
		s, err := New(testProvider())
		require.NoError(t, err)
		require.True(t, s.Accept("https://didcomm.org/oob-request/1.0/request"))
	})
	t.Run("rejects unsupported messages", func(t *testing.T) {
		s, err := New(testProvider())
		require.NoError(t, err)
		require.False(t, s.Accept("unsupported"))
	})
}

func TestHandleInbound(t *testing.T) {
	t.Run("accepts out-of-band request messages", func(t *testing.T) {
		s, err := New(testProvider())
		require.NoError(t, err)
		_, err = s.HandleInbound(
			service.NewDIDCommMsgMap(newRequest()),
			"did:example:mine",
			"did:example:theirs")
		require.NoError(t, err)
	})
	t.Run("rejects unsupported message types", func(t *testing.T) {
		s, err := New(testProvider())
		require.NoError(t, err)
		req := newRequest()
		req.Type = "invalid"
		_, err = s.HandleInbound(
			service.NewDIDCommMsgMap(req),
			"did:example:mine",
			"did:example:theirs")
		require.Error(t, err)
	})
	t.Run("fires off an action event", func(t *testing.T) {
		expected := service.NewDIDCommMsgMap(newRequest())
		s, err := New(testProvider())
		require.NoError(t, err)
		events := make(chan service.DIDCommAction)
		err = s.RegisterActionEvent(events)
		require.NoError(t, err)
		_, err = s.HandleInbound(expected, "did:example:mine", "did:example:theirs")
		require.NoError(t, err)
		select {
		case e := <-events:
			require.Equal(t, Name, e.ProtocolName)
			require.Equal(t, expected, e.Message)
		case <-time.After(1 * time.Second):
			t.Error("timeout waiting for action event")
		}
	})
}

func TestContinueFunc(t *testing.T) {
	t.Run("enqueues callback", func(t *testing.T) {
		callbacks := make(chan *callback, 2)
		msg := service.NewDIDCommMsgMap(newRequest())
		myDID := "did:example:mine"
		theirDID := "did:example:theirs"
		f := continueFunc(callbacks, msg, myDID, theirDID)
		f(nil)
		select {
		case c := <-callbacks:
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
				RespondToFunc: func(_ *didexchange.OOBInvitation) (string, error) {
					invoked <- struct{}{}
					return "", nil
				},
			},
		}
		s := newAutoService(t, provider)
		err := s.handleRequestCallback(newReqCallback())
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
				RespondToFunc: func(i *didexchange.OOBInvitation) (string, error) {
					require.NotNil(t, i)
					return "", nil
				},
			},
		}
		s := newAutoService(t, provider)
		err := s.handleRequestCallback(newReqCallback())
		require.NoError(t, err)
	})
	t.Run("wraps error thrown when decoding the message", func(t *testing.T) {
		expected := errors.New("test")
		s := newAutoService(t, testProvider())
		err := s.handleRequestCallback(&callback{msg: &testDIDCommMsg{errDecode: expected}})
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
	t.Run("wraps error returned by the didexchange service", func(t *testing.T) {
		expected := errors.New("test")
		provider := testProvider()
		provider.ServiceMap = map[string]interface{}{
			didexchange.DIDExchange: &mockdidexchange.MockDIDExchangeSvc{
				RespondToFunc: func(_ *didexchange.OOBInvitation) (string, error) {
					return "", expected
				},
			},
		}
		s := newAutoService(t, provider)
		err := s.handleRequestCallback(newReqCallback())
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
	t.Run("wraps error returned by the transient store", func(t *testing.T) {
		expected := errors.New("test")
		provider := testProvider()
		provider.TransientStoreProvider = &mockstore.MockStoreProvider{
			Store: &mockstore.MockStore{
				ErrPut: expected,
			},
		}
		s := newAutoService(t, provider)
		err := s.handleRequestCallback(newReqCallback())
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
		provider.InboundMsgHandler = func([]byte, string, string) error {
			invoked <- struct{}{}
			return nil
		}

		// setup connection state
		r, err := connection.NewRecorder(provider)
		require.NoError(t, err)
		err = r.SaveConnectionRecord(&connection.Record{
			ConnectionID: connID,
			MyDID:        "did:example:mine",
			TheirDID:     "did:example:theirs",
		})
		require.NoError(t, err)

		s := newAutoService(t, provider,
			withState(t, &myState{
				ID:           pthid,
				ConnectionID: connID,
				Request:      newRequest(),
				Done:         false,
			},
			))

		err = s.handleDIDEvent(service.StateMsg{
			ProtocolName: didexchange.DIDExchange,
			Type:         service.PostState,
			Msg:          service.NewDIDCommMsgMap(newAck(pthid)),
		})
		require.NoError(t, err)

		select {
		case <-invoked:
		case <-time.After(1 * time.Second):
			t.Error("timeout")
		}
	})
	t.Run("wraps error returned by the transient store", func(t *testing.T) {
		expected := errors.New("test")
		provider := testProvider()
		provider.TransientStoreProvider = &mockstore.MockStoreProvider{
			Store: &mockstore.MockStore{
				ErrGet: expected,
			},
		}
		s := newAutoService(t, provider)
		err := s.handleDIDEvent(service.StateMsg{
			ProtocolName: didexchange.DIDExchange,
			Type:         service.PostState,
			Msg:          service.NewDIDCommMsgMap(newAck()),
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
				Request:      newRequest(),
				Done:         false,
			},
			))
		err := s.handleDIDEvent(service.StateMsg{
			ProtocolName: didexchange.DIDExchange,
			Type:         service.PostState,
			Msg:          service.NewDIDCommMsgMap(newAck(pthid)),
		})
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
	t.Run("wraps error thrown by the dispatcher", func(t *testing.T) {
		expected := errors.New("test")
		pthid := uuid.New().String()
		connID := uuid.New().String()

		provider := testProvider()
		provider.InboundMsgHandler = func([]byte, string, string) error {
			return expected
		}

		// setup connection state
		r, err := connection.NewRecorder(provider)
		require.NoError(t, err)
		err = r.SaveConnectionRecord(&connection.Record{
			ConnectionID: connID,
			MyDID:        "did:example:mine",
			TheirDID:     "did:example:theirs",
		})
		require.NoError(t, err)

		s := newAutoService(t, provider,
			withState(t, &myState{
				ID:           pthid,
				ConnectionID: connID,
				Request:      newRequest(),
				Done:         false,
			},
			))
		err = s.handleDIDEvent(service.StateMsg{
			ProtocolName: didexchange.DIDExchange,
			Type:         service.PostState,
			Msg:          service.NewDIDCommMsgMap(newAck(pthid)),
		})
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
	t.Run("wraps error from store when saving state", func(t *testing.T) {
		expected := errors.New("test")
		pthid := uuid.New().String()
		connID := uuid.New().String()

		provider := testProvider()
		provider.InboundMsgHandler = func([]byte, string, string) error {
			return nil
		}

		// setup connection state
		r, err := connection.NewRecorder(provider)
		require.NoError(t, err)
		err = r.SaveConnectionRecord(&connection.Record{
			ConnectionID: connID,
			MyDID:        "did:example:mine",
			TheirDID:     "did:example:theirs",
		})
		require.NoError(t, err)

		s := newAutoService(t, provider,
			withState(t, &myState{
				ID:           pthid,
				ConnectionID: connID,
				Request:      newRequest(),
				Done:         false,
			},
			))

		s.store = &mockstore.MockStore{
			Store:  provider.TransientStoreProvider.Store.Store,
			ErrPut: expected,
		}

		err = s.handleDIDEvent(service.StateMsg{
			ProtocolName: didexchange.DIDExchange,
			Type:         service.PostState,
			Msg:          service.NewDIDCommMsgMap(newAck(pthid)),
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
				Request:      newRequest(),
				Done:         false,
			}),
		)
		s.getNextRequestFunc = func(*myState) (*decorator.Attachment, bool) {
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

		s := newAutoService(t, testProvider(),
			withState(t, &myState{
				ID:           pthid,
				ConnectionID: connID,
				Request:      newRequest(),
				Done:         false,
			}),
		)
		s.extractDIDCommMsgBytesFunc = func(*decorator.Attachment) ([]byte, error) {
			return nil, expected
		}
		err := s.handleDIDEvent(service.StateMsg{
			ProtocolName: didexchange.DIDExchange,
			Type:         service.PostState,
			Msg:          service.NewDIDCommMsgMap(newAck(pthid)),
		})
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
}

func TestListener(t *testing.T) {
	t.Run("invokes handleReqFunc", func(t *testing.T) {
		invoked := make(chan struct{})
		callbacks := make(chan *callback)
		handleReqFunc := func(*callback) error {
			invoked <- struct{}{}
			return nil
		}
		go listener(callbacks, nil, handleReqFunc, nil)()

		callbacks <- &callback{
			msg: service.NewDIDCommMsgMap(newRequest()),
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

func TestDecodeInvitationAndRequest(t *testing.T) {
	t.Run("returns invitation with a public DID and request", func(t *testing.T) {
		id := "did:example:myPublicDID123"
		expected := newRequest()
		expected.Service = []interface{}{id}
		inv, req, err := decodeInvitationAndRequest(service.NewDIDCommMsgMap(expected))
		require.NoError(t, err)
		require.NotNil(t, req)
		require.Equal(t, expected, req)
		require.NotNil(t, inv)
		require.NotEmpty(t, inv.ID)
		require.Equal(t, req.ID, inv.ID)
		require.Equal(t, req.ID, inv.ThreadID)
		require.Equal(t, req.Label, inv.Label)
		require.NotNil(t, inv.Target)
		require.Equal(t, id, inv.Target)
	})
	t.Run("returns invitation with a service block and request", func(t *testing.T) {
		expected := &did.Service{
			ID:              uuid.New().String(),
			Type:            "did-communication",
			Priority:        0,
			RecipientKeys:   []string{"did:example:123#key-1"},
			ServiceEndpoint: "http://my.test.endpoint.com",
		}
		req := newRequest()
		req.Service = []interface{}{expected}
		inv, req, err := decodeInvitationAndRequest(service.NewDIDCommMsgMap(req))
		require.NoError(t, err)
		require.NotNil(t, inv)
		require.Equal(t, expected, inv.Target)
		require.Equal(t, req.ID, inv.ID)
		require.Equal(t, req.ID, inv.ThreadID)
		require.Equal(t, req.Label, inv.Label)
	})
	t.Run("fails if request has no service targets", func(t *testing.T) {
		req := newRequest()
		req.Service = nil
		_, _, err := decodeInvitationAndRequest(service.NewDIDCommMsgMap(req))
		require.Error(t, err)
	})
	t.Run("wraps error thrown when decoding the message", func(t *testing.T) {
		expected := errors.New("test")
		msg := &testDIDCommMsg{errDecode: expected}
		_, _, err := decodeInvitationAndRequest(msg)
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
}

func testProvider() *protocol.MockProvider {
	return &protocol.MockProvider{
		StoreProvider:          mockstore.NewMockStoreProvider(),
		TransientStoreProvider: mockstore.NewMockStoreProvider(),
		ServiceMap: map[string]interface{}{
			didexchange.DIDExchange: &mockdidexchange.MockDIDExchangeSvc{},
		},
	}
}

func newRequest() *Request {
	return &Request{
		ID:       uuid.New().String(),
		Type:     RequestMsgType,
		Label:    "test",
		Goal:     "test",
		GoalCode: "test",
		Requests: []*decorator.Attachment{
			{
				ID:          uuid.New().String(),
				Description: "test",
				FileName:    "dont_open_this.exe",
				MimeType:    "text/plain",
				LastModTime: time.Now(),
				Data: decorator.AttachmentData{
					Base64: "test",
				},
			},
		},
		Service: []interface{}{"did:example:1235"},
	}
}

func newReqCallback() *callback {
	return &callback{
		myDID:    fmt.Sprintf("did:example:%s", uuid.New().String()),
		theirDID: fmt.Sprintf("did:example:%s", uuid.New().String()),
		msg:      service.NewDIDCommMsgMap(newRequest()),
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
	provider *protocol.MockProvider, opts ...func(*Service)) *Service { //nolint:interfacer
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
