/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	dispatcherMocks "github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher/gomocks"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	mocks "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/introduce/gomocks"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	storageMocks "github.com/hyperledger/aries-framework-go/pkg/storage/gomocks"
)

// this line checks that Service satisfies service.Handler interface
var _ service.Handler = &Service{}

type flow struct {
	t            *testing.T
	wg           *sync.WaitGroup
	svc          *Service
	inv          *didexchange.Invitation
	transport    map[string]chan interface{}
	dep          *mocks.MockInvitationEnvelope
	dests        []*service.Destination
	transportKey string
}

func Test_nextState(t *testing.T) {
	t.Run("Happy path (ProposalMsgType arranging)", func(t *testing.T) {
		next, err := nextState(&service.DIDCommMsg{
			Header: &service.Header{Type: ProposalMsgType},
		}, nil, true)
		require.NoError(t, err)
		require.Equal(t, &arranging{}, next)
	})

	t.Run("Happy path (ProposalMsgType deciding)", func(t *testing.T) {
		next, err := nextState(&service.DIDCommMsg{
			Header: &service.Header{Type: ProposalMsgType},
		}, nil, false)
		require.NoError(t, err)
		require.Equal(t, &deciding{}, next)
	})

	t.Run("Happy path (ResponseMsgType waiting)", func(t *testing.T) {
		next, err := nextState(&service.DIDCommMsg{
			Header: &service.Header{Type: ResponseMsgType},
		}, nil, true)
		require.NoError(t, err)
		require.Equal(t, &waiting{}, next)
	})

	t.Run("Happy path (ResponseMsgType delivering)", func(t *testing.T) {
		next, err := nextState(&service.DIDCommMsg{
			Header: &service.Header{Type: ResponseMsgType},
		}, &record{WaitCount: 1}, false)
		require.NoError(t, err)
		require.Equal(t, &delivering{}, next)
	})

	t.Run("Happy path (AckMsgType)", func(t *testing.T) {
		next, err := nextState(&service.DIDCommMsg{
			Header: &service.Header{Type: AckMsgType},
		}, nil, false)
		require.NoError(t, err)
		require.Equal(t, &done{}, next)
	})
}

func TestService_handle(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	storageProvider := storageMocks.NewMockProvider(ctrl)
	storageProvider.EXPECT().OpenStore(Introduce).Return(nil, nil)

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().StorageProvider().Return(storageProvider)
	provider.EXPECT().OutboundDispatcher().Return(nil)

	svc, err := New(provider)
	require.NoError(t, err)

	defer stop(t, svc)

	dep := mocks.NewMockInvitationEnvelope(ctrl)
	dep.EXPECT().Destinations().Return(nil)

	require.EqualError(t, svc.handle(&metaData{
		dependency: dep,
		Msg:        &service.DIDCommMsg{},
	}, nil), "state from name: invalid state name ")

	// inject invitation error
	err = svc.handle(&metaData{
		record: record{
			StateName: stateNameStart,
		},
		Msg: &service.DIDCommMsg{
			Header:  &service.Header{Type: ResponseMsgType},
			Payload: []byte(`[]`),
		},
	}, nil)

	const errMsg = "inject invitation: json: cannot unmarshal array into Go value of type introduce.Response"

	require.EqualError(t, errors.Unwrap(err), errMsg)
}

func TestService_New(t *testing.T) {
	const errMsg = "test err"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	storageProvider := storageMocks.NewMockProvider(ctrl)
	storageProvider.EXPECT().OpenStore(Introduce).Return(nil, errors.New(errMsg))

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().StorageProvider().Return(storageProvider)

	svc, err := New(provider)
	require.EqualError(t, err, "test err")
	require.Nil(t, svc)
}

func fakeStore(ctrl *gomock.Controller) storage.Store {
	store := storageMocks.NewMockStore(ctrl)
	data := make(map[string][]byte)

	store.EXPECT().Put(gomock.Any(), gomock.Any()).DoAndReturn(func(k string, v []byte) error {
		data[k] = v

		return nil
	}).AnyTimes()
	store.EXPECT().Get(gomock.Any()).DoAndReturn(func(k string) ([]byte, error) {
		v, ok := data[k]
		if !ok {
			return nil, storage.ErrDataNotFound
		}

		return v, nil
	}).AnyTimes()

	return store
}

func TestService_abandon(t *testing.T) {
	const errMsg = "test err"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := storageMocks.NewMockStore(ctrl)
	store.EXPECT().Put("ID", []byte(`{}`)).Return(errors.New(errMsg))

	storageProvider := storageMocks.NewMockProvider(ctrl)
	storageProvider.EXPECT().OpenStore(Introduce).Return(store, nil)

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().StorageProvider().Return(storageProvider)
	provider.EXPECT().OutboundDispatcher().Return(nil)

	svc, err := New(provider)
	require.NoError(t, err)
	require.NotNil(t, svc)

	defer stop(t, svc)

	const errStr = "save abandoning sate: " + errMsg

	require.EqualError(t, svc.abandon("ID", &service.DIDCommMsg{}, nil), errStr)
}

func TestService_Stop(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	storageProvider := storageMocks.NewMockProvider(ctrl)
	storageProvider.EXPECT().OpenStore(Introduce).Return(nil, nil)

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().StorageProvider().Return(storageProvider)
	provider.EXPECT().OutboundDispatcher().Return(nil)

	svc, err := New(provider)
	require.NoError(t, err)

	require.NoError(t, svc.Stop())
	require.EqualError(t, svc.Stop(), "server was already stopped")
}

func TestService_Action(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	storageProvider := storageMocks.NewMockProvider(ctrl)
	storageProvider.EXPECT().OpenStore(Introduce).Return(nil, nil)

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().StorageProvider().Return(storageProvider)
	provider.EXPECT().OutboundDispatcher().Return(nil)

	svc, err := New(provider)
	require.NoError(t, err)

	defer stop(t, svc)

	ch := make(chan<- service.DIDCommAction)

	// by default
	require.Nil(t, svc.ActionEvent())

	// register action event
	require.Nil(t, svc.RegisterActionEvent(ch))
	require.Equal(t, ch, svc.ActionEvent())

	// unregister action event
	require.Nil(t, svc.UnregisterActionEvent(ch))
	require.Nil(t, svc.ActionEvent())
}

func TestService_Message(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	storageProvider := storageMocks.NewMockProvider(ctrl)
	storageProvider.EXPECT().OpenStore(Introduce).Return(nil, nil)

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().StorageProvider().Return(storageProvider)
	provider.EXPECT().OutboundDispatcher().Return(nil)

	svc, err := New(provider)
	require.NoError(t, err)

	defer stop(t, svc)

	ch := make(chan<- service.StateMsg)

	// by default
	require.Nil(t, svc.MsgEvents())

	// register message event
	require.Nil(t, svc.RegisterMsgEvent(ch))
	require.Equal(t, ch, svc.MsgEvents()[0])

	// unregister message event
	require.Nil(t, svc.UnregisterMsgEvent(ch))
	require.Equal(t, 0, len(svc.MsgEvents()))
}

func TestService_Name(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	storageProvider := storageMocks.NewMockProvider(ctrl)
	storageProvider.EXPECT().OpenStore(Introduce).Return(nil, nil)

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().StorageProvider().Return(storageProvider)
	provider.EXPECT().OutboundDispatcher().Return(nil)

	svc, err := New(provider)
	require.NoError(t, err)

	defer stop(t, svc)

	require.Equal(t, Introduce, svc.Name())
}

func TestService_HandleOutbound(t *testing.T) {
	t.Run("Storage JSON Error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get("ID").Return([]byte(`[]`), nil)

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(Introduce).Return(store, nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(nil)

		svc, err := New(provider)
		require.NoError(t, err)
		defer stop(t, svc)
		msg, err := service.NewDIDCommMsg([]byte(fmt.Sprintf(`{"@id":"ID","@type":%q}`, ResponseMsgType)))
		require.NoError(t, err)
		const errMsg = "json: cannot unmarshal array into Go value of type introduce.record"
		require.EqualError(t, svc.HandleOutbound(msg, nil), errMsg)
	})

	t.Run("Invalid state", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := storageMocks.NewMockStore(ctrl)
		raw := fmt.Sprintf(`{"state_name":%q, "wait_count":%d}`, "unknown", 1)
		store.EXPECT().Get("ID").Return([]byte(raw), nil)

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(Introduce).Return(store, nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(nil)

		svc, err := New(provider)

		require.NoError(t, err)
		defer stop(t, svc)
		msg, err := service.NewDIDCommMsg([]byte(fmt.Sprintf(`{"@id":"ID","@type":%q}`, ProposalMsgType)))
		require.NoError(t, err)
		ch := make(chan service.DIDCommAction)
		require.NoError(t, svc.RegisterActionEvent(ch))
		require.EqualError(t, svc.HandleOutbound(msg, &service.Destination{}), "invalid state name unknown")
	})

	t.Run("Happy path", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Put("ID", []byte(`{"state_name":"start","wait_count":1}`)).Return(nil)
		store.EXPECT().Get("ID").Return([]byte(`{"state_name":"start","wait_count":1}`), nil)
		store.EXPECT().Put("ID", []byte(`{"state_name":"arranging","wait_count":1}`)).Return(nil)

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(Introduce).Return(store, nil)

		dispatcher := dispatcherMocks.NewMockOutbound(ctrl)
		dispatcher.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(dispatcher)

		svc, err := New(provider)
		require.NoError(t, err)
		defer stop(t, svc)
		msg, err := service.NewDIDCommMsg([]byte(fmt.Sprintf(`{"@id":"ID","@type":%q}`, ProposalMsgType)))
		require.NoError(t, err)
		ch := make(chan service.DIDCommAction)
		require.NoError(t, svc.RegisterActionEvent(ch))
		require.NoError(t, svc.save("ID", record{
			StateName: stateNameStart,
			WaitCount: 1,
		}))
		require.NoError(t, svc.HandleOutbound(msg, &service.Destination{}))
	})
}

func TestService_HandleInboundStop(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := storageMocks.NewMockStore(ctrl)
	store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound)
	store.EXPECT().Put("ID", []byte(`{}`)).Return(nil)

	storageProvider := storageMocks.NewMockProvider(ctrl)
	storageProvider.EXPECT().OpenStore(Introduce).Return(store, nil)

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().StorageProvider().Return(storageProvider)
	provider.EXPECT().OutboundDispatcher().Return(nil)

	svc, err := New(provider)
	require.NoError(t, err)

	defer stop(t, svc)

	msg, err := service.NewDIDCommMsg([]byte(fmt.Sprintf(`{"@id":"ID","@type":%q}`, ProposalMsgType)))
	require.NoError(t, err)

	aCh := make(chan service.DIDCommAction)
	require.NoError(t, svc.RegisterActionEvent(aCh))

	sCh := make(chan service.StateMsg)
	require.NoError(t, svc.RegisterMsgEvent(sCh))

	go func() {
		_, err := svc.HandleInbound(msg)
		require.NoError(t, err)
	}()

	for {
		select {
		case res := <-aCh:
			res.Stop(errors.New("test error"))
		case <-time.After(time.Second):
			t.Error("timeout")
		case res := <-sCh:
			// test is done here!
			if res.StateID == stateNameAbandoning {
				return
			}
		}
	}
}

func TestService_HandleInbound(t *testing.T) {
	t.Parallel()

	t.Run("No clients", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(Introduce).Return(nil, nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(nil)

		svc, err := New(provider)
		require.NoError(t, err)
		defer stop(t, svc)
		_, err = svc.HandleInbound(&service.DIDCommMsg{})
		require.EqualError(t, err, "no clients are registered to handle the message")
	})

	t.Run("ThreadID Error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(Introduce).Return(nil, nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(nil)

		svc, err := New(provider)
		require.NoError(t, err)
		defer stop(t, svc)
		msg, err := service.NewDIDCommMsg([]byte(`{}`))
		require.NoError(t, err)
		ch := make(chan service.DIDCommAction)
		require.NoError(t, svc.RegisterActionEvent(ch))

		_, err = svc.HandleInbound(msg)
		require.EqualError(t, err, service.ErrThreadIDNotFound.Error())
	})

	t.Run("Storage error", func(t *testing.T) {
		const errMsg = "test err"

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get("ID").Return(nil, errors.New(errMsg))

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(Introduce).Return(store, nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(nil)

		svc, err := New(provider)
		require.NoError(t, err)
		defer stop(t, svc)
		msg, err := service.NewDIDCommMsg([]byte(fmt.Sprintf(`{"@id":"ID","@type":%q}`, ProposalMsgType)))
		require.NoError(t, err)
		ch := make(chan service.DIDCommAction)
		require.NoError(t, svc.RegisterActionEvent(ch))

		_, err = svc.HandleInbound(msg)
		require.EqualError(t, err, "cannot fetch state from store: thid=ID err=test err")
	})

	t.Run("Bad transition", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Put(gomock.Any(), []byte(`{"state_name":"noop","wait_count":1}`)).Return(nil)
		store.EXPECT().Get(gomock.Any()).Return([]byte(`{"state_name":"noop","wait_count":1}`), nil)

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(Introduce).Return(store, nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(nil)

		svc, err := New(provider)
		require.NoError(t, err)
		defer stop(t, svc)
		require.NoError(t, svc.save("ID", record{
			StateName: stateNameNoop,
			WaitCount: 1,
		}))
		msg, err := service.NewDIDCommMsg([]byte(fmt.Sprintf(`{"@id":"ID","@type":%q}`, ProposalMsgType)))
		require.NoError(t, err)
		ch := make(chan service.DIDCommAction)
		require.NoError(t, svc.RegisterActionEvent(ch))

		_, err = svc.HandleInbound(msg)
		require.EqualError(t, err, "invalid state transition: noop -> deciding")
	})

	t.Run("Invalid state", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := storageMocks.NewMockStore(ctrl)
		raw := fmt.Sprintf(`{"state_name":%q, "wait_count":%d}`, "unknown", 1)
		store.EXPECT().Get("ID").Return([]byte(raw), nil)

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(Introduce).Return(store, nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(nil)

		svc, err := New(provider)
		defer stop(t, svc)
		require.NoError(t, err)
		msg, err := service.NewDIDCommMsg([]byte(fmt.Sprintf(`{"@id":"ID","@type":%q}`, ProposalMsgType)))
		require.NoError(t, err)
		ch := make(chan service.DIDCommAction)
		require.NoError(t, svc.RegisterActionEvent(ch))

		_, err = svc.HandleInbound(msg)
		require.EqualError(t, err, "invalid state name unknown")
	})

	t.Run("Unknown msg type error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get("ID").Return(nil, storage.ErrDataNotFound)

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(Introduce).Return(store, nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(nil)

		svc, err := New(provider)
		require.NoError(t, err)
		defer stop(t, svc)
		msg, err := service.NewDIDCommMsg([]byte(`{"@id":"ID","@type":"unknown"}`))
		require.NoError(t, err)
		ch := make(chan service.DIDCommAction)
		require.NoError(t, svc.RegisterActionEvent(ch))

		_, err = svc.HandleInbound(msg)
		require.EqualError(t, err, "unrecognized msgType: unknown")
	})

	t.Run("Happy path (send an action event)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get("ID").Return(nil, storage.ErrDataNotFound)
		store.EXPECT().Put("ID", []byte(`{}`)).Return(nil)

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(Introduce).Return(store, nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(nil)

		svc, err := New(provider)
		require.NoError(t, err)
		defer stop(t, svc)
		msg, err := service.NewDIDCommMsg([]byte(fmt.Sprintf(`{"@id":"ID","@type":%q}`, ProposalMsgType)))
		require.NoError(t, err)
		ch := make(chan service.DIDCommAction)
		require.NoError(t, svc.RegisterActionEvent(ch))
		go func() {
			_, err := svc.HandleInbound(msg)
			require.NoError(t, err)
		}()

		select {
		case res := <-ch:
			// TODO: need to check `Continue` function after implantation `processCallback`
			res.Continue(&service.Empty{})
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Happy path (execute handle)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get("ID").Return(nil, storage.ErrDataNotFound)

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(Introduce).Return(store, nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(nil)

		svc, err := New(provider)
		require.NoError(t, err)
		defer stop(t, svc)
		msg, err := service.NewDIDCommMsg([]byte(fmt.Sprintf(`{"@id":"ID","@type":%q}`, ResponseMsgType)))
		require.NoError(t, err)
		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		_, err = svc.HandleInbound(msg)
		require.Nil(t, errors.Unwrap(err))
	})
}

func TestService_Accept(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	storageProvider := storageMocks.NewMockProvider(ctrl)
	storageProvider.EXPECT().OpenStore(Introduce).Return(nil, nil)

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().StorageProvider().Return(storageProvider)
	provider.EXPECT().OutboundDispatcher().Return(nil)

	svc, err := New(provider)
	require.NoError(t, err)

	defer stop(t, svc)

	require.False(t, svc.Accept(""))
	require.True(t, svc.Accept(ProposalMsgType))
	require.True(t, svc.Accept(RequestMsgType))
	require.True(t, svc.Accept(ResponseMsgType))
	require.True(t, svc.Accept(AckMsgType))
}

func Test_stateFromName(t *testing.T) {
	st, err := stateFromName(stateNameNoop)
	require.NoError(t, err)
	require.Equal(t, &noOp{}, st)

	st, err = stateFromName(stateNameStart)
	require.NoError(t, err)
	require.Equal(t, &start{}, st)

	st, err = stateFromName(stateNameDone)
	require.NoError(t, err)
	require.Equal(t, &done{}, st)

	st, err = stateFromName(stateNameArranging)
	require.NoError(t, err)
	require.Equal(t, &arranging{}, st)

	st, err = stateFromName(stateNameDelivering)
	require.NoError(t, err)
	require.Equal(t, &delivering{}, st)

	st, err = stateFromName(stateNameConfirming)
	require.NoError(t, err)
	require.Equal(t, &confirming{}, st)

	st, err = stateFromName(stateNameAbandoning)
	require.NoError(t, err)
	require.Equal(t, &abandoning{}, st)

	st, err = stateFromName(stateNameDeciding)
	require.NoError(t, err)
	require.Equal(t, &deciding{}, st)

	st, err = stateFromName(stateNameWaiting)
	require.NoError(t, err)
	require.Equal(t, &waiting{}, st)

	st, err = stateFromName("unknown")
	require.EqualError(t, err, "invalid state name unknown")
	require.Nil(t, st)
}

func TestService_save(t *testing.T) {
	t.Run("Happy path", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := storageMocks.NewMockStore(ctrl)

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(Introduce).Return(store, nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(nil)

		svc, err := New(provider)
		require.NoError(t, err)
		defer stop(t, svc)
		data := &metaData{
			record: record{
				StateName: "state_name",
				WaitCount: 2,
			},
			Msg: &service.DIDCommMsg{
				Header: &service.Header{
					ID:     "ID",
					Thread: decorator.Thread{},
					Type:   "Type",
				},
				Payload: []byte{0x1},
			},
			ThreadID: "ThreadID",
		}
		store.EXPECT().Put("ID", toBytes(t, data)).Return(nil)
		require.NoError(t, svc.save("ID", data))
	})

	t.Run("JSON Error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(Introduce).Return(nil, nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(nil)

		svc, err := New(provider)
		defer stop(t, svc)
		require.NoError(t, err)
		const errMsg = "service save: json: unsupported type: chan int"
		require.EqualError(t, svc.save("ID", struct{ A chan int }{}), errMsg)
	})
}

// This test describes the following flow :
// 1. Alice sends a proposal to the Bob
// 2. Bob responded with an invitation and approval
// 3. Alice sends a proposal to the Carol
// 4. Carol responded with approval
// 5. Alice forwards an invitation to Carol
// 6  Alice sends Ack message to Bob
func TestService_Proposal(t *testing.T) {
	const (
		Alice = "Alice"
		Bob   = "Bob"
		Carol = "Carol"
	)

	// the map of channels which is responsible for the communication
	transport := map[string]chan interface{}{
		Alice: make(chan interface{}),
		Bob:   make(chan interface{}),
		Carol: make(chan interface{}),
	}

	inv := &didexchange.Invitation{Label: Bob}
	dests := []*service.Destination{
		{ServiceEndpoint: Bob},
		{ServiceEndpoint: Carol},
	}

	getInboundDestinationOriginal := getInboundDestination

	defer func() { getInboundDestination = getInboundDestinationOriginal }()

	// injection
	getInboundDestination = func() *service.Destination {
		return &service.Destination{ServiceEndpoint: Alice}
	}

	aliceCtrl, alice, aliceDep := setupIntroducer(&flow{
		t:         t,
		inv:       inv,
		transport: transport,
		dests:     dests,
	})
	defer aliceCtrl.Finish()
	defer stop(t, alice)

	bobCtrl, bob, bobDep := setupIntroducee(&flow{
		t:         t,
		inv:       inv,
		transport: transport,
	})
	defer bobCtrl.Finish()
	defer stop(t, bob)

	carolCtrl, carol, carolDep := setupIntroducee(&flow{
		t:         t,
		transport: transport,
	})
	defer carolCtrl.Finish()
	defer stop(t, carol)

	var wg sync.WaitGroup

	wg.Add(3)

	go handleIntroducer(&flow{
		t:            t,
		wg:           &wg,
		svc:          alice,
		transport:    transport,
		dep:          aliceDep,
		transportKey: Alice,
		dests:        dests,
	})

	go handleIntroduceeDone(&flow{
		t:            t,
		wg:           &wg,
		svc:          bob,
		transport:    transport,
		dep:          bobDep,
		transportKey: Bob,
	})

	go handleIntroduceeUnfinished(&flow{
		t:            t,
		wg:           &wg,
		svc:          carol,
		transport:    transport,
		dep:          carolDep,
		transportKey: Carol,
	})

	wg.Wait()
}

// This test describes the following flow :
// 1. Alice sends a proposal to the Bob
// 2. Bob responded with approval
// 3. Alice forwards an invitation to Bob
func TestService_SkipProposal(t *testing.T) {
	const (
		Alice = "Alice"
		Bob   = "Bob"
	)

	// the channel which is responsible for the communication
	transport := map[string]chan interface{}{
		Alice: make(chan interface{}),
		Bob:   make(chan interface{}),
	}

	inv := &didexchange.Invitation{Label: "Public Invitation"}
	dests := []*service.Destination{{ServiceEndpoint: Bob}}

	getInboundDestinationOriginal := getInboundDestination

	defer func() { getInboundDestination = getInboundDestinationOriginal }()

	// injection
	getInboundDestination = func() *service.Destination {
		return &service.Destination{ServiceEndpoint: Alice}
	}

	aliceCtrl, alice, aliceDep := setupIntroducer(&flow{
		t:         t,
		inv:       inv,
		transport: transport,
		dests:     dests,
	})
	defer aliceCtrl.Finish()
	defer stop(t, alice)

	bobCtrl, bob, bobDep := setupIntroducee(&flow{
		t:         t,
		inv:       &didexchange.Invitation{Label: Bob},
		transport: transport,
	})
	defer bobCtrl.Finish()
	defer stop(t, bob)

	var wg sync.WaitGroup

	wg.Add(2)

	go handleIntroducer(&flow{
		t:            t,
		wg:           &wg,
		svc:          alice,
		transport:    transport,
		dep:          aliceDep,
		transportKey: Alice,
		dests:        dests,
	})

	go handleIntroduceeUnfinished(&flow{
		t:            t,
		wg:           &wg,
		svc:          bob,
		transport:    transport,
		dep:          bobDep,
		transportKey: Bob,
	})

	wg.Wait()
}

// This test describes the following flow :
// 1. Alice sends a proposal to the Bob
// 2. Bob responded with approval (without an invitation)
// 3. Alice sends a proposal to the Carol
// 4. Carol responded with an invitation and approval
// 5. Alice forwards an invitation to Bob
// 6  Alice sends Ack message to Carol
func TestService_ProposalUnusual(t *testing.T) {
	const (
		Alice = "Alice"
		Bob   = "Bob"
		Carol = "Carol"
	)

	// the map of channels which is responsible for the communication
	transport := map[string]chan interface{}{
		Alice: make(chan interface{}),
		Bob:   make(chan interface{}),
		Carol: make(chan interface{}),
	}

	inv := &didexchange.Invitation{Label: Carol}
	dests := []*service.Destination{
		{ServiceEndpoint: Bob},
		{ServiceEndpoint: Carol},
	}

	getInboundDestinationOriginal := getInboundDestination

	defer func() { getInboundDestination = getInboundDestinationOriginal }()

	// injection
	getInboundDestination = func() *service.Destination {
		return &service.Destination{ServiceEndpoint: Alice}
	}

	aliceCtrl, alice, aliceDep := setupIntroducer(&flow{
		t:         t,
		inv:       inv,
		transport: transport,
		dests:     dests,
	})
	defer aliceCtrl.Finish()
	defer stop(t, alice)

	bobCtrl, bob, bobDep := setupIntroducee(&flow{
		t:         t,
		transport: transport,
	})
	defer bobCtrl.Finish()
	defer stop(t, bob)

	carolCtrl, carol, carolDep := setupIntroducee(&flow{
		t:         t,
		inv:       inv,
		transport: transport,
	})
	defer carolCtrl.Finish()
	defer stop(t, carol)

	var wg sync.WaitGroup

	wg.Add(3)

	go handleIntroducer(&flow{
		t:            t,
		wg:           &wg,
		svc:          alice,
		transport:    transport,
		dep:          aliceDep,
		transportKey: Alice,
		dests:        dests,
	})

	go handleIntroduceeUnfinished(&flow{
		t:            t,
		wg:           &wg,
		svc:          bob,
		transport:    transport,
		dep:          bobDep,
		transportKey: Bob,
	})

	go handleIntroduceeDone(&flow{
		t:            t,
		wg:           &wg,
		svc:          carol,
		transport:    transport,
		dep:          carolDep,
		transportKey: Carol,
	})

	wg.Wait()
}

func setupIntroducer(f *flow) (*gomock.Controller, *Service, *mocks.MockInvitationEnvelope) {
	ctrl := gomock.NewController(f.t)

	dispatcher := dispatcherMocks.NewMockOutbound(ctrl)
	dispatcher.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any()).
		Do(func(msg interface{}, _ string, dest *service.Destination) error {
			f.transport[dest.ServiceEndpoint] <- msg
			return nil
		}).MaxTimes(3)

	storageProvider := storageMocks.NewMockProvider(ctrl)
	storageProvider.EXPECT().OpenStore(Introduce).Return(fakeStore(ctrl), nil)

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().StorageProvider().Return(storageProvider)
	provider.EXPECT().OutboundDispatcher().Return(dispatcher)
	provider.EXPECT().SendInvitation(f.inv, gomock.Any()).Return(nil)

	svc, err := New(provider)
	require.NoError(f.t, err)

	dep := mocks.NewMockInvitationEnvelope(ctrl)

	dep.EXPECT().Invitation().Return(f.inv).MaxTimes(1)
	dep.EXPECT().Destinations().Return(f.dests).AnyTimes()

	return ctrl, svc, dep
}

func handleIntroducer(f *flow) {
	defer f.wg.Done()

	// register action event channel
	aCh := make(chan service.DIDCommAction)
	require.NoError(f.t, f.svc.RegisterActionEvent(aCh))

	// register action event channel
	sCh := make(chan service.StateMsg)
	require.NoError(f.t, f.svc.RegisterMsgEvent(sCh))

	// creates proposal msg
	proposal, err := service.NewDIDCommMsg(toBytes(f.t, Proposal{
		Type: ProposalMsgType,
		// creates threadID
		ID: uuid.New().String(),
	}))
	require.NoError(f.t, err)

	go func() {
		// handle outbound Proposal msg (sends Proposal)
		require.NoError(f.t, f.svc.HandleOutbound(proposal, &service.Destination{
			ServiceEndpoint: f.dests[0].ServiceEndpoint,
		}))
	}()
	checkStateMsg(f.t, sCh, service.PreState, ProposalMsgType, stateNameArranging)
	checkStateMsg(f.t, sCh, service.PostState, ProposalMsgType, stateNameArranging)

	// this code will be ignored for skip proposal
	if len(f.dests) != 1 {
		go func() {
			// handle Response msg (receives Response)
			// nolint: govet
			resp, err := service.NewDIDCommMsg(toBytes(f.t, <-f.transport[f.transportKey]))
			require.NoError(f.t, err)
			_, err = f.svc.HandleInbound(resp)
			require.NoError(f.t, err)
		}()
		continueAction(f.t, aCh, ResponseMsgType, f.dep)
		checkStateMsg(f.t, sCh, service.PreState, ResponseMsgType, stateNameArranging)
		checkStateMsg(f.t, sCh, service.PostState, ResponseMsgType, stateNameArranging)
	}

	go func() {
		// handle Response msg (receives Response)
		// nolint: govet
		resp, err := service.NewDIDCommMsg(toBytes(f.t, <-f.transport[f.transportKey]))
		require.NoError(f.t, err)
		_, err = f.svc.HandleInbound(resp)
		require.NoError(f.t, err)
	}()
	continueAction(f.t, aCh, ResponseMsgType, f.dep)
	checkStateMsg(f.t, sCh, service.PreState, ResponseMsgType, stateNameDelivering)
	checkStateMsg(f.t, sCh, service.PostState, ResponseMsgType, stateNameDelivering)
	checkStateMsg(f.t, sCh, service.PreState, ResponseMsgType, stateNameDone)
	checkStateMsg(f.t, sCh, service.PostState, ResponseMsgType, stateNameDone)
}

func setupIntroducee(f *flow) (*gomock.Controller, *Service, *mocks.MockInvitationEnvelope) {
	ctrl := gomock.NewController(f.t)

	dispatcher := dispatcherMocks.NewMockOutbound(ctrl)
	dispatcher.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any()).
		Do(func(msg interface{}, _ string, dest *service.Destination) error {
			f.transport[dest.ServiceEndpoint] <- msg
			return nil
		}).AnyTimes()

	storageProvider := storageMocks.NewMockProvider(ctrl)
	storageProvider.EXPECT().OpenStore(Introduce).Return(fakeStore(ctrl), nil)

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().StorageProvider().Return(storageProvider)
	provider.EXPECT().OutboundDispatcher().Return(dispatcher)

	svc, err := New(provider)
	require.NoError(f.t, err)

	dep := mocks.NewMockInvitationEnvelope(ctrl)
	dep.EXPECT().Destinations().Return(nil)
	dep.EXPECT().Invitation().Return(f.inv)

	return ctrl, svc, dep
}

func handleIntroduceeDone(f *flow) {
	defer f.wg.Done()

	// register action event channel
	aCh := make(chan service.DIDCommAction)
	require.NoError(f.t, f.svc.RegisterActionEvent(aCh))

	// register action event channel
	sCh := make(chan service.StateMsg)
	require.NoError(f.t, f.svc.RegisterMsgEvent(sCh))

	go func() {
		// handle Proposal msg (sends Request)
		// nolint: govet
		reqMsg, err := service.NewDIDCommMsg(toBytes(f.t, <-f.transport[f.transportKey]))
		require.NoError(f.t, err)
		_, err = f.svc.HandleInbound(reqMsg)
		require.NoError(f.t, err)
	}()

	continueAction(f.t, aCh, ProposalMsgType, f.dep)
	checkStateMsg(f.t, sCh, service.PreState, ProposalMsgType, stateNameDeciding)
	checkStateMsg(f.t, sCh, service.PostState, ProposalMsgType, stateNameDeciding)
	checkStateMsg(f.t, sCh, service.PreState, ProposalMsgType, stateNameWaiting)
	checkStateMsg(f.t, sCh, service.PostState, ProposalMsgType, stateNameWaiting)

	go func() {
		// handle Ack msg
		// nolint: govet
		ackMsg, err := service.NewDIDCommMsg(toBytes(f.t, <-f.transport[f.transportKey]))
		require.NoError(f.t, err)
		_, err = f.svc.HandleInbound(ackMsg)
		require.NoError(f.t, err)
	}()
	checkStateMsg(f.t, sCh, service.PreState, AckMsgType, stateNameDone)
	checkStateMsg(f.t, sCh, service.PostState, AckMsgType, stateNameDone)
}

func handleIntroduceeUnfinished(f *flow) {
	defer f.wg.Done()

	// register action event channel
	aCh := make(chan service.DIDCommAction)
	require.NoError(f.t, f.svc.RegisterActionEvent(aCh))

	// register action event channel
	sCh := make(chan service.StateMsg)
	require.NoError(f.t, f.svc.RegisterMsgEvent(sCh))

	// handle Proposal msg (sends Request)
	go func() {
		// creates proposal msg
		reqMsg, err := service.NewDIDCommMsg(toBytes(f.t, <-f.transport[f.transportKey]))
		require.NoError(f.t, err)
		_, err = f.svc.HandleInbound(reqMsg)
		require.NoError(f.t, err)
	}()

	// TODO: state machine should be done!
	continueAction(f.t, aCh, ProposalMsgType, f.dep)
	checkStateMsg(f.t, sCh, service.PreState, ProposalMsgType, stateNameDeciding)
	checkStateMsg(f.t, sCh, service.PostState, ProposalMsgType, stateNameDeciding)
	checkStateMsg(f.t, sCh, service.PreState, ProposalMsgType, stateNameWaiting)
	checkStateMsg(f.t, sCh, service.PostState, ProposalMsgType, stateNameWaiting)
}

func checkStateMsg(t *testing.T, ch chan service.StateMsg, sType service.StateMsgType, dType, stateID string) {
	t.Helper()

	select {
	case res := <-ch:
		require.Equal(t, sType, res.Type)
		require.Equal(t, dType, res.Msg.Header.Type)
		require.Equal(t, stateID, res.StateID)

		return
	case <-time.After(time.Second):
		t.Fatalf("timeout: waiting for %d %s - %s", sType, dType, stateID)
	}
}

func continueAction(t *testing.T, ch chan service.DIDCommAction, action string, dep InvitationEnvelope) {
	t.Helper()

	select {
	case res := <-ch:
		require.Equal(t, action, res.Message.Header.Type)

		if res.Message.Header.Type != RequestMsgType {
			res.Continue(dep)
		}

		return
	case <-time.After(time.Second):
		t.Error("timeout")
	}
}

func toBytes(t *testing.T, data interface{}) []byte {
	t.Helper()

	src, err := json.Marshal(data)
	require.NoError(t, err)

	return src
}

type stopper interface {
	Stop() error
}

func stop(t *testing.T, s stopper) {
	t.Helper()

	done := make(chan struct{})

	go func() { require.NoError(t, s.Stop()); close(done) }()

	select {
	case <-done:
		return
	case <-time.After(time.Second):
		t.Error("timeout waiting for Stop()")
	}
}
