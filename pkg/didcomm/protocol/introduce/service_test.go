/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	dispatcherMocks "github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher/gomocks"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	mocks "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/introduce/gomocks"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	storageMocks "github.com/hyperledger/aries-framework-go/pkg/storage/gomocks"
)

// this line checks that Service satisfies service.Handler interface
var _ service.Handler = &Service{}

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
	t.Parallel()
	t.Run("Happy path", func(t *testing.T) {
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

		require.EqualError(t, svc.handle(&metaData{
			Msg: &service.DIDCommMsg{},
		}, nil), "state from name: invalid state name ")
	})

	t.Run("Happy path", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Put("ID", []byte(`{"StateName":"start","WaitCount":0}`)).Return(nil).Times(1)
		store.EXPECT().Put("ID", []byte(`{"StateName":"arranging","WaitCount":0}`)).Return(nil).Times(1)

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

		ch := make(chan service.StateMsg, 2)
		require.NoError(t, svc.RegisterMsgEvent(ch))
		done := make(chan struct{})

		go func() {
			timeout := time.After(time.Millisecond * 100)
			expected := []service.StateMsgType{
				service.PreState,
				service.PostState,
			}
			for {
				select {
				case res := <-ch:
					require.Equal(t, res.Type, expected[0])
					expected = expected[1:]
					if len(expected) == 0 {
						done <- struct{}{}
						return
					}
				case <-timeout:
					t.Error("timeout")
				}
			}
		}()

		require.NoError(t, svc.handle(&metaData{
			record:   record{StateName: stateNameStart},
			Msg:      &service.DIDCommMsg{},
			ThreadID: "ID",
		}, nil))
		<-done
	})
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
		raw := fmt.Sprintf(`{"StateName":%q, "WaitCount":%d}`, "unknown", 1)
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
		store.EXPECT().Put("ID", []byte(`{"StateName":"start","WaitCount":1}`)).Return(nil)
		store.EXPECT().Get("ID").Return([]byte(`{"StateName":"start","WaitCount":1}`), nil)
		store.EXPECT().Put("ID", []byte(`{"StateName":"arranging","WaitCount":1}`)).Return(nil)

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(Introduce).Return(store, nil)

		dispatcher := dispatcherMocks.NewMockOutbound(ctrl)
		dispatcher.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)

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

	t.Run("Happy path (Request)", func(t *testing.T) {
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
		msg, err := service.NewDIDCommMsg([]byte(fmt.Sprintf(`{"@id":"ID","@type":%q}`, RequestMsgType)))
		require.NoError(t, err)
		ch := make(chan service.DIDCommAction)
		require.NoError(t, svc.RegisterActionEvent(ch))
		require.NoError(t, svc.HandleOutbound(msg, &service.Destination{}))
	})
}

func TestService_HandleInboundStop(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := storageMocks.NewMockStore(ctrl)
	store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound).Times(1)
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
		store.EXPECT().Put(gomock.Any(), []byte(`{"StateName":"noop","WaitCount":1}`)).Return(nil)
		store.EXPECT().Get(gomock.Any()).Return([]byte(`{"StateName":"noop","WaitCount":1}`), nil)

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
		raw := fmt.Sprintf(`{"StateName":%q, "WaitCount":%d}`, "unknown", 1)
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
				StateName: "StateName",
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

// Proposal
func TestService_Proposal(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Introducer", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound).Times(1)
		store.EXPECT().Put(gomock.Any(), []byte(`{"StateName":"arranging","WaitCount":2}`)).Return(nil).Times(1)
		store.EXPECT().Get(gomock.Any()).Return([]byte(`{"StateName":"arranging","WaitCount":2}`), nil).Times(1)
		store.EXPECT().Put(gomock.Any(), []byte(`{"StateName":"arranging","WaitCount":1}`)).Return(nil).Times(1)
		store.EXPECT().Get(gomock.Any()).Return([]byte(`{"StateName":"arranging","WaitCount":1}`), nil).Times(1)
		store.EXPECT().Put(gomock.Any(), []byte(`{"StateName":"delivering","WaitCount":0}`)).Return(nil).Times(1)
		store.EXPECT().Put(gomock.Any(), []byte(`{"StateName":"done","WaitCount":0}`)).Return(nil).Times(1)

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(Introduce).Return(store, nil)

		dispatcher := dispatcherMocks.NewMockOutbound(ctrl)
		dispatcher.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(2)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(dispatcher)

		svc, err := New(provider)
		require.NoError(t, err)
		defer stop(t, svc)

		// register action event channel
		aCh := make(chan service.DIDCommAction)
		require.NoError(t, svc.RegisterActionEvent(aCh))

		// register action event channel
		sCh := make(chan service.StateMsg)
		require.NoError(t, svc.RegisterMsgEvent(sCh))

		// creates threadID
		thID := uuid.New().String()

		// creates proposal msg
		propMsg, err := service.NewDIDCommMsg(toBytes(t, Proposal{
			Type: ProposalMsgType,
			ID:   thID,
		}))
		require.NoError(t, err)

		// handle outbound Proposal msg (sends Proposal)
		go func() { require.NoError(t, svc.HandleOutbound(propMsg, &service.Destination{})) }()
		checkStateMsg(t, sCh, service.PreState, ProposalMsgType, stateNameArranging)
		checkStateMsg(t, sCh, service.PostState, ProposalMsgType, stateNameArranging)

		respMsg1, err := service.NewDIDCommMsg(toBytes(t, Response{
			Type:   ResponseMsgType,
			ID:     uuid.New().String(),
			Thread: &decorator.Thread{ID: thID},
		}))
		require.NoError(t, err)

		// handle Response msg (receives Response)
		go func() {
			// nolint: govet
			_, err := svc.HandleInbound(respMsg1)
			require.NoError(t, err)
		}()

		dep := mocks.NewMockInvitationEnvelope(ctrl)
		dep.EXPECT().Destinations().Return([]*service.Destination{
			{ServiceEndpoint: "service/endpoint1"},
			{ServiceEndpoint: "service/endpoint2"},
		}).Times(2)

		continueAction(t, aCh, ResponseMsgType, dep)
		checkStateMsg(t, sCh, service.PreState, ResponseMsgType, stateNameArranging)
		checkStateMsg(t, sCh, service.PostState, ResponseMsgType, stateNameArranging)

		respMsg2, err := service.NewDIDCommMsg(toBytes(t, Response{
			Type:   ResponseMsgType,
			ID:     uuid.New().String(),
			Thread: &decorator.Thread{ID: thID},
		}))
		require.NoError(t, err)

		// handle Response msg (receives Response)
		go func() {
			// nolint: govet
			_, err := svc.HandleInbound(respMsg2)
			require.NoError(t, err)
		}()

		continueAction(t, aCh, ResponseMsgType, dep)
		checkStateMsg(t, sCh, service.PreState, ResponseMsgType, stateNameDelivering)
		checkStateMsg(t, sCh, service.PostState, ResponseMsgType, stateNameDelivering)
		checkStateMsg(t, sCh, service.PreState, ResponseMsgType, stateNameDone)
		checkStateMsg(t, sCh, service.PostState, ResponseMsgType, stateNameDone)
	})

	t.Run("Introducee", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound).Times(1)
		store.EXPECT().Put(gomock.Any(), []byte(`{"StateName":"deciding","WaitCount":2}`)).Return(nil).Times(1)
		store.EXPECT().Put(gomock.Any(), []byte(`{"StateName":"waiting","WaitCount":2}`)).Return(nil).Times(1)
		store.EXPECT().Get(gomock.Any()).Return([]byte(`{"StateName":"waiting","WaitCount":2}`), nil).Times(1)
		store.EXPECT().Put(gomock.Any(), []byte(`{"StateName":"done","WaitCount":2}`)).Return(nil).Times(1)

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

		// register action event channel
		aCh := make(chan service.DIDCommAction)
		require.NoError(t, svc.RegisterActionEvent(aCh))

		// register action event channel
		sCh := make(chan service.StateMsg)
		require.NoError(t, svc.RegisterMsgEvent(sCh))

		// creates threadID
		thID := uuid.New().String()

		// creates proposal msg
		reqMsg, err := service.NewDIDCommMsg(toBytes(t, Proposal{
			Type: ProposalMsgType,
			ID:   thID,
		}))
		require.NoError(t, err)

		// handle Proposal msg (sends Request)
		go func() {
			// nolint: govet
			_, err := svc.HandleInbound(reqMsg)
			require.NoError(t, err)
		}()

		dep := mocks.NewMockInvitationEnvelope(ctrl)
		dep.EXPECT().Destinations().Return(nil)

		continueAction(t, aCh, ProposalMsgType, dep)
		checkStateMsg(t, sCh, service.PreState, ProposalMsgType, stateNameDeciding)
		checkStateMsg(t, sCh, service.PostState, ProposalMsgType, stateNameDeciding)
		checkStateMsg(t, sCh, service.PreState, ProposalMsgType, stateNameWaiting)
		checkStateMsg(t, sCh, service.PostState, ProposalMsgType, stateNameWaiting)

		// creates Ack msg
		ackMsg, err := service.NewDIDCommMsg(toBytes(t, model.Ack{
			Type: AckMsgType,
			ID:   thID,
		}))
		require.NoError(t, err)

		// handle Proposal msg (sends Request)
		go func() {
			_, err := svc.HandleInbound(ackMsg)
			require.NoError(t, err)
		}()

		checkStateMsg(t, sCh, service.PreState, AckMsgType, stateNameDone)
		checkStateMsg(t, sCh, service.PostState, AckMsgType, stateNameDone)
	})
}

// Skip proposal (The introducer has a public invitation)
func TestService_SkipProposal(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Introducer", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound).Times(1)
		store.EXPECT().Put(gomock.Any(), []byte(`{"StateName":"arranging","WaitCount":2}`)).Return(nil).Times(1)
		store.EXPECT().Get(gomock.Any()).Return([]byte(`{"StateName":"arranging","WaitCount":2}`), nil).Times(1)
		store.EXPECT().Put(gomock.Any(), []byte(`{"StateName":"delivering","WaitCount":1}`)).Return(nil).Times(1)
		store.EXPECT().Put(gomock.Any(), []byte(`{"StateName":"done","WaitCount":1}`)).Return(nil).Times(1)

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

		// register action event channel
		aCh := make(chan service.DIDCommAction)
		require.NoError(t, svc.RegisterActionEvent(aCh))

		// register action event channel
		sCh := make(chan service.StateMsg)
		require.NoError(t, svc.RegisterMsgEvent(sCh))

		// creates threadID
		thID := uuid.New().String()

		// creates skip proposal msg
		reqMsg, err := service.NewDIDCommMsg(toBytes(t, Proposal{
			Type: ProposalMsgType,
			ID:   thID,
		}))
		require.NoError(t, err)

		// handle outbound Proposal msg (sends Proposal)
		go func() { require.NoError(t, svc.HandleOutbound(reqMsg, &service.Destination{})) }()
		checkStateMsg(t, sCh, service.PreState, ProposalMsgType, stateNameArranging)
		checkStateMsg(t, sCh, service.PostState, ProposalMsgType, stateNameArranging)

		respMsg, err := service.NewDIDCommMsg(toBytes(t, Response{
			Type:   ResponseMsgType,
			ID:     uuid.New().String(),
			Thread: &decorator.Thread{ID: thID},
		}))
		require.NoError(t, err)

		// handle Response msg (receives Response)
		go func() {
			_, err := svc.HandleInbound(respMsg)
			require.NoError(t, err)
		}()

		dep := mocks.NewMockInvitationEnvelope(ctrl)
		dep.EXPECT().Destinations().Return([]*service.Destination{
			{ServiceEndpoint: "service/endpoint"},
		})

		continueAction(t, aCh, ResponseMsgType, dep)
		checkStateMsg(t, sCh, service.PreState, ResponseMsgType, stateNameDelivering)
		checkStateMsg(t, sCh, service.PostState, ResponseMsgType, stateNameDelivering)
		checkStateMsg(t, sCh, service.PreState, ResponseMsgType, stateNameDone)
		checkStateMsg(t, sCh, service.PostState, ResponseMsgType, stateNameDone)
	})

	t.Run("Introducee", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound).Times(1)
		store.EXPECT().Put(gomock.Any(), []byte(`{"StateName":"deciding","WaitCount":2}`)).Return(nil).Times(1)
		store.EXPECT().Put(gomock.Any(), []byte(`{"StateName":"waiting","WaitCount":2}`)).Return(nil).Times(1)

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

		// register action event channel
		aCh := make(chan service.DIDCommAction)
		require.NoError(t, svc.RegisterActionEvent(aCh))

		// register action event channel
		sCh := make(chan service.StateMsg)
		require.NoError(t, svc.RegisterMsgEvent(sCh))

		// creates threadID
		thID := uuid.New().String()

		// creates proposal msg
		reqMsg, err := service.NewDIDCommMsg(toBytes(t, Proposal{
			Type: ProposalMsgType,
			ID:   thID,
		}))
		require.NoError(t, err)

		// handle Proposal msg (sends Request)
		go func() {
			_, err := svc.HandleInbound(reqMsg)
			require.NoError(t, err)
		}()

		dep := mocks.NewMockInvitationEnvelope(ctrl)
		dep.EXPECT().Destinations().Return(nil)

		continueAction(t, aCh, ProposalMsgType, dep)
		checkStateMsg(t, sCh, service.PreState, ProposalMsgType, stateNameDeciding)
		checkStateMsg(t, sCh, service.PostState, ProposalMsgType, stateNameDeciding)
		checkStateMsg(t, sCh, service.PreState, ProposalMsgType, stateNameWaiting)
		checkStateMsg(t, sCh, service.PostState, ProposalMsgType, stateNameWaiting)
	})
}

func checkStateMsg(t *testing.T, ch chan service.StateMsg, sType service.StateMsgType, dType, stateID string) {
	select {
	case res := <-ch:
		require.Equal(t, sType, res.Type)
		require.Equal(t, dType, res.Msg.Header.Type)
		require.Equal(t, stateID, res.StateID)

		return
	case <-time.After(time.Second):
		t.Error("timeout")
	}
}

func continueAction(t *testing.T, ch chan service.DIDCommAction, action string, dep InvitationEnvelope) {
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
	require.NoError(t, s.Stop())
}
