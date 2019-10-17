/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
)

// this line checks that Service satisfies service.Handler interface
var _ service.Handler = &Service{}

func TestService_New(t *testing.T) {
	const errMsg = "test err"
	store := mockstore.NewMockStoreProvider()
	store.ErrOpenStoreHandle = errors.New(errMsg)
	svc, err := New(store)
	require.EqualError(t, err, "test err")
	require.Nil(t, svc)
}

func TestService_Action(t *testing.T) {
	store := mockstore.NewMockStoreProvider()
	svc, err := New(store)
	require.NoError(t, err)
	ch := make(chan<- service.DIDCommAction)

	// by default
	require.Nil(t, svc.GetActionEvent())

	// register action event
	require.Nil(t, svc.RegisterActionEvent(ch))
	require.Equal(t, ch, svc.GetActionEvent())

	// unregister action event
	require.Nil(t, svc.UnregisterActionEvent(ch))
	require.Nil(t, svc.GetActionEvent())
}

func TestService_Message(t *testing.T) {
	store := mockstore.NewMockStoreProvider()
	svc, err := New(store)
	require.NoError(t, err)
	ch := make(chan<- service.StateMsg)

	// by default
	require.Nil(t, svc.GetMsgEvents())

	// register message event
	require.Nil(t, svc.RegisterMsgEvent(ch))
	require.Equal(t, ch, svc.GetMsgEvents()[0])

	// unregister message event
	require.Nil(t, svc.UnregisterMsgEvent(ch))
	require.Equal(t, 0, len(svc.GetMsgEvents()))
}

func TestService_Name(t *testing.T) {
	store := mockstore.NewMockStoreProvider()
	svc, err := New(store)
	require.NoError(t, err)
	require.Equal(t, Introduce, svc.Name())
}

func TestService_HandleOutbound(t *testing.T) {
	store := mockstore.NewMockStoreProvider()
	svc, err := New(store)
	require.NoError(t, err)
	msg, err := service.NewDIDCommMsg([]byte(fmt.Sprintf(`{"@id":"ID","@type":%q}`, ResponseMsgType)))
	require.NoError(t, err)
	require.EqualError(t, svc.HandleOutbound(msg, nil), "not implemented yet")
}

func TestService_HandleInbound(t *testing.T) {
	t.Parallel()

	t.Run("No clients", func(t *testing.T) {
		store := mockstore.NewMockStoreProvider()
		svc, err := New(store)
		require.NoError(t, err)
		require.EqualError(t, svc.HandleInbound(&service.DIDCommMsg{}), "no clients are registered to handle the message")
	})

	t.Run("ThreadID Error", func(t *testing.T) {
		store := mockstore.NewMockStoreProvider()
		svc, err := New(store)
		require.NoError(t, err)
		msg, err := service.NewDIDCommMsg([]byte(`{}`))
		require.NoError(t, err)
		ch := make(chan service.DIDCommAction)
		require.NoError(t, svc.RegisterActionEvent(ch))
		require.EqualError(t, svc.HandleInbound(msg), service.ErrThreadIDNotFound.Error())
	})

	t.Run("Storage error", func(t *testing.T) {
		const errMsg = "test err"
		store := mockstore.NewMockStoreProvider()
		store.Store.ErrGet = errors.New(errMsg)
		require.NoError(t, store.Store.Put("ID", nil))
		svc, err := New(store)
		require.NoError(t, err)
		msg, err := service.NewDIDCommMsg([]byte(fmt.Sprintf(`{"@id":"ID","@type":%q}`, ProposalMsgType)))
		require.NoError(t, err)
		ch := make(chan service.DIDCommAction)
		require.NoError(t, svc.RegisterActionEvent(ch))
		require.EqualError(t, svc.HandleInbound(msg), "cannot fetch state from store: thid=ID err=test err")
	})

	t.Run("Bad transition", func(t *testing.T) {
		store := mockstore.NewMockStoreProvider()
		require.NoError(t, store.Store.Put("ID", []byte(stateNameNoop)))
		svc, err := New(store)
		require.NoError(t, err)
		msg, err := service.NewDIDCommMsg([]byte(fmt.Sprintf(`{"@id":"ID","@type":%q}`, ProposalMsgType)))
		require.NoError(t, err)
		ch := make(chan service.DIDCommAction)
		require.NoError(t, svc.RegisterActionEvent(ch))
		require.EqualError(t, svc.HandleInbound(msg), "invalid state transition: noop -> arranging")
	})

	t.Run("Unknown msg type error", func(t *testing.T) {
		store := mockstore.NewMockStoreProvider()
		svc, err := New(store)
		require.NoError(t, err)
		msg, err := service.NewDIDCommMsg([]byte(`{"@id":"ID","@type":"unknown"}`))
		require.NoError(t, err)
		ch := make(chan service.DIDCommAction)
		require.NoError(t, svc.RegisterActionEvent(ch))
		require.EqualError(t, svc.HandleInbound(msg), "unrecognized msgType: unknown")
	})

	t.Run("Happy path (send an action event)", func(t *testing.T) {
		store := mockstore.NewMockStoreProvider()
		svc, err := New(store)
		require.NoError(t, err)
		msg, err := service.NewDIDCommMsg([]byte(fmt.Sprintf(`{"@id":"ID","@type":%q}`, ProposalMsgType)))
		require.NoError(t, err)
		aCh := make(chan service.DIDCommAction)
		require.NoError(t, svc.RegisterActionEvent(aCh))
		sCh := make(chan service.StateMsg)
		require.NoError(t, svc.RegisterMsgEvent(sCh))
		go func() { require.NoError(t, svc.HandleInbound(msg)) }()

		select {
		case <-sCh:
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Happy path (execute handle)", func(t *testing.T) {
		store := mockstore.NewMockStoreProvider()
		svc, err := New(store)
		require.NoError(t, err)
		msg, err := service.NewDIDCommMsg([]byte(fmt.Sprintf(`{"@id":"ID","@type":%q}`, ResponseMsgType)))
		require.NoError(t, err)
		ch := make(chan service.DIDCommAction)
		require.NoError(t, svc.RegisterActionEvent(ch))
		require.EqualError(t, svc.HandleInbound(msg), "not implemented yet")
	})
}

func TestService_Accept(t *testing.T) {
	store := mockstore.NewMockStoreProvider()
	svc, err := New(store)
	require.NoError(t, err)
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
