/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package messenger

import (
	"errors"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	dispatcherMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/dispatcher"
	messengerMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/messenger"
	storageMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/spi/storage"
)

const (
	ID       = "ID"
	myDID    = "myDID"
	theirDID = "theirDID"
	msgID    = "msgID"
	errMsg   = "test error"

	jsonID             = "@id"
	jsonThread         = "~thread"
	jsonThreadID       = "thid"
	jsonParentThreadID = "pthid"
)

// makes sure it satisfies the interface.
var _ service.MessengerHandler = (*Messenger)(nil)

func TestNewMessenger(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("success", func(t *testing.T) {
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(nil, nil)

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(nil)

		msgr, err := NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)
	})

	t.Run("open store error", func(t *testing.T) {
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(nil, errors.New("test error"))

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)

		msgr, err := NewMessenger(provider)
		require.Error(t, err)
		require.Nil(t, msgr)
	})
}

func TestMessenger_HandleInbound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("success", func(t *testing.T) {
		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Put(ID, gomock.Any()).Return(nil)

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(store, nil)

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(nil)

		msgr, err := NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)

		require.NoError(t,
			msgr.HandleInbound(service.DIDCommMsgMap{jsonID: ID}, service.NewDIDCommContext(myDID, theirDID, nil)))
	})

	t.Run("absent ID", func(t *testing.T) {
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(nil, nil)

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(nil)

		msgr, err := NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)

		err = msgr.HandleInbound(service.DIDCommMsgMap{}, service.NewDIDCommContext(myDID, theirDID, nil))
		require.Contains(t, fmt.Sprintf("%v", err), "message-id is absent")
	})
}

func sendToDIDCheck(t *testing.T, checks ...string) func(msg service.DIDCommMsgMap, myDID, theirDID string) error {
	return func(msg service.DIDCommMsgMap, myDID, theirDID string) error {
		v := struct {
			ID     string           `json:"@id"`
			Thread decorator.Thread `json:"~thread"`
		}{}

		require.NoError(t, msg.Decode(&v))

		for _, check := range checks {
			switch check {
			case jsonID:
				// ID always should be in the message
				require.NotEmpty(t, v.ID)
			case jsonThreadID:
				require.NotEmpty(t, v.Thread.ID)
			case jsonParentThreadID:
				require.NotEmpty(t, v.Thread.PID)
			}
		}

		return nil
	}
}

func TestMessenger_Send(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("send success", func(t *testing.T) {
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(nil, nil)

		outbound := dispatcherMocks.NewMockOutbound(ctrl)
		outbound.EXPECT().SendToDID(gomock.Any(), myDID, theirDID).
			Do(sendToDIDCheck(t, jsonID))

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(outbound)

		msgr, err := NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)

		require.NoError(t, msgr.Send(service.DIDCommMsgMap{jsonID: ID}, myDID, theirDID))
	})

	t.Run("send to destination success", func(t *testing.T) {
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(nil, nil)

		outbound := dispatcherMocks.NewMockOutbound(ctrl)
		outbound.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil)

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(outbound)

		msgr, err := NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)

		require.NoError(t, msgr.SendToDestination(service.DIDCommMsgMap{jsonID: ID}, "", &service.Destination{}))
	})

	t.Run("success msg without id", func(t *testing.T) {
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(nil, nil)

		outbound := dispatcherMocks.NewMockOutbound(ctrl)
		outbound.EXPECT().SendToDID(gomock.Any(), myDID, theirDID).
			Do(sendToDIDCheck(t, jsonID))

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(outbound)

		msgr, err := NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)

		require.NoError(t, msgr.Send(service.DIDCommMsgMap{}, myDID, theirDID))
	})
}

func TestMessenger_ReplyTo(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("success", func(t *testing.T) {
		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get(ID).Return([]byte(`{"thread_id":"thID","parent_thread_id":"pthID"}`), nil)

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(store, nil)

		outbound := dispatcherMocks.NewMockOutbound(ctrl)
		outbound.EXPECT().SendToDID(gomock.Any(), gomock.Any(), gomock.Any()).
			Do(sendToDIDCheck(t, jsonID, jsonThreadID, jsonParentThreadID))

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(outbound)

		msgr, err := NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)
		require.NoError(t, msgr.ReplyTo(ID, service.DIDCommMsgMap{jsonID: ID}))
	})

	t.Run("the message was not received", func(t *testing.T) {
		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get(ID).Return(nil, errors.New(errMsg))

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(store, nil)

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(nil)

		msgr, err := NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)

		err = msgr.ReplyTo(ID, service.DIDCommMsgMap{})
		require.Contains(t, fmt.Sprintf("%v", err), errMsg)
	})

	t.Run("success msg without id", func(t *testing.T) {
		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get(ID).Return([]byte(`{"thread_id":"thID"}`), nil)

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(store, nil)

		outbound := dispatcherMocks.NewMockOutbound(ctrl)
		outbound.EXPECT().SendToDID(gomock.Any(), gomock.Any(), gomock.Any()).
			Do(sendToDIDCheck(t, jsonID, jsonThreadID))

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(outbound)

		msgr, err := NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)

		require.NoError(t, msgr.ReplyTo(ID, service.DIDCommMsgMap{}))
	})
}

func TestMessenger_ReplyToNested(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	const thID = "thID"

	t.Run("success", func(t *testing.T) {
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(nil, nil)

		outbound := dispatcherMocks.NewMockOutbound(ctrl)
		outbound.EXPECT().SendToDID(gomock.Any(), gomock.Any(), gomock.Any()).
			Do(sendToDIDCheck(t, jsonID, jsonParentThreadID))

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(outbound)

		msgr, err := NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)
		require.NoError(t, msgr.ReplyToNested(service.DIDCommMsgMap{jsonID: ID},
			&service.NestedReplyOpts{ThreadID: thID, TheirDID: theirDID, MyDID: myDID}))
	})

	t.Run("success with msgID option", func(t *testing.T) {
		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get(msgID).Return([]byte(`{"my_did":"myDID","their_did":"theirDID","thread_id":"theirDID"}`), nil)

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(store, nil)

		outbound := dispatcherMocks.NewMockOutbound(ctrl)
		outbound.EXPECT().SendToDID(gomock.Any(), gomock.Any(), gomock.Any()).
			Do(sendToDIDCheck(t, jsonID, jsonParentThreadID))

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(outbound)

		msgr, err := NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)
		require.NoError(t, msgr.ReplyToNested(service.DIDCommMsgMap{jsonID: ID},
			&service.NestedReplyOpts{MsgID: msgID}))
	})

	t.Run("success msg without id", func(t *testing.T) {
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(nil, nil)

		outbound := dispatcherMocks.NewMockOutbound(ctrl)
		outbound.EXPECT().SendToDID(gomock.Any(), gomock.Any(), gomock.Any()).
			Do(sendToDIDCheck(t, jsonID, jsonParentThreadID))

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(outbound)

		msgr, err := NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)

		require.NoError(t, msgr.ReplyToNested(service.DIDCommMsgMap{},
			&service.NestedReplyOpts{ThreadID: thID, TheirDID: theirDID, MyDID: myDID}))
	})

	t.Run("failure with message ID issues", func(t *testing.T) {
		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get(msgID).Return(nil, errors.New(errMsg))

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(store, nil)

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(dispatcherMocks.NewMockOutbound(ctrl))

		msgr, err := NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)

		err = msgr.ReplyToNested(service.DIDCommMsgMap{jsonID: ID},
			&service.NestedReplyOpts{MsgID: msgID})
		require.Contains(t, err.Error(), errMsg)
	})
}

func TestMessenger_ReplyToMsg(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("success", func(t *testing.T) {
		outbound := dispatcherMocks.NewMockOutbound(ctrl)
		outbound.EXPECT().SendToDID(gomock.Any(), gomock.Any(), gomock.Any()).
			Do(sendToDIDCheck(t, jsonID, jsonThreadID, jsonParentThreadID))

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(nil, nil)

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(outbound)

		msgr, err := NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)
		require.NoError(t, msgr.ReplyToMsg(service.DIDCommMsgMap{
			jsonID:     "id",
			jsonThread: map[string]interface{}{jsonThreadID: "thID", jsonParentThreadID: "pthID"},
		}, service.DIDCommMsgMap{}, "", ""))
	})

	t.Run("success msg without id", func(t *testing.T) {
		outbound := dispatcherMocks.NewMockOutbound(ctrl)
		outbound.EXPECT().SendToDID(gomock.Any(), gomock.Any(), gomock.Any()).
			Do(sendToDIDCheck(t, jsonID, jsonThreadID))

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(nil, nil)

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(outbound)

		msgr, err := NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)

		require.NoError(t, msgr.ReplyToMsg(service.DIDCommMsgMap{
			jsonID:     "id",
			jsonThread: map[string]interface{}{jsonThreadID: "thID"},
		}, service.DIDCommMsgMap{}, "", ""))
	})

	t.Run("invalid message", func(t *testing.T) {
		outbound := dispatcherMocks.NewMockOutbound(ctrl)

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(nil, nil)

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(outbound)

		msgr, err := NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)

		require.EqualError(t, msgr.ReplyToMsg(service.DIDCommMsgMap{
			jsonThread: map[string]interface{}{jsonThreadID: "thID"},
		}, service.DIDCommMsgMap{}, "", ""), "get threadID: invalid message")
	})
}
