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
	storageMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	ID       = "ID"
	myDID    = "myDID"
	theirDID = "theirDID"
	errMsg   = "test error"
)

// makes sure it satisfies the interface
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
		store.EXPECT().Get(gomock.Any()).Return([]byte(`{}`), nil)

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(store, nil)

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(nil)

		msgr, err := NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)

		require.NoError(t, msgr.HandleInbound(service.DIDCommMsgMap{jsonID: ID}, myDID, theirDID))
	})

	t.Run("success without metadata", func(t *testing.T) {
		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Put(ID, gomock.Any()).Return(nil)
		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound)

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(store, nil)

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(nil)

		msgr, err := NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)

		require.NoError(t, msgr.HandleInbound(service.DIDCommMsgMap{jsonID: ID}, myDID, theirDID))
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

		err = msgr.HandleInbound(service.DIDCommMsgMap{}, myDID, theirDID)
		require.Contains(t, fmt.Sprintf("%v", err), "message-id is absent")
	})

	t.Run("metadata with error", func(t *testing.T) {
		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get(gomock.Any()).Return(nil, errors.New(errMsg))

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(store, nil)

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(nil)

		msgr, err := NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)

		err = msgr.HandleInbound(service.DIDCommMsgMap{jsonID: ID}, myDID, theirDID)
		require.Contains(t, fmt.Sprintf("%v", err), errMsg)
	})

	t.Run("success with metadata", func(t *testing.T) {
		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Put(ID, gomock.Any()).Return(nil)
		store.EXPECT().Get(gomock.Any()).Return([]byte(`{"Metadata":{"key":"val"}}`), nil)

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(store, nil)

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(nil)

		msgr, err := NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)

		msg := service.DIDCommMsgMap{jsonID: ID, jsonThread: map[string]interface{}{jsonThreadID: "thID"}}
		require.NoError(t, msgr.HandleInbound(msg, myDID, theirDID))

		v := struct {
			service.Metadata `json:",squash"` // nolint: staticcheck
			Thread           decorator.Thread `json:"~thread"`
		}{}

		require.NoError(t, msg.Decode(&v))
		require.Equal(t, "val", v.Payload["key"])
	})

	t.Run("success with metadata (thread is nil)", func(t *testing.T) {
		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Put(ID, gomock.Any()).Return(nil)
		store.EXPECT().Get(gomock.Any()).Return([]byte(`{"Metadata":{"key":"val"}}`), nil)

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(store, nil)

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(nil)

		msgr, err := NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)

		msg := service.DIDCommMsgMap{jsonID: ID}
		require.NoError(t, msgr.HandleInbound(msg, myDID, theirDID))

		v := struct {
			service.Metadata `json:",squash"` // nolint: staticcheck
			Thread           decorator.Thread `json:"~thread"`
		}{}

		require.NoError(t, msg.Decode(&v))
		require.Equal(t, "val", v.Payload["key"])
	})
}

func sendToDIDCheck(t *testing.T, checks ...string) func(msg service.DIDCommMsgMap, myDID, theirDID string) error {
	return func(msg service.DIDCommMsgMap, myDID, theirDID string) error {
		v := struct {
			service.Metadata `json:",squash"` // nolint: staticcheck
			ID               string           `json:"@id"`
			Thread           decorator.Thread `json:"~thread"`
		}{}

		require.NoError(t, msg.Decode(&v))

		for _, check := range checks {
			switch check {
			case jsonMetadata:
				// metadata always should be absent
				require.Nil(t, v.Payload)
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

	t.Run("success", func(t *testing.T) {
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(nil, nil)

		outbound := dispatcherMocks.NewMockOutbound(ctrl)
		outbound.EXPECT().SendToDID(gomock.Any(), myDID, theirDID).
			Do(sendToDIDCheck(t, jsonID, jsonMetadata))

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(outbound)

		msgr, err := NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)

		require.NoError(t, msgr.Send(service.DIDCommMsgMap{jsonID: ID}, myDID, theirDID))
	})

	t.Run("success msg without id", func(t *testing.T) {
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(nil, nil)

		outbound := dispatcherMocks.NewMockOutbound(ctrl)
		outbound.EXPECT().SendToDID(gomock.Any(), myDID, theirDID).
			Do(sendToDIDCheck(t, jsonID, jsonMetadata))

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(outbound)

		msgr, err := NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)

		// ~thread in the message causes a warning
		require.NoError(t, msgr.Send(service.DIDCommMsgMap{jsonThread: map[string]interface{}{}}, myDID, theirDID))
	})

	t.Run("save metadata error", func(t *testing.T) {
		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Put(gomock.Any(), gomock.Any()).Return(errors.New(errMsg))

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(store, nil)

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(nil)

		msgr, err := NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)

		// ~thread in the message causes a warning
		err = msgr.Send(service.DIDCommMsgMap{
			jsonMetadata: map[string]interface{}{"key": "val"},
		}, myDID, theirDID)
		require.Contains(t, fmt.Sprintf("%v", err), errMsg)
	})
}

func TestMessenger_ReplyTo(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("success", func(t *testing.T) {
		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get(ID).Return([]byte(`{"ThreadID":"thID"}`), nil)

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(store, nil)

		outbound := dispatcherMocks.NewMockOutbound(ctrl)
		outbound.EXPECT().SendToDID(gomock.Any(), gomock.Any(), gomock.Any()).
			Do(sendToDIDCheck(t, jsonID, jsonMetadata, jsonThreadID))

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
		store.EXPECT().Get(ID).Return([]byte(`{"ThreadID":"thID"}`), nil)

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(store, nil)

		outbound := dispatcherMocks.NewMockOutbound(ctrl)
		outbound.EXPECT().SendToDID(gomock.Any(), gomock.Any(), gomock.Any()).
			Do(sendToDIDCheck(t, jsonID, jsonMetadata, jsonThreadID))

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(outbound)

		msgr, err := NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)
		// ~thread in the message causes a warning
		require.NoError(t, msgr.ReplyTo(ID, service.DIDCommMsgMap{jsonThread: map[string]interface{}{}}))
	})

	t.Run("save metadata error", func(t *testing.T) {
		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get(ID).Return([]byte(`{"ThreadID":"thID"}`), nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any()).Return(errors.New(errMsg))

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(store, nil)

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(nil)

		msgr, err := NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)

		// ~thread in the message causes a warning
		err = msgr.ReplyTo(ID, service.DIDCommMsgMap{
			jsonMetadata: map[string]interface{}{"key": "val"},
		})
		require.Contains(t, fmt.Sprintf("%v", err), errMsg)
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
			Do(sendToDIDCheck(t, jsonID, jsonMetadata, jsonParentThreadID))

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(outbound)

		msgr, err := NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)
		require.NoError(t, msgr.ReplyToNested(thID, service.DIDCommMsgMap{jsonID: ID}, myDID, theirDID))
	})

	t.Run("success msg without id", func(t *testing.T) {
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(nil, nil)

		outbound := dispatcherMocks.NewMockOutbound(ctrl)
		outbound.EXPECT().SendToDID(gomock.Any(), gomock.Any(), gomock.Any()).
			Do(sendToDIDCheck(t, jsonID, jsonMetadata, jsonParentThreadID))

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(outbound)

		msgr, err := NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)
		// ~thread in the message causes a warning
		require.NoError(t, msgr.ReplyToNested(thID, service.DIDCommMsgMap{
			jsonThread: map[string]interface{}{},
		}, myDID, theirDID))
	})

	t.Run("save metadata error", func(t *testing.T) {
		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Put(gomock.Any(), gomock.Any()).Return(errors.New(errMsg))

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(store, nil)

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(nil)

		msgr, err := NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)

		// ~thread in the message causes a warning
		err = msgr.ReplyToNested("thID", service.DIDCommMsgMap{
			jsonMetadata: map[string]interface{}{"key": "val"},
		}, myDID, theirDID)
		require.Contains(t, fmt.Sprintf("%v", err), errMsg)
	})
}
