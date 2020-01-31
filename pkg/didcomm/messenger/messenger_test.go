/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package messenger_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messenger"
	dispatcherMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/dispatcher"
	messengerMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/messenger"
	storageMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/storage"
)

// makes sure it satisfies the interface
var _ service.MessengerHandler = (*messenger.Messenger)(nil)

func TestNewMessenger(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("success", func(t *testing.T) {
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(nil, nil)

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(nil)

		msgr, err := messenger.NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)
	})

	t.Run("open store error", func(t *testing.T) {
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(nil, errors.New("test error"))

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)

		msgr, err := messenger.NewMessenger(provider)
		require.Error(t, err)
		require.Nil(t, msgr)
	})
}

func TestMessenger_HandleInbound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("success", func(t *testing.T) {
		const ID = "ID"

		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Put(ID, gomock.Any()).Return(nil)

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(store, nil)

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(nil)

		msgr, err := messenger.NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)

		require.NoError(t, msgr.HandleInbound(service.DIDCommMsgMap{"@id": ID}, "myDID", "theirDID"))
	})

	t.Run("absent ID", func(t *testing.T) {
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(nil, nil)

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(nil)

		msgr, err := messenger.NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)

		err = msgr.HandleInbound(service.DIDCommMsgMap{}, "myDID", "theirDID")
		require.Contains(t, fmt.Sprintf("%v", err), "message-id is absent")
	})
}

func TestMessenger_Send(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	const (
		ID       = "ID"
		myDID    = "myDID"
		theirDID = "theirDID"
	)

	t.Run("success", func(t *testing.T) {
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(nil, nil)

		outbound := dispatcherMocks.NewMockOutbound(ctrl)
		outbound.EXPECT().SendToDID(gomock.Any(), myDID, theirDID).Return(nil)

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(outbound)

		msgr, err := messenger.NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)

		require.NoError(t, msgr.Send(service.DIDCommMsgMap{"@id": ID}, myDID, theirDID))
	})

	t.Run("success msg without id", func(t *testing.T) {
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(nil, nil)

		outbound := dispatcherMocks.NewMockOutbound(ctrl)
		outbound.EXPECT().
			SendToDID(gomock.Any(), myDID, theirDID).
			Do(func(msg interface{}, myDID, theirDID string) error {
				didMsg, ok := msg.(service.DIDCommMsgMap)
				require.True(t, ok)
				// checks that @id was injected
				require.NotNil(t, didMsg["@id"])
				return nil
			})

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(outbound)

		msgr, err := messenger.NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)

		// ~thread in the message causes a warning
		require.NoError(t, msgr.Send(service.DIDCommMsgMap{"~thread": ""}, myDID, theirDID))
	})
}

func TestMessenger_ReplyTo(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	const (
		ID     = "ID"
		errMsg = "test error"
	)

	t.Run("success", func(t *testing.T) {
		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get(ID).Return([]byte(`{}`), nil)

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(store, nil)

		outbound := dispatcherMocks.NewMockOutbound(ctrl)
		outbound.EXPECT().
			SendToDID(gomock.Any(), gomock.Any(), gomock.Any()).
			Do(func(msg interface{}, myDID, theirDID string) error {
				didMsg, ok := msg.(service.DIDCommMsgMap)
				require.True(t, ok)
				// checks that ~thread was injected
				require.NotNil(t, didMsg["~thread"])
				// checks that ~thread->thid was injected
				require.NotNil(t, didMsg["~thread"].(map[string]interface{})["thid"])
				return nil
			})

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(outbound)

		msgr, err := messenger.NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)
		require.NoError(t, msgr.ReplyTo(ID, service.DIDCommMsgMap{"@id": ID}))
	})

	t.Run("the message was not received", func(t *testing.T) {
		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get(ID).Return(nil, errors.New(errMsg))

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(store, nil)

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(nil)

		msgr, err := messenger.NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)

		err = msgr.ReplyTo(ID, service.DIDCommMsgMap{})
		require.Contains(t, fmt.Sprintf("%v", err), errMsg)
	})

	t.Run("success msg without id", func(t *testing.T) {
		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get(ID).Return([]byte(`{}`), nil)

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(store, nil)

		outbound := dispatcherMocks.NewMockOutbound(ctrl)
		outbound.EXPECT().
			SendToDID(gomock.Any(), gomock.Any(), gomock.Any()).
			Do(func(msg interface{}, myDID, theirDID string) error {
				didMsg, ok := msg.(service.DIDCommMsgMap)
				require.True(t, ok)
				// checks that @id was injected
				require.NotNil(t, didMsg["@id"])
				// checks that ~thread was injected
				require.NotNil(t, didMsg["~thread"])
				// checks that ~thread->thid was injected
				require.NotNil(t, didMsg["~thread"].(map[string]interface{})["thid"])
				return nil
			})

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(outbound)

		msgr, err := messenger.NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)
		// ~thread in the message causes a warning
		require.NoError(t, msgr.ReplyTo(ID, service.DIDCommMsgMap{"~thread": ""}))
	})
}

func TestMessenger_ReplyToNested(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	const (
		ID       = "ID"
		thID     = "thID"
		myDID    = "myDID"
		theirDID = "theirDID"
	)

	t.Run("success", func(t *testing.T) {
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(nil, nil)

		outbound := dispatcherMocks.NewMockOutbound(ctrl)
		outbound.EXPECT().
			SendToDID(gomock.Any(), myDID, theirDID).
			Do(func(msg interface{}, myDID, theirDID string) error {
				didMsg, ok := msg.(service.DIDCommMsgMap)
				require.True(t, ok)
				// checks that ~thread was injected
				require.NotNil(t, didMsg["~thread"])
				// checks that ~thread->thid was injected
				require.NotNil(t, didMsg["~thread"].(map[string]interface{})["pthid"])
				return nil
			})

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(outbound)

		msgr, err := messenger.NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)
		require.NoError(t, msgr.ReplyToNested(thID, service.DIDCommMsgMap{"@id": ID}, myDID, theirDID))
	})

	t.Run("success msg without id", func(t *testing.T) {
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(nil, nil)

		outbound := dispatcherMocks.NewMockOutbound(ctrl)
		outbound.EXPECT().
			SendToDID(gomock.Any(), myDID, theirDID).
			Do(func(msg interface{}, myDID, theirDID string) error {
				didMsg, ok := msg.(service.DIDCommMsgMap)
				require.True(t, ok)
				// checks that @id was injected
				require.NotNil(t, didMsg["@id"])
				// checks that ~thread was injected
				require.NotNil(t, didMsg["~thread"])
				// checks that ~thread->thid was injected
				require.NotNil(t, didMsg["~thread"].(map[string]interface{})["pthid"])
				return nil
			})

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(outbound)

		msgr, err := messenger.NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)
		// ~thread in the message causes a warning
		require.NoError(t, msgr.ReplyToNested(thID, service.DIDCommMsgMap{"~thread": ""}, myDID, theirDID))
	})
}
