/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/client/introduce/mocks"
	serviceMocks "github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service/mocks"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/introduce"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol"
	storageMocks "github.com/hyperledger/aries-framework-go/pkg/storage/mocks"
)

func TestNew(t *testing.T) {
	const errMsg = "test err"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("get service error", func(t *testing.T) {
		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(introduce.Introduce).Return(nil, errors.New(errMsg))
		_, err := New(provider)
		require.EqualError(t, err, errMsg)
	})

	t.Run("cast service error", func(t *testing.T) {
		provider := mocks.NewMockProvider(ctrl)
		_ = serviceMocks.NewMockDIDComm(ctrl)
		provider.EXPECT().Service(introduce.Introduce).Return(nil, nil)
		_, err := New(provider)
		require.EqualError(t, err, "cast service to Introduce Service failed")
	})

	t.Run("open store error", func(t *testing.T) {
		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(introduce.Introduce).Return(serviceMocks.NewMockDIDComm(ctrl), nil)
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(nil, errors.New(errMsg))
		provider.EXPECT().StorageProvider().Return(storageProvider)
		_, err := New(provider)
		require.EqualError(t, err, errMsg)
	})
}

func TestClient_SendProposal(t *testing.T) {
	svc, err := introduce.New(&protocol.MockProvider{})
	require.NoError(t, err)
	require.NotNil(t, svc)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocks.NewMockProvider(ctrl)
	DIDComm := serviceMocks.NewMockDIDComm(ctrl)
	DIDComm.EXPECT().HandleOutbound(gomock.Any(), gomock.Any()).Return(nil)
	provider.EXPECT().Service(introduce.Introduce).Return(DIDComm, nil)

	storageProvider := storageMocks.NewMockProvider(ctrl)
	storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(storageMocks.NewMockStore(ctrl), nil)
	provider.EXPECT().StorageProvider().Return(storageProvider)
	client, err := New(provider)
	require.NoError(t, err)
	require.NoError(t, client.SendProposal(nil, nil))
}

func TestClient_SendProposalWithInvitation(t *testing.T) {
	svc, err := introduce.New(&protocol.MockProvider{})
	require.NoError(t, err)
	require.NotNil(t, svc)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocks.NewMockProvider(ctrl)
	DIDComm := serviceMocks.NewMockDIDComm(ctrl)
	DIDComm.EXPECT().HandleOutbound(gomock.Any(), gomock.Any()).Return(nil)
	provider.EXPECT().Service(introduce.Introduce).Return(DIDComm, nil)

	storageProvider := storageMocks.NewMockProvider(ctrl)
	storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(storageMocks.NewMockStore(ctrl), nil)
	provider.EXPECT().StorageProvider().Return(storageProvider)
	client, err := New(provider)
	require.NoError(t, err)
	require.NoError(t, client.SendProposalWithInvitation(nil, nil))
}

func TestClient_HandleRequest(t *testing.T) {
	svc, err := introduce.New(&protocol.MockProvider{})
	require.NoError(t, err)
	require.NotNil(t, svc)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocks.NewMockProvider(ctrl)
	DIDComm := serviceMocks.NewMockDIDComm(ctrl)
	DIDComm.EXPECT().HandleOutbound(gomock.Any(), gomock.Any()).Return(nil)
	provider.EXPECT().Service(introduce.Introduce).Return(DIDComm, nil)

	storageProvider := storageMocks.NewMockProvider(ctrl)
	storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(storageMocks.NewMockStore(ctrl), nil)
	provider.EXPECT().StorageProvider().Return(storageProvider)
	client, err := New(provider)
	require.NoError(t, err)
	require.NoError(t, client.HandleRequest(nil, nil))
}

func TestClient_HandleRequestWithInvitation(t *testing.T) {
	svc, err := introduce.New(&protocol.MockProvider{})
	require.NoError(t, err)
	require.NotNil(t, svc)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocks.NewMockProvider(ctrl)
	DIDComm := serviceMocks.NewMockDIDComm(ctrl)
	DIDComm.EXPECT().HandleOutbound(gomock.Any(), gomock.Any()).Return(nil)
	provider.EXPECT().Service(introduce.Introduce).Return(DIDComm, nil)

	storageProvider := storageMocks.NewMockProvider(ctrl)
	storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(storageMocks.NewMockStore(ctrl), nil)
	provider.EXPECT().StorageProvider().Return(storageProvider)
	client, err := New(provider)
	require.NoError(t, err)
	require.NoError(t, client.HandleRequestWithInvitation(nil, nil))
}

func TestClient_SendRequest(t *testing.T) {
	svc, err := introduce.New(&protocol.MockProvider{})
	require.NoError(t, err)
	require.NotNil(t, svc)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocks.NewMockProvider(ctrl)
	DIDComm := serviceMocks.NewMockDIDComm(ctrl)
	DIDComm.EXPECT().HandleOutbound(gomock.Any(), gomock.Any()).Return(nil)
	provider.EXPECT().Service(introduce.Introduce).Return(DIDComm, nil)

	storageProvider := storageMocks.NewMockProvider(ctrl)
	storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(storageMocks.NewMockStore(ctrl), nil)
	provider.EXPECT().StorageProvider().Return(storageProvider)
	client, err := New(provider)
	require.NoError(t, err)
	require.NoError(t, client.SendRequest(nil))
}
