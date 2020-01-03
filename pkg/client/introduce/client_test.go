/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	mocks "github.com/hyperledger/aries-framework-go/pkg/client/introduce/gomocks"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	serviceMocks "github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service/gomocks"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/introduce"
	introduceMocks "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/introduce/gomocks"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	storageMocks "github.com/hyperledger/aries-framework-go/pkg/storage/gomocks"
)

func TestNew(t *testing.T) {
	const errMsg = "test err"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("get service error", func(t *testing.T) {
		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(introduce.Introduce).Return(nil, errors.New(errMsg))
		_, err := New(provider, nil)
		require.EqualError(t, err, errMsg)
	})

	t.Run("cast service error", func(t *testing.T) {
		provider := mocks.NewMockProvider(ctrl)
		_ = serviceMocks.NewMockDIDComm(ctrl)
		provider.EXPECT().Service(introduce.Introduce).Return(nil, nil)
		_, err := New(provider, nil)
		require.EqualError(t, err, "cast service to Introduce Service failed")
	})

	t.Run("open store error", func(t *testing.T) {
		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(introduce.Introduce).Return(serviceMocks.NewMockDIDComm(ctrl), nil)
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(nil, errors.New(errMsg))
		provider.EXPECT().StorageProvider().Return(storageProvider)
		_, err := New(provider, nil)
		require.EqualError(t, err, errMsg)
	})
}

func TestClient_handleOutbound(t *testing.T) {
	t.Run("marshal outbound msg", func(t *testing.T) {
		c := &Client{}
		err := c.handleOutbound(make(chan int), InvitationEnvelope{})
		const errMsg = "marshal outbound msg: json: unsupported type: chan int"
		require.EqualError(t, err, errMsg)
	})

	t.Run("invalid payload data format", func(t *testing.T) {
		c := &Client{}
		err := c.handleOutbound([]int{}, InvitationEnvelope{})
		const errMsg = "invalid payload data format: json: cannot unmarshal array into Go value of type service.Header"
		require.EqualError(t, errors.Unwrap(err), errMsg)
	})

	t.Run("outbound threadID", func(t *testing.T) {
		c := &Client{}
		err := c.handleOutbound(struct{}{}, InvitationEnvelope{})
		const errMsg = "outbound threadID: invalid message"
		require.EqualError(t, err, errMsg)
	})
}

func TestClient_SendProposal(t *testing.T) {
	const UUID = "382a7cf8-2c57-4f2f-9359-8ac45b7b4b1f"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := storageMocks.NewMockStore(ctrl)

	storageProvider := storageMocks.NewMockProvider(ctrl)
	storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(store, nil).Times(2)

	didService := serviceMocks.NewMockDIDComm(ctrl)
	didService.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)

	introduceProvider := introduceMocks.NewMockProvider(ctrl)
	introduceProvider.EXPECT().StorageProvider().Return(storageProvider)
	introduceProvider.EXPECT().OutboundDispatcher().Return(nil)
	introduceProvider.EXPECT().Service(didexchange.DIDExchange).Return(didService, nil)

	svc, err := introduce.New(introduceProvider)
	require.NoError(t, err)
	require.NotNil(t, svc)

	DIDComm := serviceMocks.NewMockDIDComm(ctrl)
	DIDComm.EXPECT().HandleOutbound(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

	opts := InvitationEnvelope{
		Recps: []*introduce.Recipient{
			{MyDID: "My_DID1", TheirDID: "THEIR_DID1"},
			{MyDID: "My_DID2", TheirDID: "THEIR_DID2"},
		},
	}
	store.EXPECT().Put(invitationEnvelopePrefix+UUID, toBytes(t, opts)).Return(nil)

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(introduce.Introduce).Return(DIDComm, nil)
	provider.EXPECT().StorageProvider().Return(storageProvider)

	client, err := New(provider, nil)
	require.NoError(t, err)

	client.newUUID = func() string { return UUID }
	require.NoError(t, client.SendProposal(opts.Recps[0], opts.Recps[1]))
}

func TestClient_SendProposalWithInvitation(t *testing.T) {
	const UUID = "382a7cf8-2c57-4f2f-9359-8ac45b7b4b1f"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := storageMocks.NewMockStore(ctrl)

	storageProvider := storageMocks.NewMockProvider(ctrl)
	storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(store, nil).Times(2)

	didService := serviceMocks.NewMockDIDComm(ctrl)
	didService.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)

	introduceProvider := introduceMocks.NewMockProvider(ctrl)
	introduceProvider.EXPECT().StorageProvider().Return(storageProvider)
	introduceProvider.EXPECT().OutboundDispatcher().Return(nil)
	introduceProvider.EXPECT().Service(didexchange.DIDExchange).Return(didService, nil)

	svc, err := introduce.New(introduceProvider)
	require.NoError(t, err)
	require.NotNil(t, svc)

	DIDComm := serviceMocks.NewMockDIDComm(ctrl)
	DIDComm.EXPECT().HandleOutbound(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

	opts := InvitationEnvelope{
		Inv: &didexchange.Invitation{
			ID: UUID,
		},
		Recps: []*introduce.Recipient{
			{MyDID: "My_DID", TheirDID: "THEIR_DID"},
		},
	}
	store.EXPECT().Put(invitationEnvelopePrefix+UUID, toBytes(t, opts)).Return(nil)

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(introduce.Introduce).Return(DIDComm, nil)
	provider.EXPECT().StorageProvider().Return(storageProvider)

	client, err := New(provider, nil)
	require.NoError(t, err)

	client.newUUID = func() string { return UUID }
	require.NoError(t, client.SendProposalWithInvitation(opts.Inv, opts.Recps[0]))
}

func TestClient_HandleRequest(t *testing.T) {
	const UUID = "382a7cf8-2c57-4f2f-9359-8ac45b7b4b1f"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := storageMocks.NewMockStore(ctrl)

	storageProvider := storageMocks.NewMockProvider(ctrl)
	storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(store, nil).Times(2)

	didService := serviceMocks.NewMockDIDComm(ctrl)
	didService.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)

	introduceProvider := introduceMocks.NewMockProvider(ctrl)
	introduceProvider.EXPECT().StorageProvider().Return(storageProvider)
	introduceProvider.EXPECT().OutboundDispatcher().Return(nil)
	introduceProvider.EXPECT().Service(didexchange.DIDExchange).Return(didService, nil)

	svc, err := introduce.New(introduceProvider)
	require.NoError(t, err)
	require.NotNil(t, svc)

	opts := InvitationEnvelope{
		Recps: []*introduce.Recipient{
			{To: &introduce.To{Name: "Carol"}},
			{MyDID: "My_DID2", TheirDID: "THEIR_DID2"},
		},
	}
	store.EXPECT().Put(invitationEnvelopePrefix+UUID, toBytes(t, opts)).Return(nil)

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(introduce.Introduce).Return(serviceMocks.NewMockDIDComm(ctrl), nil)
	provider.EXPECT().StorageProvider().Return(storageProvider)

	client, err := New(provider, nil)
	require.NoError(t, err)

	client.newUUID = func() string { return UUID }

	msg, err := service.NewDIDCommMsg(toBytes(t, &introduce.Request{
		Type: introduce.RequestMsgType,
		ID:   UUID,
	}))
	require.NoError(t, err)
	require.NoError(t, client.HandleRequest(*msg, opts.Recps[0].To, opts.Recps[1]))

	// cover error case
	err = client.HandleRequest(service.DIDCommMsg{}, opts.Recps[0].To, opts.Recps[1])
	require.Equal(t, service.ErrInvalidMessage, errors.Unwrap(err))
}

func TestClient_HandleRequestWithInvitation(t *testing.T) {
	const UUID = "382a7cf8-2c57-4f2f-9359-8ac45b7b4b1f"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	opts := InvitationEnvelope{
		Inv: &didexchange.Invitation{
			ID: UUID,
		},
		Recps: []*introduce.Recipient{
			{To: &introduce.To{Name: "Carol"}},
		},
	}

	store := storageMocks.NewMockStore(ctrl)
	store.EXPECT().Put(invitationEnvelopePrefix+UUID, toBytes(t, opts)).Return(nil)

	storageProvider := storageMocks.NewMockProvider(ctrl)
	storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(store, nil)

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(introduce.Introduce).Return(serviceMocks.NewMockDIDComm(ctrl), nil)
	provider.EXPECT().StorageProvider().Return(storageProvider)

	client, err := New(provider, nil)
	require.NoError(t, err)

	client.newUUID = func() string { return UUID }

	require.NoError(t, err)
	msg, err := service.NewDIDCommMsg(toBytes(t, &introduce.Request{
		Type: introduce.RequestMsgType,
		ID:   UUID,
	}))
	require.NoError(t, err)
	require.NoError(t, client.HandleRequestWithInvitation(*msg, opts.Inv, opts.Recps[0].To))

	// cover error case
	err = client.HandleRequestWithInvitation(service.DIDCommMsg{}, opts.Inv, opts.Recps[0].To)
	require.Equal(t, service.ErrInvalidMessage, errors.Unwrap(err))
}

func TestClient_InvitationEnvelope(t *testing.T) {
	const UUID = "382a7cf8-2c57-4f2f-9359-8ac45b7b4b1f"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := storageMocks.NewMockStore(ctrl)

	storageProvider := storageMocks.NewMockProvider(ctrl)
	storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(store, nil).Times(2)

	didService := serviceMocks.NewMockDIDComm(ctrl)
	didService.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)

	introduceProvider := introduceMocks.NewMockProvider(ctrl)
	introduceProvider.EXPECT().StorageProvider().Return(storageProvider)
	introduceProvider.EXPECT().OutboundDispatcher().Return(nil)
	introduceProvider.EXPECT().Service(didexchange.DIDExchange).Return(didService, nil)

	svc, err := introduce.New(introduceProvider)
	require.NoError(t, err)
	require.NotNil(t, svc)

	opts := InvitationEnvelope{
		Inv: &didexchange.Invitation{
			ID: UUID,
		},
		Recps: []*introduce.Recipient{
			{To: &introduce.To{Name: "Carol"}, MyDID: "My_DID1", TheirDID: "THEIR_DID1"},
			{MyDID: "My_DID2", TheirDID: "THEIR_DID2"},
		},
	}
	store.EXPECT().Get(invitationEnvelopePrefix+UUID).Return(toBytes(t, opts), nil)
	store.EXPECT().Get(invitationEnvelopePrefix+UUID).Return(nil, errors.New("error"))
	store.EXPECT().Get(invitationEnvelopePrefix+UUID).Return([]byte(`[]`), nil)
	store.EXPECT().Get(invitationEnvelopePrefix+UUID).Return(nil, storage.ErrDataNotFound)

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(introduce.Introduce).Return(serviceMocks.NewMockDIDComm(ctrl), nil)
	provider.EXPECT().StorageProvider().Return(storageProvider)

	client, err := New(provider, nil)
	require.NoError(t, err)

	client.newUUID = func() string { return UUID }
	dependency := client.InvitationEnvelope(UUID)
	require.Equal(t, opts.Inv, dependency.Invitation())
	require.Equal(t, opts.Recps, dependency.Recipients())

	// with error
	dependency = client.InvitationEnvelope(UUID)
	require.Nil(t, dependency.Invitation())
	require.Nil(t, dependency.Recipients())

	// with error
	dependency = client.InvitationEnvelope(UUID)
	require.Nil(t, dependency.Invitation())
	require.Nil(t, dependency.Recipients())

	// with error (storageMocks.ErrDataNotFound)
	dependency = client.InvitationEnvelope(UUID)
	require.Nil(t, dependency.Invitation())
	require.Nil(t, dependency.Recipients())
}

func TestClient_SendRequest(t *testing.T) {
	const UUID = "382a7cf8-2c57-4f2f-9359-8ac45b7b4b1f"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := storageMocks.NewMockStore(ctrl)

	storageProvider := storageMocks.NewMockProvider(ctrl)
	storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(store, nil).Times(2)

	didService := serviceMocks.NewMockDIDComm(ctrl)
	didService.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)

	introduceProvider := introduceMocks.NewMockProvider(ctrl)
	introduceProvider.EXPECT().StorageProvider().Return(storageProvider)
	introduceProvider.EXPECT().OutboundDispatcher().Return(nil)
	introduceProvider.EXPECT().Service(didexchange.DIDExchange).Return(didService, nil)

	svc, err := introduce.New(introduceProvider)
	require.NoError(t, err)
	require.NotNil(t, svc)

	opts := InvitationEnvelope{
		Recps: []*introduce.Recipient{
			{MyDID: "My_DID", TheirDID: "THEIR_DID"},
		},
	}

	DIDComm := serviceMocks.NewMockDIDComm(ctrl)
	DIDComm.EXPECT().HandleOutbound(gomock.Any(), opts.Recps[0].MyDID, opts.Recps[0].TheirDID).Return(nil)

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(introduce.Introduce).Return(DIDComm, nil)
	provider.EXPECT().StorageProvider().Return(storageProvider)

	client, err := New(provider, nil)
	require.NoError(t, err)

	client.newUUID = func() string { return UUID }
	require.NoError(t, client.SendRequest(nil, opts.Recps[0].MyDID, opts.Recps[0].TheirDID))
}

func toBytes(t *testing.T, v interface{}) []byte {
	t.Helper()

	res, err := json.Marshal(v)
	require.NoError(t, err)

	return res
}
