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

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	dispatcherMocks "github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher/gomocks"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	mocks "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/introduce/gomocks"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	storageMocks "github.com/hyperledger/aries-framework-go/pkg/storage/gomocks"
)

const (
	Alice = "Alice"
	Bob   = "Bob"
	Carol = "Carol"
)

// this line checks that Service satisfies service.Handler interface
var _ service.Handler = &Service{}

type flow struct {
	t            *testing.T
	wg           *sync.WaitGroup
	svc          *Service
	expectedInv  *didexchange.Invitation
	inv          *didexchange.Invitation
	transportKey string
	transport    map[string]chan interface{}
	dependency   InvitationEnvelope
	destinations []*service.Destination
	withRequest  bool
	skipProposal bool
	withProposal bool
	withError    bool
}

func TestService_handle(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	storageProvider := storageMocks.NewMockProvider(ctrl)
	storageProvider.EXPECT().OpenStore(Introduce).Return(nil, nil)

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().StorageProvider().Return(storageProvider)
	provider.EXPECT().OutboundDispatcher().Return(nil)
	provider.EXPECT().Service(didexchange.DIDExchange).Return(mocks.NewMockForwarder(ctrl), nil)

	svc, err := New(provider)
	require.NoError(t, err)

	defer stop(t, svc)

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

	t.Run("OpenStore Error", func(t *testing.T) {
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(Introduce).Return(nil, errors.New(errMsg))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)

		svc, err := New(provider)
		require.EqualError(t, err, "test err")
		require.Nil(t, svc)
	})

	t.Run("Service Error", func(t *testing.T) {
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(Introduce).Return(nil, nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().Service(didexchange.DIDExchange).Return(nil, errors.New(errMsg))

		svc, err := New(provider)
		require.EqualError(t, err, "test err")
		require.Nil(t, svc)
	})

	t.Run("Cast Service Error", func(t *testing.T) {
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(Introduce).Return(nil, nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().Service(didexchange.DIDExchange).Return(nil, nil)

		svc, err := New(provider)
		require.EqualError(t, err, "cast service to forwarder service failed")
		require.Nil(t, svc)
	})
}

func TestService_Stop(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	storageProvider := storageMocks.NewMockProvider(ctrl)
	storageProvider.EXPECT().OpenStore(Introduce).Return(nil, nil)

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().StorageProvider().Return(storageProvider)
	provider.EXPECT().OutboundDispatcher().Return(nil)
	provider.EXPECT().Service(didexchange.DIDExchange).Return(mocks.NewMockForwarder(ctrl), nil)

	svc, err := New(provider)
	require.NoError(t, err)

	require.NoError(t, svc.Stop())
	require.EqualError(t, svc.Stop(), "server was already stopped")
}

func TestService_Abandoning(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	storageProvider := storageMocks.NewMockProvider(ctrl)
	storageProvider.EXPECT().OpenStore(Introduce).Return(fakeStore(ctrl), nil)

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().StorageProvider().Return(storageProvider)
	provider.EXPECT().OutboundDispatcher().Return(nil)
	provider.EXPECT().Service(didexchange.DIDExchange).Return(mocks.NewMockForwarder(ctrl), nil)

	svc, err := New(provider)
	require.NoError(t, err)

	msg, err := service.NewDIDCommMsg(toBytes(t, &model.Ack{
		Type: AckMsgType,
		ID:   uuid.New().String(),
	}))
	require.NoError(t, err)

	_, err = msg.ThreadID()
	require.NoError(t, err)

	// register action event channel
	sCh := make(chan service.StateMsg)
	require.NoError(t, svc.RegisterMsgEvent(sCh))

	go func() {
		aMsg := svc.newDIDCommActionMsg(&metaData{Msg: msg})
		aMsg.Stop(errors.New("test error"))
	}()

	checkStateMsg(t, sCh, service.PreState, AckMsgType, stateNameAbandoning)
	checkStateMsg(t, sCh, service.PostState, AckMsgType, stateNameAbandoning)
	checkStateMsg(t, sCh, service.PreState, AckMsgType, stateNameDone)
	checkStateMsg(t, sCh, service.PostState, AckMsgType, stateNameDone)

	require.NoError(t, svc.Stop())
	require.EqualError(t, svc.Stop(), "server was already stopped")
}

func TestService_Name(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	storageProvider := storageMocks.NewMockProvider(ctrl)
	storageProvider.EXPECT().OpenStore(Introduce).Return(nil, nil)

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().StorageProvider().Return(storageProvider)
	provider.EXPECT().OutboundDispatcher().Return(nil)
	provider.EXPECT().Service(didexchange.DIDExchange).Return(mocks.NewMockForwarder(ctrl), nil)

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
		provider.EXPECT().Service(didexchange.DIDExchange).Return(mocks.NewMockForwarder(ctrl), nil)

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
		provider.EXPECT().Service(didexchange.DIDExchange).Return(mocks.NewMockForwarder(ctrl), nil)

		svc, err := New(provider)

		require.NoError(t, err)
		defer stop(t, svc)
		msg, err := service.NewDIDCommMsg([]byte(fmt.Sprintf(`{"@id":"ID","@type":%q}`, ProposalMsgType)))
		require.NoError(t, err)
		ch := make(chan service.DIDCommAction)
		require.NoError(t, svc.RegisterActionEvent(ch))
		require.EqualError(t, svc.HandleOutbound(msg, &service.Destination{}), "invalid state transition: noop -> arranging")
	})
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
		provider.EXPECT().Service(didexchange.DIDExchange).Return(mocks.NewMockForwarder(ctrl), nil)

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
		provider.EXPECT().Service(didexchange.DIDExchange).Return(mocks.NewMockForwarder(ctrl), nil)

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
		provider.EXPECT().Service(didexchange.DIDExchange).Return(mocks.NewMockForwarder(ctrl), nil)

		svc, err := New(provider)
		require.NoError(t, err)
		defer stop(t, svc)
		msg, err := service.NewDIDCommMsg([]byte(fmt.Sprintf(`{"@id":"ID","@type":%q}`, ProposalMsgType)))
		require.NoError(t, err)
		ch := make(chan service.DIDCommAction)
		require.NoError(t, svc.RegisterActionEvent(ch))

		_, err = svc.HandleInbound(msg)
		require.EqualError(t, err, "cannot fetch state from store: thid=ID : test err")
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
		provider.EXPECT().Service(didexchange.DIDExchange).Return(mocks.NewMockForwarder(ctrl), nil)

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
		provider.EXPECT().Service(didexchange.DIDExchange).Return(mocks.NewMockForwarder(ctrl), nil)

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
}

func TestService_Accept(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	storageProvider := storageMocks.NewMockProvider(ctrl)
	storageProvider.EXPECT().OpenStore(Introduce).Return(nil, nil)

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().StorageProvider().Return(storageProvider)
	provider.EXPECT().OutboundDispatcher().Return(nil)
	provider.EXPECT().Service(didexchange.DIDExchange).Return(mocks.NewMockForwarder(ctrl), nil)

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
	st := stateFromName(stateNameNoop)
	require.Equal(t, &noOp{}, st)

	st = stateFromName(stateNameStart)
	require.Equal(t, &start{}, st)

	st = stateFromName(stateNameDone)
	require.Equal(t, &done{}, st)

	st = stateFromName(stateNameArranging)
	require.Equal(t, &arranging{}, st)

	st = stateFromName(stateNameDelivering)
	require.Equal(t, &delivering{}, st)

	st = stateFromName(stateNameConfirming)
	require.Equal(t, &confirming{}, st)

	st = stateFromName(stateNameAbandoning)
	require.Equal(t, &abandoning{}, st)

	st = stateFromName(stateNameDeciding)
	require.Equal(t, &deciding{}, st)

	st = stateFromName(stateNameWaiting)
	require.Equal(t, &waiting{}, st)

	st = stateFromName(stateNameRequesting)
	require.Equal(t, &requesting{}, st)

	st = stateFromName("unknown")
	require.Equal(t, &noOp{}, st)
}

func TestService_save(t *testing.T) {
	// JSON Error
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	storageProvider := storageMocks.NewMockProvider(ctrl)
	storageProvider.EXPECT().OpenStore(Introduce).Return(nil, nil)

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().StorageProvider().Return(storageProvider)
	provider.EXPECT().OutboundDispatcher().Return(nil)
	provider.EXPECT().Service(didexchange.DIDExchange).Return(mocks.NewMockForwarder(ctrl), nil)

	svc, err := New(provider)
	defer stop(t, svc)
	require.NoError(t, err)

	const errMsg = "service save: json: unsupported type: chan int"

	require.EqualError(t, svc.save("ID", struct{ A chan int }{}), errMsg)
}

// This test describes the following flow :
// 1. Alice sends a proposal to the Bob
// 2. Bob sends a response to the Alice (with an Invitation)
// 3. Alice sends a proposal to the Carol
// 4. Carol sends a response to the Alice
// 5. Alice forwards an invitation Carol
// 6. Alice sends a ack to the Bob
func TestService_Proposal(t *testing.T) {
	var transport = transport()

	inv := &didexchange.Invitation{Label: Bob}

	getInboundDestinationOriginal := getInboundDestination

	defer func() { getInboundDestination = getInboundDestinationOriginal }()

	// injection
	getInboundDestination = func() *service.Destination {
		return &service.Destination{ServiceEndpoint: Alice}
	}

	aliceCtrl, alice, aliceDep := setupIntroducer(&flow{
		t:           t,
		expectedInv: inv,
		transport:   transport,
		destinations: []*service.Destination{
			{ServiceEndpoint: Bob},
			{ServiceEndpoint: Carol},
		},
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

	// introducer side Alice
	go checkAndHandle(&flow{
		t:            t,
		wg:           &wg,
		svc:          alice,
		transport:    transport,
		dependency:   aliceDep,
		transportKey: Alice,
		destinations: []*service.Destination{
			{ServiceEndpoint: Bob},
		},
		withProposal: true,
	})

	// introducee side Bob
	go checkAndHandle(&flow{
		t:            t,
		wg:           &wg,
		svc:          bob,
		transport:    transport,
		dependency:   bobDep,
		transportKey: Bob,
	})

	// introducee side Carol
	go checkAndHandle(&flow{
		t:            t,
		wg:           &wg,
		svc:          carol,
		transport:    transport,
		dependency:   carolDep,
		transportKey: Carol,
	})

	wg.Wait()
}

// This test describes the following flow :
// 1. Alice sends a proposal to the Bob
// 2. Bob sends a response to the Alice
// 3. Alice forwards an invitation to the Bob
func TestService_SkipProposal(t *testing.T) {
	var transport = transport()

	inv := &didexchange.Invitation{Label: "Public Invitation"}

	getInboundDestinationOriginal := getInboundDestination

	defer func() { getInboundDestination = getInboundDestinationOriginal }()

	// injection
	getInboundDestination = func() *service.Destination {
		return &service.Destination{ServiceEndpoint: Alice}
	}

	aliceCtrl, alice, aliceDep := setupIntroducer(&flow{
		t:           t,
		inv:         inv,
		expectedInv: inv,
		transport:   transport,
		destinations: []*service.Destination{
			{ServiceEndpoint: Bob},
		},
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

	// introducer side Alice
	go checkAndHandle(&flow{
		t:            t,
		wg:           &wg,
		svc:          alice,
		transport:    transport,
		dependency:   aliceDep,
		transportKey: Alice,
		destinations: []*service.Destination{
			{ServiceEndpoint: Bob},
		},
		skipProposal: true,
		withProposal: true,
	})

	// introducee side Bob
	go checkAndHandle(&flow{
		t:            t,
		wg:           &wg,
		svc:          bob,
		transport:    transport,
		dependency:   bobDep,
		transportKey: Bob,
	})

	wg.Wait()
}

// This test describes the following flow :
// 1. Alice sends a proposal to the Bob
// 2. Bob sends a response to the Alice (without an Invitation)
// 3. Alice sends a proposal to the Carol
// 4. Carol sends a response to the Alice (with an Invitation)
// 5. Alice forwards an invitation to the Bob
// 6. Alice sends a ack to the Carol
func TestService_ProposalUnusual(t *testing.T) {
	var transport = transport()

	inv := &didexchange.Invitation{Label: Carol}

	getInboundDestinationOriginal := getInboundDestination

	defer func() { getInboundDestination = getInboundDestinationOriginal }()

	// injection
	getInboundDestination = func() *service.Destination {
		return &service.Destination{ServiceEndpoint: Alice}
	}

	aliceCtrl, alice, aliceDep := setupIntroducer(&flow{
		t:           t,
		expectedInv: inv,
		transport:   transport,
		destinations: []*service.Destination{
			{ServiceEndpoint: Bob},
			{ServiceEndpoint: Carol},
		},
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

	// introducer side Alice
	go checkAndHandle(&flow{
		t:            t,
		wg:           &wg,
		svc:          alice,
		transport:    transport,
		dependency:   aliceDep,
		transportKey: Alice,
		destinations: []*service.Destination{
			{ServiceEndpoint: Bob},
		},
		withProposal: true,
	})

	// introducee side Bob
	go checkAndHandle(&flow{
		t:            t,
		wg:           &wg,
		svc:          bob,
		transport:    transport,
		dependency:   bobDep,
		transportKey: Bob,
	})

	// introducee side Carol
	go checkAndHandle(&flow{
		t:            t,
		wg:           &wg,
		svc:          carol,
		transport:    transport,
		dependency:   carolDep,
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
		}).AnyTimes()

	storageProvider := storageMocks.NewMockProvider(ctrl)
	storageProvider.EXPECT().OpenStore(Introduce).Return(fakeStore(ctrl), nil)

	forwarder := mocks.NewMockForwarder(ctrl)
	forwarder.EXPECT().SendInvitation(gomock.Any(), f.expectedInv, gomock.Any()).
		Do(func(pthID string, inv *didexchange.Invitation, dest *service.Destination) error {
			inv.ID = pthID
			f.transport[dest.ServiceEndpoint] <- inv
			return nil
		}).Return(nil).MaxTimes(1)

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().StorageProvider().Return(storageProvider)
	provider.EXPECT().OutboundDispatcher().Return(dispatcher)
	provider.EXPECT().Service(didexchange.DIDExchange).Return(forwarder, nil)

	svc, err := New(provider)
	require.NoError(f.t, err)

	dep := mocks.NewMockInvitationEnvelope(ctrl)

	dep.EXPECT().Invitation().Return(f.inv).AnyTimes()
	dep.EXPECT().Destinations().Return(f.destinations).AnyTimes()

	return ctrl, svc, dep
}

func handleInbound(t *testing.T, svc *Service, msg interface{}) {
	t.Helper()

	resp, err := service.NewDIDCommMsg(toBytes(t, msg))
	require.NoError(t, err)
	_, err = svc.HandleInbound(resp)
	require.NoError(t, err)
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
	provider.EXPECT().Service(didexchange.DIDExchange).Return(mocks.NewMockForwarder(ctrl), nil)

	svc, err := New(provider)
	require.NoError(f.t, err)

	dep := mocks.NewMockInvitationEnvelope(ctrl)
	dep.EXPECT().Invitation().Return(f.inv).AnyTimes()

	return ctrl, svc, dep
}

// This test describes the following flow :
// 1. Bob sends a request to the Alice
// 2. Alice sends a proposal to the Bob
// 3. Bob sends a response to the Alice
// 4. Alice forwards an invitation to the Bob
func TestService_SkipProposalWithRequest(t *testing.T) {
	var transport = transport()

	inv := &didexchange.Invitation{Label: "Public Invitation"}

	getInboundDestinationOriginal := getInboundDestination

	defer func() { getInboundDestination = getInboundDestinationOriginal }()

	// injection
	idx := -1
	destinations := []*service.Destination{
		{ServiceEndpoint: Bob},
		{ServiceEndpoint: Alice},
		{ServiceEndpoint: Bob},
	}
	getInboundDestination = func() *service.Destination {
		idx++
		return destinations[idx]
	}

	aliceCtrl, alice, aliceDep := setupIntroducer(&flow{
		t:           t,
		inv:         inv,
		expectedInv: inv,
		transport:   transport,
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

	// introducer side Alice
	go checkAndHandle(&flow{
		t:            t,
		wg:           &wg,
		svc:          alice,
		transport:    transport,
		dependency:   aliceDep,
		transportKey: Alice,
		skipProposal: true,
	})

	// introducee side Bob
	go checkAndHandle(&flow{
		t:          t,
		wg:         &wg,
		svc:        bob,
		transport:  transport,
		dependency: bobDep,
		destinations: []*service.Destination{
			{ServiceEndpoint: Alice},
		},
		transportKey: Bob,
		withRequest:  true,
	})

	wg.Wait()
}

// This test describes the following flow :
// 1. Bob sends a request to the Alice
// 2. Alice sends a proposal to the Bob
// 3. Bob sends a response to the Alice (with an Invitation)
// 4. Alice sends a proposal to the Carol
// 5. Carol sends a response to the Alice
// 6. Alice forwards an invitation Carol
// 7. Alice sends a ack to the Bob
func TestService_ProposalWithRequest(t *testing.T) {
	var transport = transport()

	inv := &didexchange.Invitation{Label: Bob}

	getInboundDestinationOriginal := getInboundDestination

	defer func() { getInboundDestination = getInboundDestinationOriginal }()

	// injection
	idx := -1
	destinations := []*service.Destination{
		{ServiceEndpoint: Bob},
		{ServiceEndpoint: Alice},
		{ServiceEndpoint: Alice},
		{ServiceEndpoint: Bob},
	}
	getInboundDestination = func() *service.Destination {
		idx++
		return destinations[idx]
	}

	aliceCtrl, alice, aliceDep := setupIntroducer(&flow{
		t:           t,
		expectedInv: inv,
		transport:   transport,
		destinations: []*service.Destination{
			{ServiceEndpoint: Carol},
		},
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

	// introducer side Alice
	go checkAndHandle(&flow{
		t:            t,
		wg:           &wg,
		svc:          alice,
		transport:    transport,
		dependency:   aliceDep,
		transportKey: Alice,
	})

	// introducee side Bob
	go checkAndHandle(&flow{
		t:          t,
		wg:         &wg,
		svc:        bob,
		transport:  transport,
		dependency: bobDep,
		destinations: []*service.Destination{
			{ServiceEndpoint: Alice},
		},
		transportKey: Bob,
		withRequest:  true,
	})

	// introducee side Carol
	go checkAndHandle(&flow{
		t:            t,
		wg:           &wg,
		svc:          carol,
		transport:    transport,
		dependency:   carolDep,
		transportKey: Carol,
	})

	wg.Wait()
}

// This test describes the following flow :
// 1. Bob sends a request to the Alice
// 2. Alice sends a proposal to the Bob
// 3. Bob sends a response to the Alice
// 4. Alice sends a proposal to the Carol
// 5. Carol sends a response to the Alice (with an Invitation)
// 6. Alice forwards an invitation to the Bob
// 7. Alice sends a ack to the Carol
func TestService_ProposalUnusualWithRequest(t *testing.T) {
	var transport = transport()

	inv := &didexchange.Invitation{Label: Carol}

	getInboundDestinationOriginal := getInboundDestination

	defer func() { getInboundDestination = getInboundDestinationOriginal }()

	// injection
	idx := -1
	destinations := []*service.Destination{
		{ServiceEndpoint: Bob},
		{ServiceEndpoint: Alice},
		{ServiceEndpoint: Alice},
		{ServiceEndpoint: Bob},
	}
	getInboundDestination = func() *service.Destination {
		idx++
		return destinations[idx]
	}

	aliceCtrl, alice, aliceDep := setupIntroducer(&flow{
		t:           t,
		expectedInv: inv,
		transport:   transport,
		destinations: []*service.Destination{
			{ServiceEndpoint: Carol},
		},
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

	// introducer side Alice
	go checkAndHandle(&flow{
		t:            t,
		wg:           &wg,
		svc:          alice,
		transport:    transport,
		dependency:   aliceDep,
		transportKey: Alice,
	})

	// introducee side Bob
	go checkAndHandle(&flow{
		t:          t,
		wg:         &wg,
		svc:        bob,
		transport:  transport,
		dependency: bobDep,
		destinations: []*service.Destination{
			{ServiceEndpoint: Alice},
		},
		transportKey: Bob,
		withRequest:  true,
	})

	// introducee side Carol
	go checkAndHandle(&flow{
		t:            t,
		wg:           &wg,
		svc:          carol,
		transport:    transport,
		dependency:   carolDep,
		transportKey: Carol,
	})

	wg.Wait()
}

// This test describes the following flow :
// 1. Alice sends a proposal to the Bob
// 2. Bob sends a response to the Alice
// 3. Alice sends a proposal to the Carol
// 4. Carol sends a response to the Alice
// 5. Alice sends problem-report Bob
// 6. Alice sends problem-report Carol
func TestService_ProposalError(t *testing.T) {
	var transport = transport()

	getInboundDestinationOriginal := getInboundDestination

	defer func() { getInboundDestination = getInboundDestinationOriginal }()

	// injection
	getInboundDestination = func() *service.Destination {
		return &service.Destination{ServiceEndpoint: Alice}
	}

	aliceCtrl, alice, aliceDep := setupIntroducer(&flow{
		t:         t,
		transport: transport,
		destinations: []*service.Destination{
			{ServiceEndpoint: Bob},
			{ServiceEndpoint: Carol},
		},
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
		transport: transport,
	})
	defer carolCtrl.Finish()
	defer stop(t, carol)

	var wg sync.WaitGroup

	wg.Add(3)

	// introducer side Alice
	go checkAndHandle(&flow{
		t:            t,
		wg:           &wg,
		svc:          alice,
		transport:    transport,
		dependency:   aliceDep,
		transportKey: Alice,
		destinations: []*service.Destination{
			{ServiceEndpoint: Bob},
		},
		withError:    true,
		withProposal: true,
	})

	// introducee side Bob
	go checkAndHandle(&flow{
		t:            t,
		wg:           &wg,
		svc:          bob,
		transport:    transport,
		dependency:   bobDep,
		transportKey: Bob,
	})

	// introducee side Carol
	go checkAndHandle(&flow{
		t:            t,
		wg:           &wg,
		svc:          carol,
		transport:    transport,
		dependency:   carolDep,
		transportKey: Carol,
	})

	wg.Wait()
}

// This test describes the following flow :
// 1. Bob sends a request to the Alice
// 2. Alice sends a proposal to the Bob
// 3. Bob sends a response to the Alice (with an Invitation)
// 4. Alice sends a proposal to the Carol
// 5. Carol sends a response to the Alice
// 6. Alice sends problem-report to Bob
// 7. Alice sends problem-report to Carol
// nolint: gocyclo
func TestService_ProposalErrorWithRequest(t *testing.T) {
	var transport = transport()

	getInboundDestinationOriginal := getInboundDestination

	defer func() { getInboundDestination = getInboundDestinationOriginal }()

	// injection
	idx := -1
	destinations := []*service.Destination{
		{ServiceEndpoint: Bob},
		{ServiceEndpoint: Alice},
		{ServiceEndpoint: Alice},
		{ServiceEndpoint: Bob},
	}
	getInboundDestination = func() *service.Destination {
		idx++
		return destinations[idx]
	}

	aliceCtrl, alice, aliceDep := setupIntroducer(&flow{
		t:         t,
		transport: transport,
		destinations: []*service.Destination{
			{ServiceEndpoint: Carol},
		},
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
		transport: transport,
	})
	defer carolCtrl.Finish()
	defer stop(t, carol)

	var wg sync.WaitGroup

	wg.Add(3)

	// introducer side Alice
	go checkAndHandle(&flow{
		t:            t,
		wg:           &wg,
		svc:          alice,
		transport:    transport,
		dependency:   aliceDep,
		transportKey: Alice,
		withError:    true,
	})

	// introducee side Bob
	go checkAndHandle(&flow{
		t:          t,
		wg:         &wg,
		svc:        bob,
		transport:  transport,
		dependency: bobDep,
		destinations: []*service.Destination{
			{ServiceEndpoint: Alice},
		},
		transportKey: Bob,
		withRequest:  true,
	})

	// introducee side Carol
	go checkAndHandle(&flow{
		t:            t,
		wg:           &wg,
		svc:          carol,
		transport:    transport,
		dependency:   carolDep,
		transportKey: Carol,
	})

	wg.Wait()
}

// nolint: gocyclo
func checkAndHandle(f *flow) {
	defer f.wg.Done()

	// register action event channel
	aCh := make(chan service.DIDCommAction)
	require.NoError(f.t, f.svc.RegisterActionEvent(aCh))

	// register action event channel
	sCh := make(chan service.StateMsg)
	require.NoError(f.t, f.svc.RegisterMsgEvent(sCh))

	if f.withRequest {
		// creates request msg
		request, err := service.NewDIDCommMsg(toBytes(f.t, Request{
			Type: RequestMsgType,
			// creates threadID
			ID: uuid.New().String(),
		}))
		require.NoError(f.t, err)

		go func() {
			// handle outbound Request msg
			require.NoError(f.t, f.svc.HandleOutbound(request, &service.Destination{
				ServiceEndpoint: f.destinations[0].ServiceEndpoint,
			}))
		}()
		checkStateMsg(f.t, sCh, service.PreState, RequestMsgType, stateNameRequesting)
		checkStateMsg(f.t, sCh, service.PostState, RequestMsgType, stateNameRequesting)
	}

	if f.withProposal {
		// creates proposal msg
		proposal, err := service.NewDIDCommMsg(toBytes(f.t, Proposal{
			Type: ProposalMsgType,
			// creates threadID
			ID: uuid.New().String(),
		}))
		require.NoError(f.t, err)

		go func() {
			// handle outbound Proposal msg
			require.NoError(f.t, f.svc.HandleOutbound(proposal, &service.Destination{
				ServiceEndpoint: f.destinations[0].ServiceEndpoint,
			}))
		}()
		checkStateMsg(f.t, sCh, service.PreState, ProposalMsgType, stateNameArranging)
		checkStateMsg(f.t, sCh, service.PostState, ProposalMsgType, stateNameArranging)
	}

	for {
		var incomingMsg interface{}
		select {
		case incomingMsg = <-f.transport[f.transportKey]:
		case <-time.After(time.Second):
			f.t.Error("timeout")
			return
		}

		switch iMsg := incomingMsg.(type) {
		case *Request:
			go handleInbound(f.t, f.svc, incomingMsg)
			continueAction(f.t, aCh, RequestMsgType, f.dependency)
			checkStateMsg(f.t, sCh, service.PreState, RequestMsgType, stateNameArranging)
			checkStateMsg(f.t, sCh, service.PostState, RequestMsgType, stateNameArranging)
		case *Response:
			go handleInbound(f.t, f.svc, incomingMsg)
			continueAction(f.t, aCh, ResponseMsgType, f.dependency)
			// this code will be ignored for skip proposal
			if !f.skipProposal {
				f.skipProposal = true
				checkStateMsg(f.t, sCh, service.PreState, ResponseMsgType, stateNameArranging)
				checkStateMsg(f.t, sCh, service.PostState, ResponseMsgType, stateNameArranging)

				break
			}

			checkStateMsg(f.t, sCh, service.PreState, ResponseMsgType, stateNameDelivering)
			checkStateMsg(f.t, sCh, service.PostState, ResponseMsgType, stateNameDelivering)

			if f.withError {
				checkStateMsg(f.t, sCh, service.PreState, ResponseMsgType, stateNameAbandoning)
				checkStateMsg(f.t, sCh, service.PostState, ResponseMsgType, stateNameAbandoning)
			}

			checkStateMsg(f.t, sCh, service.PreState, ResponseMsgType, stateNameDone)
			checkStateMsg(f.t, sCh, service.PostState, ResponseMsgType, stateNameDone)

			return
		case *Proposal:
			go handleInbound(f.t, f.svc, incomingMsg)
			continueAction(f.t, aCh, ProposalMsgType, f.dependency)
			checkStateMsg(f.t, sCh, service.PreState, ProposalMsgType, stateNameDeciding)
			checkStateMsg(f.t, sCh, service.PostState, ProposalMsgType, stateNameDeciding)
			checkStateMsg(f.t, sCh, service.PreState, ProposalMsgType, stateNameWaiting)
			checkStateMsg(f.t, sCh, service.PostState, ProposalMsgType, stateNameWaiting)
		case *model.ProblemReport:
			go handleInbound(f.t, f.svc, incomingMsg)
			checkStateMsg(f.t, sCh, service.PreState, ProblemReportMsgType, stateNameAbandoning)
			checkStateMsg(f.t, sCh, service.PostState, ProblemReportMsgType, stateNameAbandoning)
			checkStateMsg(f.t, sCh, service.PreState, ProblemReportMsgType, stateNameDone)
			checkStateMsg(f.t, sCh, service.PostState, ProblemReportMsgType, stateNameDone)

			return
		case *model.Ack:
			go handleInbound(f.t, f.svc, incomingMsg)
			checkStateMsg(f.t, sCh, service.PreState, AckMsgType, stateNameDone)
			checkStateMsg(f.t, sCh, service.PostState, AckMsgType, stateNameDone)

			return
		case *didexchange.Invitation:
			go func() { require.NoError(f.t, f.svc.InvitationReceived(iMsg.ID)) }()
			checkStateMsg(f.t, sCh, service.PreState, AckMsgType, stateNameDone)
			checkStateMsg(f.t, sCh, service.PostState, AckMsgType, stateNameDone)

			return
		}
	}
}

func transport() map[string]chan interface{} {
	// the map of channels which is responsible for the communication
	return map[string]chan interface{}{
		Alice: make(chan interface{}),
		Bob:   make(chan interface{}),
		Carol: make(chan interface{}),
	}
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

		res.Continue(dep)

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
