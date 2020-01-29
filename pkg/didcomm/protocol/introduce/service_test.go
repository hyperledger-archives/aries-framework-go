/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce_test

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
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messenger"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/introduce"
	serviceMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/common/service"
	dispatcherMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/dispatcher"
	messengerMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/messenger"
	introduceMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/protocol/introduce"
	storageMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	Alice = "Alice"
	Bob   = "Bob"
	Carol = "Carol"
)

// this line checks that Service satisfies service.Handler interface
var _ service.Handler = &introduce.Service{}

type flow struct {
	t                       *testing.T
	wg                      *sync.WaitGroup
	svc                     *introduce.Service
	expectedInv             *didexchange.Invitation
	inv                     *didexchange.Invitation
	transportKey            string
	transport               map[string]chan service.DIDCommMsg
	dependency              introduce.InvitationEnvelope
	recipients              []*introduce.Recipient
	didEvent                chan<- service.StateMsg
	controller              *gomock.Controller
	messenger               service.Messenger
	startWithRequest        bool
	startWithProposal       bool
	skipProposal            bool
	withResponseError       bool
	withSecondResponseError bool
	withSecondResponseStop  bool
	withProposalStop        bool
	withRequestStop         bool
	withResponseStop        bool
}

func TestService_New(t *testing.T) {
	const errMsg = "test err"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("OpenStore Error", func(t *testing.T) {
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(nil, errors.New(errMsg))

		provider := introduceMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)

		svc, err := introduce.New(provider)
		require.EqualError(t, err, "test err")
		require.Nil(t, svc)
	})

	t.Run("Service Error", func(t *testing.T) {
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(nil, nil)

		provider := introduceMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().Service(didexchange.DIDExchange).Return(nil, errors.New(errMsg))

		svc, err := introduce.New(provider)
		require.EqualError(t, err, "load the DIDExchange service: test err")
		require.Nil(t, svc)
	})

	t.Run("Cast Service Error", func(t *testing.T) {
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(nil, nil)

		provider := introduceMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().Service(didexchange.DIDExchange).Return(nil, nil)

		svc, err := introduce.New(provider)
		require.EqualError(t, err, "cast service to service.Event")
		require.Nil(t, svc)
	})
}

func TestService_Stop(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	storageProvider := storageMocks.NewMockProvider(ctrl)
	storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(nil, nil)

	didService := serviceMocks.NewMockDIDComm(ctrl)
	didService.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
	didService.EXPECT().UnregisterMsgEvent(gomock.Any()).Return(nil)

	provider := introduceMocks.NewMockProvider(ctrl)
	provider.EXPECT().StorageProvider().Return(storageProvider)
	provider.EXPECT().Messenger().Return(nil)
	provider.EXPECT().Service(didexchange.DIDExchange).Return(didService, nil)

	svc, err := introduce.New(provider)
	require.NoError(t, err)

	require.NoError(t, svc.Stop())
	require.EqualError(t, svc.Stop(), "server was already stopped")
}

func TestService_Name(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	storageProvider := storageMocks.NewMockProvider(ctrl)
	storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(nil, nil)

	didService := serviceMocks.NewMockDIDComm(ctrl)
	didService.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
	didService.EXPECT().UnregisterMsgEvent(gomock.Any()).Return(nil)

	provider := introduceMocks.NewMockProvider(ctrl)
	provider.EXPECT().StorageProvider().Return(storageProvider)
	provider.EXPECT().Messenger().Return(nil)
	provider.EXPECT().Service(didexchange.DIDExchange).Return(didService, nil)

	svc, err := introduce.New(provider)
	require.NoError(t, err)

	defer stop(t, svc)

	require.Equal(t, introduce.Introduce, svc.Name())
}

func TestService_HandleOutbound(t *testing.T) {
	t.Run("Storage JSON error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get("ID").Return([]byte(`[]`), nil)

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(store, nil)

		didService := serviceMocks.NewMockDIDComm(ctrl)
		didService.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		didService.EXPECT().UnregisterMsgEvent(gomock.Any()).Return(nil)

		provider := introduceMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().Messenger().Return(nil)
		provider.EXPECT().Service(didexchange.DIDExchange).Return(didService, nil)

		svc, err := introduce.New(provider)
		require.NoError(t, err)
		defer stop(t, svc)
		msg, err := service.ParseDIDCommMsgMap([]byte(fmt.Sprintf(`{"@id":"ID","@type":%q}`, introduce.ResponseMsgType)))
		require.NoError(t, err)
		const errMsg = "json: cannot unmarshal array into Go value of type introduce.record"
		require.EqualError(t, svc.HandleOutbound(msg, "", ""), errMsg)
	})

	t.Run("Invalid state", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := storageMocks.NewMockStore(ctrl)
		raw := fmt.Sprintf(`{"state_name":%q, "wait_count":%d}`, "unknown", 1)
		store.EXPECT().Get("ID").Return([]byte(raw), nil)

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(store, nil)

		didService := serviceMocks.NewMockDIDComm(ctrl)
		didService.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		didService.EXPECT().UnregisterMsgEvent(gomock.Any()).Return(nil)

		provider := introduceMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().Messenger().Return(nil)
		provider.EXPECT().Service(didexchange.DIDExchange).Return(didService, nil)

		svc, err := introduce.New(provider)

		require.NoError(t, err)
		defer stop(t, svc)
		msg, err := service.ParseDIDCommMsgMap([]byte(fmt.Sprintf(`{"@id":"ID","@type":%q}`, introduce.ProposalMsgType)))
		require.NoError(t, err)
		ch := make(chan service.DIDCommAction)
		require.NoError(t, svc.RegisterActionEvent(ch))
		require.EqualError(t, svc.HandleOutbound(msg, "", ""), "invalid state transition: noop -> arranging")
	})

	t.Run("Inject invitation error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get("thID").Return([]byte(`{"state_name":"start","wait_count":2}`), nil)

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(store, nil)

		didService := serviceMocks.NewMockDIDComm(ctrl)
		didService.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		didService.EXPECT().UnregisterMsgEvent(gomock.Any()).Return(nil)

		provider := introduceMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().Messenger().Return(nil)
		provider.EXPECT().Service(didexchange.DIDExchange).Return(didService, nil)

		svc, err := introduce.New(provider)
		require.NoError(t, err)

		defer stop(t, svc)

		didMsg, err := service.ParseDIDCommMsgMap(toBytes(t, &service.Header{
			ID:     "ID",
			Thread: decorator.Thread{ID: "thID"},
			Type:   introduce.ResponseMsgType,
		}))
		require.NoError(t, err)
		didMsg["approve"] = "invalid"
		// inject invitation error
		err = svc.HandleOutbound(didMsg, "", "")

		const errMsg = `execute: inject invitation`

		require.Contains(t, err.Error(), errMsg)
	})

	t.Run("Save error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get("thID").Return([]byte(`{"state_name":"arranging","wait_count":2}`), nil)
		store.EXPECT().Put("thID", gomock.Any()).Return(errors.New("DB error"))

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(store, nil)

		didService := serviceMocks.NewMockDIDComm(ctrl)
		didService.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		didService.EXPECT().UnregisterMsgEvent(gomock.Any()).Return(nil)

		provider := introduceMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().Messenger().Return(nil)
		provider.EXPECT().Service(didexchange.DIDExchange).Return(didService, nil)

		svc, err := introduce.New(provider)
		require.NoError(t, err)

		defer stop(t, svc)

		require.NoError(t, svc.RegisterActionEvent(make(chan service.DIDCommAction, 1)))

		didMsg, err := service.ParseDIDCommMsgMap(toBytes(t, &service.Header{
			ID:     "ID",
			Thread: decorator.Thread{ID: "thID"},
			Type:   introduce.AckMsgType,
		}))
		require.NoError(t, err)

		// inject invitation error
		_, err = svc.HandleInbound(didMsg, "", "")

		const errMsg = "failed to persist state done: DB error"

		require.EqualError(t, errors.Unwrap(err), errMsg)
	})
	t.Run("Invalid state transition", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get("thID").Return([]byte(`{"state_name":"confirming","wait_count":2}`), nil)

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(store, nil)

		didService := serviceMocks.NewMockDIDComm(ctrl)
		didService.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		didService.EXPECT().UnregisterMsgEvent(gomock.Any()).Return(nil)

		provider := introduceMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().Messenger().Return(nil)
		provider.EXPECT().Service(didexchange.DIDExchange).Return(didService, nil)

		svc, err := introduce.New(provider)
		require.NoError(t, err)

		defer stop(t, svc)
		didMsg, err := service.ParseDIDCommMsgMap(toBytes(t, &service.Header{
			ID:     "ID",
			Thread: decorator.Thread{ID: "thID"},
			Type:   introduce.ResponseMsgType,
		}))
		require.NoError(t, err)

		// inject invitation error
		err = svc.HandleOutbound(didMsg, "", "")

		const errMsg = "invalid state transition: confirming -> arranging"

		require.EqualError(t, err, errMsg)
	})
}

func TestService_HandleInbound(t *testing.T) {
	t.Parallel()

	t.Run("No clients", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(nil, nil)

		didService := serviceMocks.NewMockDIDComm(ctrl)
		didService.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		didService.EXPECT().UnregisterMsgEvent(gomock.Any()).Return(nil)

		provider := introduceMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().Messenger().Return(nil)
		provider.EXPECT().Service(didexchange.DIDExchange).Return(didService, nil)

		svc, err := introduce.New(provider)
		require.NoError(t, err)
		defer stop(t, svc)
		_, err = svc.HandleInbound(service.DIDCommMsgMap{}, "", "")
		require.EqualError(t, err, "no clients are registered to handle the message")
	})

	t.Run("ThreadID Error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(nil, nil)

		didService := serviceMocks.NewMockDIDComm(ctrl)
		didService.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		didService.EXPECT().UnregisterMsgEvent(gomock.Any()).Return(nil)

		provider := introduceMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().Messenger().Return(nil)
		provider.EXPECT().Service(didexchange.DIDExchange).Return(didService, nil)

		svc, err := introduce.New(provider)
		require.NoError(t, err)
		defer stop(t, svc)
		msg, err := service.ParseDIDCommMsgMap([]byte(`{}`))
		require.NoError(t, err)
		ch := make(chan service.DIDCommAction)
		require.NoError(t, svc.RegisterActionEvent(ch))

		_, err = svc.HandleInbound(msg, "", "")
		require.EqualError(t, err, service.ErrThreadIDNotFound.Error())
	})

	t.Run("Storage error", func(t *testing.T) {
		const errMsg = "test err"

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get("ID").Return(nil, errors.New(errMsg))

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(store, nil)

		didService := serviceMocks.NewMockDIDComm(ctrl)
		didService.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		didService.EXPECT().UnregisterMsgEvent(gomock.Any()).Return(nil)

		provider := introduceMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().Messenger().Return(nil)
		provider.EXPECT().Service(didexchange.DIDExchange).Return(didService, nil)

		svc, err := introduce.New(provider)
		require.NoError(t, err)
		defer stop(t, svc)
		msg, err := service.ParseDIDCommMsgMap([]byte(fmt.Sprintf(`{"@id":"ID","@type":%q}`, introduce.ProposalMsgType)))
		require.NoError(t, err)
		ch := make(chan service.DIDCommAction)
		require.NoError(t, svc.RegisterActionEvent(ch))

		_, err = svc.HandleInbound(msg, "", "")
		require.EqualError(t, err, "cannot fetch state from store: thid=ID : test err")
	})

	t.Run("Bad transition", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get(gomock.Any()).Return([]byte(`{"state_name":"noop","wait_count":1}`), nil)

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(store, nil)

		didService := serviceMocks.NewMockDIDComm(ctrl)
		didService.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		didService.EXPECT().UnregisterMsgEvent(gomock.Any()).Return(nil)

		provider := introduceMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().Messenger().Return(nil)
		provider.EXPECT().Service(didexchange.DIDExchange).Return(didService, nil)

		svc, err := introduce.New(provider)
		require.NoError(t, err)
		defer stop(t, svc)

		msg, err := service.ParseDIDCommMsgMap([]byte(fmt.Sprintf(`{"@id":"ID","@type":%q}`, introduce.ProposalMsgType)))
		require.NoError(t, err)
		ch := make(chan service.DIDCommAction)
		require.NoError(t, svc.RegisterActionEvent(ch))

		_, err = svc.HandleInbound(msg, "", "")
		require.EqualError(t, err, "invalid state transition: noop -> deciding")
	})

	t.Run("Unknown msg type error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get("ID").Return(nil, storage.ErrDataNotFound)

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(store, nil)

		didService := serviceMocks.NewMockDIDComm(ctrl)
		didService.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		didService.EXPECT().UnregisterMsgEvent(gomock.Any()).Return(nil)

		provider := introduceMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().Messenger().Return(nil)
		provider.EXPECT().Service(didexchange.DIDExchange).Return(didService, nil)

		svc, err := introduce.New(provider)
		require.NoError(t, err)
		defer stop(t, svc)
		msg, err := service.ParseDIDCommMsgMap([]byte(`{"@id":"ID","@type":"unknown"}`))
		require.NoError(t, err)
		ch := make(chan service.DIDCommAction)
		require.NoError(t, svc.RegisterActionEvent(ch))

		_, err = svc.HandleInbound(msg, "", "")
		require.EqualError(t, err, "unrecognized msgType: unknown")
	})
}

func TestService_Accept(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	storageProvider := storageMocks.NewMockProvider(ctrl)
	storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(nil, nil)

	didService := serviceMocks.NewMockDIDComm(ctrl)
	didService.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
	didService.EXPECT().UnregisterMsgEvent(gomock.Any()).Return(nil)

	provider := introduceMocks.NewMockProvider(ctrl)
	provider.EXPECT().StorageProvider().Return(storageProvider)
	provider.EXPECT().Messenger().Return(nil)
	provider.EXPECT().Service(didexchange.DIDExchange).Return(didService, nil)

	svc, err := introduce.New(provider)
	require.NoError(t, err)

	defer stop(t, svc)

	require.False(t, svc.Accept(""))
	require.True(t, svc.Accept(introduce.ProposalMsgType))
	require.True(t, svc.Accept(introduce.RequestMsgType))
	require.True(t, svc.Accept(introduce.ResponseMsgType))
	require.True(t, svc.Accept(introduce.AckMsgType))
	require.True(t, svc.Accept(introduce.ProblemReportMsgType))
}

func newMessenger(f *flow) service.Messenger {
	storageProvider := storageMocks.NewMockProvider(f.controller)
	storageProvider.EXPECT().OpenStore(gomock.Any()).Return(fakeStore(f.controller), nil)
	dispatcherOutbound := dispatcherMocks.NewMockOutbound(f.controller)
	messengerProvider := messengerMocks.NewMockProvider(f.controller)
	messengerProvider.EXPECT().StorageProvider().Return(storageProvider)
	messengerProvider.EXPECT().OutboundDispatcher().Return(dispatcherOutbound)
	// use real messenger
	msgr, err := messenger.NewMessenger(messengerProvider)
	require.NoError(f.t, err)

	dispatcherOutbound.EXPECT().
		SendToDID(gomock.Any(), gomock.Any(), gomock.Any()).
		Do(func(msg service.DIDCommMsg, myid string, dest string) error {
			require.NoError(f.t, msgr.HandleInbound(msg.(service.DIDCommMsgMap), dest, myid))
			f.transport[dest] <- msg
			return nil
		}).AnyTimes()

	return msgr
}

// This test describes the following flow :
// 1. Alice sends introduce.Proposal to the Bob
// 2. Bob sends introduce.Response to the Alice
// 3. Alice sends introduce.Proposal to the Carol
// 4. Carol sends introduce.Response to the Alice
// 5. Alice sends didexchange.Invitation to the Carol
// 6. Alice sends model.Ack to the Bob
func TestService_Proposal(t *testing.T) {
	var transport = transport()

	inv := &didexchange.Invitation{ID: uuid.New().String(), Type: didexchange.InvitationMsgType, Label: Bob}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	msgr := newMessenger(&flow{t: t, controller: ctrl, transport: transport})

	alice, aliceDep := setupIntroducer(&flow{
		t:            t,
		controller:   ctrl,
		expectedInv:  inv,
		transportKey: Alice,
		messenger:    msgr,
		transport:    transport,
		recipients: []*introduce.Recipient{
			{MyDID: Alice, TheirDID: Bob},
			{MyDID: Alice, TheirDID: Carol, To: &introduce.To{Name: Bob}},
		},
	})

	defer stop(t, alice)

	bob, bobDep, didEventBob := setupIntroducee(&flow{
		t:            t,
		controller:   ctrl,
		inv:          inv,
		transportKey: Bob,
		messenger:    msgr,
		transport:    transport,
	})
	defer stop(t, bob)

	carol, carolDep, didEventCarol := setupIntroducee(&flow{
		t:            t,
		controller:   ctrl,
		transportKey: Carol,
		messenger:    msgr,
		transport:    transport,
	})
	defer stop(t, carol)

	var wg sync.WaitGroup

	wg.Add(3)

	// introducer side Alice
	go checkAndHandle(&flow{
		t:            t,
		controller:   ctrl,
		wg:           &wg,
		svc:          alice,
		transport:    transport,
		dependency:   aliceDep,
		transportKey: Alice,
		recipients: []*introduce.Recipient{
			{MyDID: Alice, TheirDID: Bob, To: &introduce.To{Name: Carol}},
		},
		startWithProposal: true,
	})

	// introducee side Bob
	go checkAndHandle(&flow{
		t:            t,
		controller:   ctrl,
		wg:           &wg,
		svc:          bob,
		transport:    transport,
		dependency:   bobDep,
		didEvent:     didEventBob,
		transportKey: Bob,
		recipients: []*introduce.Recipient{
			{MyDID: Bob, TheirDID: Alice},
		},
	})

	// introducee side Carol
	go checkAndHandle(&flow{
		t:            t,
		controller:   ctrl,
		wg:           &wg,
		svc:          carol,
		transport:    transport,
		dependency:   carolDep,
		didEvent:     didEventCarol,
		transportKey: Carol,
		recipients: []*introduce.Recipient{
			{MyDID: Carol, TheirDID: Alice},
		},
	})

	wg.Wait()
}

// This test describes the following flow :
// 1. Alice sends introduce.Proposal to the Bob
// 2. Bob sends introduce.Response to the Alice
// 3. Alice sends didexchange.Invitation to the Bob
func TestService_SkipProposal(t *testing.T) {
	var transport = transport()

	inv := &didexchange.Invitation{
		ID:    uuid.New().String(),
		Type:  didexchange.InvitationMsgType,
		Label: "Public Invitation",
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	msgr := newMessenger(&flow{t: t, controller: ctrl, transport: transport})

	alice, aliceDep := setupIntroducer(&flow{
		t:            t,
		controller:   ctrl,
		inv:          inv,
		expectedInv:  inv,
		transportKey: Alice,
		messenger:    msgr,
		transport:    transport,
		recipients: []*introduce.Recipient{
			{MyDID: Alice, TheirDID: Bob},
		},
	})

	defer stop(t, alice)

	bob, bobDep, didEventBob := setupIntroducee(&flow{
		t:            t,
		controller:   ctrl,
		inv:          &didexchange.Invitation{Label: Bob},
		transportKey: Bob,
		messenger:    msgr,
		transport:    transport,
	})
	defer stop(t, bob)

	var wg sync.WaitGroup

	wg.Add(2)

	// introducer side Alice
	go checkAndHandle(&flow{
		t:            t,
		controller:   ctrl,
		wg:           &wg,
		svc:          alice,
		transport:    transport,
		dependency:   aliceDep,
		transportKey: Alice,
		recipients: []*introduce.Recipient{
			{MyDID: Alice, TheirDID: Bob, To: &introduce.To{Name: Carol}},
		},
		skipProposal:      true,
		startWithProposal: true,
	})

	// introducee side Bob
	go checkAndHandle(&flow{
		t:            t,
		controller:   ctrl,
		wg:           &wg,
		svc:          bob,
		transport:    transport,
		dependency:   bobDep,
		didEvent:     didEventBob,
		transportKey: Bob,
		recipients: []*introduce.Recipient{
			{MyDID: Bob, TheirDID: Alice},
		},
	})

	wg.Wait()
}

// This test describes the following flow :
// 1. Alice sends introduce.Proposal to the Bob
// 2. Bob sends introduce.Response to the Alice
// 3. Alice sends introduce.Proposal to the Carol
// 4. Carol sends introduce.Response to the Alice
// 5. Alice sends didexchange.Invitation to the Bob
// 6. Alice sends model.Ack to the Carol
func TestService_ProposalUnusual(t *testing.T) {
	var transport = transport()

	inv := &didexchange.Invitation{ID: uuid.New().String(), Type: didexchange.InvitationMsgType, Label: Carol}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	msgr := newMessenger(&flow{t: t, controller: ctrl, transport: transport})

	alice, aliceDep := setupIntroducer(&flow{
		t:            t,
		controller:   ctrl,
		expectedInv:  inv,
		transportKey: Alice,
		messenger:    msgr,
		transport:    transport,
		recipients: []*introduce.Recipient{
			{MyDID: Alice, TheirDID: Bob},
			{To: &introduce.To{Name: Bob}, MyDID: Alice, TheirDID: Carol},
		},
	})

	defer stop(t, alice)

	bob, bobDep, didEventBob := setupIntroducee(&flow{
		t:            t,
		controller:   ctrl,
		transportKey: Bob,
		messenger:    msgr,
		transport:    transport,
	})
	defer stop(t, bob)

	carol, carolDep, didEventCarol := setupIntroducee(&flow{
		t:            t,
		controller:   ctrl,
		inv:          inv,
		transportKey: Carol,
		messenger:    msgr,
		transport:    transport,
	})
	defer stop(t, carol)

	var wg sync.WaitGroup

	wg.Add(3)

	// introducer side Alice
	go checkAndHandle(&flow{
		t:            t,
		controller:   ctrl,
		wg:           &wg,
		svc:          alice,
		transport:    transport,
		dependency:   aliceDep,
		transportKey: Alice,
		recipients: []*introduce.Recipient{
			{To: &introduce.To{Name: Carol}, MyDID: Alice, TheirDID: Bob},
		},
		startWithProposal: true,
	})

	// introducee side Bob
	go checkAndHandle(&flow{
		t:            t,
		controller:   ctrl,
		wg:           &wg,
		svc:          bob,
		transport:    transport,
		dependency:   bobDep,
		didEvent:     didEventBob,
		transportKey: Bob,
		recipients: []*introduce.Recipient{
			{MyDID: Bob, TheirDID: Alice},
		},
	})

	// introducee side Carol
	go checkAndHandle(&flow{
		t:            t,
		controller:   ctrl,
		wg:           &wg,
		svc:          carol,
		transport:    transport,
		dependency:   carolDep,
		didEvent:     didEventCarol,
		transportKey: Carol,
		recipients: []*introduce.Recipient{
			{MyDID: Carol, TheirDID: Alice},
		},
	})

	wg.Wait()
}

// This test describes the following flow :
// 1. Bob sends introduce.Request to the Alice
// 2. Alice sends introduce.Proposal to the Bob
// 3. Bob sends introduce.Response to the Alice
// 4. Alice sends didexchange.Invitation to the Bob
func TestService_SkipProposalWithRequest(t *testing.T) {
	var transport = transport()

	inv := &didexchange.Invitation{
		ID:    uuid.New().String(),
		Type:  didexchange.InvitationMsgType,
		Label: "Public Invitation",
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	msgr := newMessenger(&flow{t: t, controller: ctrl, transport: transport})

	alice, aliceDep := setupIntroducer(&flow{
		t:            t,
		controller:   ctrl,
		inv:          inv,
		expectedInv:  inv,
		transportKey: Alice,
		recipients: []*introduce.Recipient{
			{To: &introduce.To{Name: Bob}},
		},
		messenger: msgr,
		transport: transport,
	})

	defer stop(t, alice)

	bob, bobDep, didEventBob := setupIntroducee(&flow{
		t:            t,
		controller:   ctrl,
		transportKey: Bob,
		inv:          &didexchange.Invitation{Label: Bob},
		messenger:    msgr,
		transport:    transport,
	})
	defer stop(t, bob)

	var wg sync.WaitGroup

	wg.Add(2)

	// introducer side Alice
	go checkAndHandle(&flow{
		t:            t,
		controller:   ctrl,
		wg:           &wg,
		svc:          alice,
		transport:    transport,
		dependency:   aliceDep,
		transportKey: Alice,
		recipients: []*introduce.Recipient{
			{MyDID: Alice, TheirDID: Bob},
		},
		skipProposal: true,
	})

	// introducee side Bob
	go checkAndHandle(&flow{
		t:          t,
		wg:         &wg,
		svc:        bob,
		transport:  transport,
		dependency: bobDep,
		didEvent:   didEventBob,
		recipients: []*introduce.Recipient{
			{MyDID: Bob, TheirDID: Alice},
		},
		transportKey:     Bob,
		startWithRequest: true,
	})

	wg.Wait()
}

// This test describes the following flow :
// 1. Bob sends introduce.Request to the Alice
// 2. Alice sends introduce.Proposal to the Bob
// 3. Bob sends introduce.Response to the Alice
// 4. Alice sends introduce.Proposal to the Carol
// 5. Carol sends introduce.Response to the Alice
// 6. Alice sends didexchange.Invitation to the Carol
// 7. Alice sends model.Ack to the Bob
func TestService_ProposalWithRequest(t *testing.T) {
	var transport = transport()

	inv := &didexchange.Invitation{ID: uuid.New().String(), Type: didexchange.InvitationMsgType, Label: Bob}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	msgr := newMessenger(&flow{t: t, controller: ctrl, transport: transport})

	alice, aliceDep := setupIntroducer(&flow{
		t:            t,
		controller:   ctrl,
		expectedInv:  inv,
		transportKey: Alice,
		messenger:    msgr,
		transport:    transport,
		recipients: []*introduce.Recipient{
			{To: &introduce.To{Name: Carol}},
			{To: &introduce.To{Name: Bob}, MyDID: Alice, TheirDID: Carol},
		},
	})

	defer stop(t, alice)

	bob, bobDep, didEventBob := setupIntroducee(&flow{
		t:            t,
		controller:   ctrl,
		inv:          inv,
		transportKey: Bob,
		messenger:    msgr,
		transport:    transport,
	})
	defer stop(t, bob)

	carol, carolDep, didEventCarol := setupIntroducee(&flow{
		t:            t,
		controller:   ctrl,
		transportKey: Carol,
		messenger:    msgr,
		transport:    transport,
	})
	defer stop(t, carol)

	var wg sync.WaitGroup

	wg.Add(3)

	// introducer side Alice
	go checkAndHandle(&flow{
		t:            t,
		controller:   ctrl,
		wg:           &wg,
		svc:          alice,
		transport:    transport,
		dependency:   aliceDep,
		transportKey: Alice,
		recipients: []*introduce.Recipient{
			{MyDID: Alice, TheirDID: Bob},
		},
	})

	// introducee side Bob
	go checkAndHandle(&flow{
		t:          t,
		wg:         &wg,
		svc:        bob,
		transport:  transport,
		dependency: bobDep,
		didEvent:   didEventBob,
		recipients: []*introduce.Recipient{
			{MyDID: Bob, TheirDID: Alice},
		},
		transportKey:     Bob,
		startWithRequest: true,
	})

	// introducee side Carol
	go checkAndHandle(&flow{
		t:            t,
		controller:   ctrl,
		wg:           &wg,
		svc:          carol,
		transport:    transport,
		dependency:   carolDep,
		didEvent:     didEventCarol,
		transportKey: Carol,
		recipients: []*introduce.Recipient{
			{MyDID: Carol, TheirDID: Alice},
		},
	})

	wg.Wait()
}

// This test describes the following flow :
// 1. Bob sends introduce.Request to the Alice
// 2. Alice sends introduce.Proposal to the Bob
// 3. Bob sends introduce.Response to the Alice
// 4. Alice sends introduce.Proposal to the Carol
// 5. Carol sends introduce.Response to the Alice
// 6. Alice sends didexchange.Invitation to the Bob
// 7. Alice sends model.Ack to the Carol
func TestService_ProposalUnusualWithRequest(t *testing.T) {
	var transport = transport()

	inv := &didexchange.Invitation{ID: uuid.New().String(), Type: didexchange.InvitationMsgType, Label: Carol}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	msgr := newMessenger(&flow{t: t, controller: ctrl, transport: transport})

	alice, aliceDep := setupIntroducer(&flow{
		t:            t,
		controller:   ctrl,
		expectedInv:  inv,
		transportKey: Alice,
		messenger:    msgr,
		transport:    transport,
		recipients: []*introduce.Recipient{
			{To: &introduce.To{Name: Carol}},
			{To: &introduce.To{Name: Bob}, MyDID: Alice, TheirDID: Carol},
		},
	})

	defer stop(t, alice)

	bob, bobDep, didEventBob := setupIntroducee(&flow{
		t:            t,
		controller:   ctrl,
		transportKey: Bob,
		messenger:    msgr,
		transport:    transport,
	})
	defer stop(t, bob)

	carol, carolDep, didEventCarol := setupIntroducee(&flow{
		t:            t,
		controller:   ctrl,
		inv:          inv,
		transportKey: Carol,
		messenger:    msgr,
		transport:    transport,
	})
	defer stop(t, carol)

	var wg sync.WaitGroup

	wg.Add(3)

	// introducer side Alice
	go checkAndHandle(&flow{
		t:            t,
		controller:   ctrl,
		wg:           &wg,
		svc:          alice,
		transport:    transport,
		dependency:   aliceDep,
		transportKey: Alice,
		recipients: []*introduce.Recipient{
			{MyDID: Alice, TheirDID: Bob},
		},
	})

	// introducee side Bob
	go checkAndHandle(&flow{
		t:          t,
		wg:         &wg,
		svc:        bob,
		transport:  transport,
		dependency: bobDep,
		didEvent:   didEventBob,
		recipients: []*introduce.Recipient{
			{MyDID: Bob, TheirDID: Alice},
		},
		transportKey:     Bob,
		startWithRequest: true,
	})

	// introducee side Carol
	go checkAndHandle(&flow{
		t:            t,
		controller:   ctrl,
		wg:           &wg,
		svc:          carol,
		transport:    transport,
		dependency:   carolDep,
		didEvent:     didEventCarol,
		transportKey: Carol,
		recipients: []*introduce.Recipient{
			{MyDID: Carol, TheirDID: Alice},
		},
	})

	wg.Wait()
}

// This test describes the following flow :
// 1. Alice sends introduce.Proposal to the Bob
// 2. Bob sends introduce.Response to the Alice
// 3. Alice sends introduce.Proposal to the Carol
// 4. Carol sends introduce.Response to the Alice
// 5. Alice sends model.ProblemReport to the Bob
// 6. Alice sends model.ProblemReport to the Carol
func TestService_ProposalNoInvitation(t *testing.T) {
	var transport = transport()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	msgr := newMessenger(&flow{t: t, controller: ctrl, transport: transport})

	alice, aliceDep := setupIntroducer(&flow{
		t:            t,
		controller:   ctrl,
		transportKey: Alice,
		messenger:    msgr,
		transport:    transport,
		recipients: []*introduce.Recipient{
			{MyDID: Alice, TheirDID: Bob},
			{To: &introduce.To{Name: Bob}, MyDID: Alice, TheirDID: Carol},
		},
	})

	defer stop(t, alice)

	bob, bobDep, didEventBob := setupIntroducee(&flow{
		t:            t,
		controller:   ctrl,
		transportKey: Bob,
		messenger:    msgr,
		transport:    transport,
	})
	defer stop(t, bob)

	carol, carolDep, didEventCarol := setupIntroducee(&flow{
		t:            t,
		controller:   ctrl,
		transportKey: Carol,
		messenger:    msgr,
		transport:    transport,
	})
	defer stop(t, carol)

	var wg sync.WaitGroup

	wg.Add(3)

	// introducer side Alice
	go checkAndHandle(&flow{
		t:            t,
		controller:   ctrl,
		wg:           &wg,
		svc:          alice,
		transport:    transport,
		dependency:   aliceDep,
		transportKey: Alice,
		recipients: []*introduce.Recipient{
			{To: &introduce.To{Name: Carol}, MyDID: Alice, TheirDID: Bob},
		},
		withSecondResponseError: true,
		startWithProposal:       true,
	})

	// introducee side Bob
	go checkAndHandle(&flow{
		t:            t,
		controller:   ctrl,
		wg:           &wg,
		svc:          bob,
		transport:    transport,
		dependency:   bobDep,
		didEvent:     didEventBob,
		transportKey: Bob,
		recipients: []*introduce.Recipient{
			{MyDID: Bob, TheirDID: Alice},
		},
	})

	// introducee side Carol
	go checkAndHandle(&flow{
		t:            t,
		controller:   ctrl,
		wg:           &wg,
		svc:          carol,
		transport:    transport,
		dependency:   carolDep,
		didEvent:     didEventCarol,
		transportKey: Carol,
		recipients: []*introduce.Recipient{
			{MyDID: Carol, TheirDID: Alice},
		},
	})

	wg.Wait()
}

// This test describes the following flow :
// 1. Bob sends introduce.Request to the Alice
// 2. Alice sends introduce.Proposal to the Bob
// 3. Bob sends introduce.Response to the Alice
// 4. Alice sends introduce.Proposal to the Carol
// 5. Carol sends introduce.Response to the Alice
// 6. Alice sends model.ProblemReport to the Bob
// 7. Alice sends model.ProblemReport to the Carol
// nolint: gocyclo
func TestService_ProposalNoInvitationWithRequest(t *testing.T) {
	var transport = transport()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	msgr := newMessenger(&flow{t: t, controller: ctrl, transport: transport})

	alice, aliceDep := setupIntroducer(&flow{
		t:            t,
		controller:   ctrl,
		transportKey: Alice,
		messenger:    msgr,
		transport:    transport,
		recipients: []*introduce.Recipient{
			{To: &introduce.To{Name: Carol}},
			{To: &introduce.To{Name: Bob}, MyDID: Alice, TheirDID: Carol},
		},
	})

	defer stop(t, alice)

	bob, bobDep, didEventBob := setupIntroducee(&flow{
		t:            t,
		controller:   ctrl,
		transportKey: Bob,
		messenger:    msgr,
		transport:    transport,
	})
	defer stop(t, bob)

	carol, carolDep, didEventCarol := setupIntroducee(&flow{
		t:            t,
		controller:   ctrl,
		transportKey: Carol,
		messenger:    msgr,
		transport:    transport,
	})
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
		recipients: []*introduce.Recipient{
			{MyDID: Alice, TheirDID: Bob},
		},
		withSecondResponseError: true,
	})

	// introducee side Bob
	go checkAndHandle(&flow{
		t:          t,
		wg:         &wg,
		svc:        bob,
		transport:  transport,
		dependency: bobDep,
		didEvent:   didEventBob,
		recipients: []*introduce.Recipient{
			{MyDID: Bob, TheirDID: Alice},
		},
		transportKey:     Bob,
		startWithRequest: true,
	})

	// introducee side Carol
	go checkAndHandle(&flow{
		t:            t,
		controller:   ctrl,
		wg:           &wg,
		svc:          carol,
		transport:    transport,
		dependency:   carolDep,
		didEvent:     didEventCarol,
		transportKey: Carol,
		recipients: []*introduce.Recipient{
			{MyDID: Carol, TheirDID: Alice},
		},
	})

	wg.Wait()
}

// This test describes the following flow :
// 1. Alice sends introduce.Proposal to the Bob
// 2. Bob sends introduce.Response to the Alice
func TestService_ProposalStop(t *testing.T) {
	var transport = transport()

	inv := &didexchange.Invitation{ID: uuid.New().String(), Type: didexchange.InvitationMsgType, Label: Bob}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	msgr := newMessenger(&flow{t: t, controller: ctrl, transport: transport})

	alice, aliceDep := setupIntroducer(&flow{
		t:            t,
		controller:   ctrl,
		expectedInv:  inv,
		transportKey: Alice,
		messenger:    msgr,
		transport:    transport,
	})

	defer stop(t, alice)

	bob, bobDep, didEventBob := setupIntroducee(&flow{
		t:            t,
		controller:   ctrl,
		inv:          inv,
		transportKey: Bob,
		messenger:    msgr,
		transport:    transport,
	})
	defer stop(t, bob)

	var wg sync.WaitGroup

	wg.Add(2)

	// introducer side Alice
	go checkAndHandle(&flow{
		t:            t,
		controller:   ctrl,
		wg:           &wg,
		svc:          alice,
		transport:    transport,
		dependency:   aliceDep,
		transportKey: Alice,
		recipients: []*introduce.Recipient{
			{To: &introduce.To{Name: Carol}, MyDID: Alice, TheirDID: Bob},
		},
		startWithProposal: true,
		withResponseError: true,
	})

	// introducee side Bob
	go checkAndHandle(&flow{
		t:            t,
		wg:           &wg,
		svc:          bob,
		transport:    transport,
		dependency:   bobDep,
		didEvent:     didEventBob,
		transportKey: Bob,
		recipients: []*introduce.Recipient{
			{MyDID: Bob, TheirDID: Alice},
		},
		withProposalStop: true,
	})

	wg.Wait()
}

// This test describes the following flow :
// 1. Bob sends introduce.Request to the Alice
// 2. Alice sends introduce.Proposal to the Bob
// 3. Bob sends introduce.Response to the Alice
func TestService_ProposalStopWithRequest(t *testing.T) {
	var transport = transport()

	inv := &didexchange.Invitation{ID: uuid.New().String(), Type: didexchange.InvitationMsgType, Label: Bob}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	msgr := newMessenger(&flow{t: t, controller: ctrl, transport: transport})

	alice, aliceDep := setupIntroducer(&flow{
		t:            t,
		controller:   ctrl,
		expectedInv:  inv,
		transportKey: Alice,
		messenger:    msgr,
		transport:    transport,
		recipients: []*introduce.Recipient{
			{To: &introduce.To{Name: Carol}},
		},
	})

	defer stop(t, alice)

	bob, bobDep, didEventBob := setupIntroducee(&flow{
		t:            t,
		controller:   ctrl,
		inv:          inv,
		transportKey: Bob,
		messenger:    msgr,
		transport:    transport,
	})
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
		recipients: []*introduce.Recipient{
			{MyDID: Alice, TheirDID: Bob},
		},
		withResponseError: true,
	})

	// introducee side Bob
	go checkAndHandle(&flow{
		t:          t,
		wg:         &wg,
		svc:        bob,
		transport:  transport,
		dependency: bobDep,
		didEvent:   didEventBob,
		recipients: []*introduce.Recipient{
			{MyDID: Bob, TheirDID: Alice},
		},
		transportKey:     Bob,
		startWithRequest: true,
		withProposalStop: true,
	})

	wg.Wait()
}

// This test describes the following flow :
// 1. Alice sends introduce.Proposal to the Bob
// 2. Bob sends introduce.Response to the Alice
func TestService_SkipProposalStop(t *testing.T) {
	var transport = transport()

	inv := &didexchange.Invitation{
		ID:    uuid.New().String(),
		Type:  didexchange.InvitationMsgType,
		Label: "Public Invitation",
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	msgr := newMessenger(&flow{t: t, controller: ctrl, transport: transport})

	alice, aliceDep := setupIntroducer(&flow{
		t:            t,
		controller:   ctrl,
		inv:          inv,
		expectedInv:  inv,
		transportKey: Alice,
		messenger:    msgr,
		transport:    transport,
	})

	defer stop(t, alice)

	bob, bobDep, didEventBob := setupIntroducee(&flow{
		t:            t,
		controller:   ctrl,
		transportKey: Bob,
		inv:          &didexchange.Invitation{Label: Bob},
		messenger:    msgr,
		transport:    transport,
	})
	defer stop(t, bob)

	var wg sync.WaitGroup

	wg.Add(2)

	// introducer side Alice
	go checkAndHandle(&flow{
		t:            t,
		controller:   ctrl,
		wg:           &wg,
		svc:          alice,
		transport:    transport,
		dependency:   aliceDep,
		transportKey: Alice,
		recipients: []*introduce.Recipient{
			{To: &introduce.To{Name: Carol}, MyDID: Alice, TheirDID: Bob},
		},
		skipProposal:      true,
		startWithProposal: true,
		withResponseError: true,
	})

	// introducee side Bob
	go checkAndHandle(&flow{
		t:            t,
		wg:           &wg,
		svc:          bob,
		transport:    transport,
		dependency:   bobDep,
		didEvent:     didEventBob,
		transportKey: Bob,
		recipients: []*introduce.Recipient{
			{MyDID: Bob, TheirDID: Alice},
		},
		withProposalStop: true,
	})

	wg.Wait()
}

// This test describes the following flow :
// 1. Bob sends introduce.Request to the Alice
// 2. Alice sends introduce.Proposal to the Bob
// 3. Bob sends introduce.Response to the Alice
func TestService_SkipProposalStopWithRequest(t *testing.T) {
	var transport = transport()

	inv := &didexchange.Invitation{
		ID:    uuid.New().String(),
		Type:  didexchange.InvitationMsgType,
		Label: "Public Invitation",
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	msgr := newMessenger(&flow{t: t, controller: ctrl, transport: transport})

	alice, aliceDep := setupIntroducer(&flow{
		t:            t,
		controller:   ctrl,
		inv:          inv,
		expectedInv:  inv,
		transportKey: Alice,
		messenger:    msgr,
		transport:    transport,
		recipients: []*introduce.Recipient{
			{To: &introduce.To{Name: Bob}},
		},
	})

	defer stop(t, alice)

	bob, bobDep, didEventBob := setupIntroducee(&flow{
		t:            t,
		controller:   ctrl,
		inv:          &didexchange.Invitation{Label: Bob},
		transportKey: Bob,
		messenger:    msgr,
		transport:    transport,
	})
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
		recipients: []*introduce.Recipient{
			{MyDID: Alice, TheirDID: Bob},
		},
		skipProposal:      true,
		withResponseError: true,
	})

	// introducee side Bob
	go checkAndHandle(&flow{
		t:          t,
		wg:         &wg,
		svc:        bob,
		transport:  transport,
		dependency: bobDep,
		didEvent:   didEventBob,
		recipients: []*introduce.Recipient{
			{MyDID: Bob, TheirDID: Alice},
		},
		transportKey:     Bob,
		startWithRequest: true,
		withProposalStop: true,
	})

	wg.Wait()
}

// This test describes the following flow :
// 1. Alice sends introduce.Proposal to the Bob
// 2. Bob sends introduce.Response to the Alice
// 3. Alice sends introduce.Proposal to the Carol
// 4. Carol sends introduce.Response to the Alice
// 5. Alice sends model.ProblemReport to the Bob
func TestService_ProposalStopUnusual(t *testing.T) {
	var transport = transport()

	inv := &didexchange.Invitation{ID: uuid.New().String(), Type: didexchange.InvitationMsgType, Label: Carol}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	msgr := newMessenger(&flow{t: t, controller: ctrl, transport: transport})

	alice, aliceDep := setupIntroducer(&flow{
		t:            t,
		controller:   ctrl,
		expectedInv:  inv,
		transportKey: Alice,
		messenger:    msgr,
		transport:    transport,
		recipients: []*introduce.Recipient{
			{MyDID: Alice, TheirDID: Bob},
			{To: &introduce.To{Name: Bob}, MyDID: Alice, TheirDID: Carol},
		},
	})

	defer stop(t, alice)

	bob, bobDep, didEventBob := setupIntroducee(&flow{
		t:            t,
		controller:   ctrl,
		transportKey: Bob,
		messenger:    msgr,
		transport:    transport,
	})
	defer stop(t, bob)

	carol, carolDep, didEventCarol := setupIntroducee(&flow{
		t:            t,
		controller:   ctrl,
		inv:          inv,
		transportKey: Carol,
		messenger:    msgr,
		transport:    transport,
	})
	defer stop(t, carol)

	var wg sync.WaitGroup

	wg.Add(3)

	// introducer side Alice
	go checkAndHandle(&flow{
		t:            t,
		controller:   ctrl,
		wg:           &wg,
		svc:          alice,
		transport:    transport,
		dependency:   aliceDep,
		transportKey: Alice,
		recipients: []*introduce.Recipient{
			{To: &introduce.To{Name: Carol}, MyDID: Alice, TheirDID: Bob},
		},
		startWithProposal:       true,
		withSecondResponseError: true,
	})

	// introducee side Bob
	go checkAndHandle(&flow{
		t:            t,
		controller:   ctrl,
		wg:           &wg,
		svc:          bob,
		transport:    transport,
		dependency:   bobDep,
		didEvent:     didEventBob,
		transportKey: Bob,
		recipients: []*introduce.Recipient{
			{MyDID: Bob, TheirDID: Alice},
		},
	})

	// introducee side Carol
	go checkAndHandle(&flow{
		t:            t,
		wg:           &wg,
		svc:          carol,
		transport:    transport,
		dependency:   carolDep,
		didEvent:     didEventCarol,
		transportKey: Carol,
		recipients: []*introduce.Recipient{
			{MyDID: Carol, TheirDID: Alice},
		},
		withProposalStop: true,
	})

	wg.Wait()
}

// This test describes the following flow :
// 1. Bob sends introduce.Request to the Alice
// 2. Alice sends introduce.Proposal to the Bob
// 3. Bob sends introduce.Response to the Alice
// 4. Alice sends introduce.Proposal to the Carol
// 5. Carol sends introduce.Response to the Alice
// 6. Alice sends model.ProblemReport to the Bob
func TestService_ProposalStopUnusualWithRequest(t *testing.T) {
	var transport = transport()

	inv := &didexchange.Invitation{ID: uuid.New().String(), Type: didexchange.InvitationMsgType, Label: Carol}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	msgr := newMessenger(&flow{t: t, controller: ctrl, transport: transport})

	alice, aliceDep := setupIntroducer(&flow{
		t:            t,
		controller:   ctrl,
		expectedInv:  inv,
		messenger:    msgr,
		transport:    transport,
		transportKey: Alice,
		recipients: []*introduce.Recipient{
			{To: &introduce.To{Name: Carol}},
			{To: &introduce.To{Name: Bob}, MyDID: Alice, TheirDID: Carol},
		},
	})

	defer stop(t, alice)

	bob, bobDep, didEventBob := setupIntroducee(&flow{
		t:            t,
		controller:   ctrl,
		transportKey: Bob,
		messenger:    msgr,
		transport:    transport,
	})
	defer stop(t, bob)

	carol, carolDep, didEventCarol := setupIntroducee(&flow{
		t:            t,
		controller:   ctrl,
		inv:          inv,
		transportKey: Carol,
		messenger:    msgr,
		transport:    transport,
	})
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
		recipients: []*introduce.Recipient{
			{MyDID: Alice, TheirDID: Bob},
		},
		withSecondResponseError: true,
	})

	// introducee side Bob
	go checkAndHandle(&flow{
		t:          t,
		wg:         &wg,
		svc:        bob,
		transport:  transport,
		dependency: bobDep,
		didEvent:   didEventBob,
		recipients: []*introduce.Recipient{
			{MyDID: Bob, TheirDID: Alice},
		},
		transportKey:     Bob,
		startWithRequest: true,
	})

	// introducee side Carol
	go checkAndHandle(&flow{
		t:            t,
		wg:           &wg,
		svc:          carol,
		transport:    transport,
		dependency:   carolDep,
		didEvent:     didEventCarol,
		transportKey: Carol,
		recipients: []*introduce.Recipient{
			{MyDID: Carol, TheirDID: Alice},
		},
		withProposalStop: true,
	})

	wg.Wait()
}

// This test describes the following flow :
// 1. Bob sends introduce.Request to the Alice
// 2. Alice sends model.ProblemReport to the Bob
func TestService_ProposalIntroducerStopWithRequest(t *testing.T) {
	var transport = transport()

	inv := &didexchange.Invitation{ID: uuid.New().String(), Type: didexchange.InvitationMsgType, Label: Bob}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	msgr := newMessenger(&flow{t: t, controller: ctrl, transport: transport})

	alice, aliceDep := setupIntroducer(&flow{
		t:            t,
		controller:   ctrl,
		expectedInv:  inv,
		messenger:    msgr,
		transport:    transport,
		transportKey: Alice,
	})

	defer stop(t, alice)

	bob, bobDep, didEventBob := setupIntroducee(&flow{
		t:            t,
		controller:   ctrl,
		inv:          inv,
		transportKey: Bob,
		messenger:    msgr,
		transport:    transport,
	})
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
		recipients: []*introduce.Recipient{
			{MyDID: Alice, TheirDID: Bob},
		},
		withRequestStop: true,
	})

	// introducee side Bob
	go checkAndHandle(&flow{
		t:          t,
		wg:         &wg,
		svc:        bob,
		transport:  transport,
		dependency: bobDep,
		didEvent:   didEventBob,
		recipients: []*introduce.Recipient{
			{MyDID: Bob, TheirDID: Alice},
		},
		transportKey:     Bob,
		startWithRequest: true,
	})

	wg.Wait()
}

// This test describes the following flow :
// 1. Alice sends introduce.Proposal to the Bob
// 2. Bob sends introduce.Response to the Alice
// 3. Alice sends model.ProblemReport to the Bob
func TestService_ProposalIntroducerStop(t *testing.T) {
	var transport = transport()

	inv := &didexchange.Invitation{ID: uuid.New().String(), Type: didexchange.InvitationMsgType, Label: Bob}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	msgr := newMessenger(&flow{t: t, controller: ctrl, transport: transport})

	alice, aliceDep := setupIntroducer(&flow{
		t:            t,
		controller:   ctrl,
		expectedInv:  inv,
		messenger:    msgr,
		transport:    transport,
		transportKey: Alice,
	})

	defer stop(t, alice)

	bob, bobDep, didEventBob := setupIntroducee(&flow{
		t:            t,
		controller:   ctrl,
		inv:          inv,
		transportKey: Bob,
		messenger:    msgr,
		transport:    transport,
	})
	defer stop(t, bob)

	var wg sync.WaitGroup

	wg.Add(2)

	// introducer side Alice
	go checkAndHandle(&flow{
		t:            t,
		controller:   ctrl,
		wg:           &wg,
		svc:          alice,
		transport:    transport,
		dependency:   aliceDep,
		transportKey: Alice,
		recipients: []*introduce.Recipient{
			{To: &introduce.To{Name: Carol}, MyDID: Alice, TheirDID: Bob},
		},
		startWithProposal: true,
		withResponseStop:  true,
	})

	// introducee side Bob
	go checkAndHandle(&flow{
		t:            t,
		controller:   ctrl,
		wg:           &wg,
		svc:          bob,
		transport:    transport,
		dependency:   bobDep,
		didEvent:     didEventBob,
		transportKey: Bob,
		recipients: []*introduce.Recipient{
			{MyDID: Bob, TheirDID: Alice},
		},
	})

	wg.Wait()
}

// This test describes the following flow :
// 1. Bob sends introduce.Request to the Alice
// 2. Alice sends introduce.Proposal to the Bob
// 3. Bob sends introduce.Response to the Alice
// 4. Alice sends model.ProblemReport to the Bob
func TestService_SkipProposalIntroducerStopWithRequest(t *testing.T) {
	var transport = transport()

	inv := &didexchange.Invitation{
		ID:    uuid.New().String(),
		Type:  didexchange.InvitationMsgType,
		Label: "Public Invitation",
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	msgr := newMessenger(&flow{t: t, controller: ctrl, transport: transport})

	alice, aliceDep := setupIntroducer(&flow{
		t:            t,
		controller:   ctrl,
		inv:          inv,
		expectedInv:  inv,
		transportKey: Alice,
		messenger:    msgr,
		transport:    transport,
		recipients: []*introduce.Recipient{
			{To: &introduce.To{Name: Carol}},
		},
	})

	defer stop(t, alice)

	bob, bobDep, didEventBob := setupIntroducee(&flow{
		t:            t,
		controller:   ctrl,
		transportKey: Bob,
		inv:          &didexchange.Invitation{Label: Bob},
		messenger:    msgr,
		transport:    transport,
	})
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
		recipients: []*introduce.Recipient{
			{MyDID: Alice, TheirDID: Bob},
		},
		skipProposal:     true,
		withResponseStop: true,
	})

	// introducee side Bob
	go checkAndHandle(&flow{
		t:          t,
		wg:         &wg,
		svc:        bob,
		transport:  transport,
		dependency: bobDep,
		didEvent:   didEventBob,
		recipients: []*introduce.Recipient{
			{MyDID: Bob, TheirDID: Alice},
		},
		transportKey:     Bob,
		startWithRequest: true,
	})

	wg.Wait()
}

// This test describes the following flow :
// 1. Alice sends introduce.Proposal to the Bob
// 2. Bob sends introduce.Response to the Alice
// 3. Alice sends introduce.Proposal to the Carol
// 4. Carol sends introduce.Response to the Alice
// 5. Alice sends model.ProblemReport to the Bob
// 6. Alice sends model.ProblemReport to the Carol
func TestService_ProposalIntroducerSecondStop(t *testing.T) {
	var transport = transport()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	msgr := newMessenger(&flow{t: t, controller: ctrl, transport: transport})

	alice, aliceDep := setupIntroducer(&flow{
		t:            t,
		controller:   ctrl,
		transportKey: Alice,
		messenger:    msgr,
		transport:    transport,
		recipients: []*introduce.Recipient{
			{MyDID: Alice, TheirDID: Bob},
			{To: &introduce.To{Name: Bob}, MyDID: Alice, TheirDID: Carol},
		},
	})

	defer stop(t, alice)

	bob, bobDep, didEventBob := setupIntroducee(&flow{
		t:            t,
		controller:   ctrl,
		transportKey: Bob,
		messenger:    msgr,
		transport:    transport,
	})
	defer stop(t, bob)

	carol, carolDep, didEventCarol := setupIntroducee(&flow{
		t:            t,
		controller:   ctrl,
		transportKey: Carol,
		messenger:    msgr,
		transport:    transport,
	})
	defer stop(t, carol)

	var wg sync.WaitGroup

	wg.Add(3)

	// introducer side Alice
	go checkAndHandle(&flow{
		t:            t,
		controller:   ctrl,
		wg:           &wg,
		svc:          alice,
		transport:    transport,
		dependency:   aliceDep,
		transportKey: Alice,
		recipients: []*introduce.Recipient{
			{To: &introduce.To{Name: Carol}, MyDID: Alice, TheirDID: Bob},
		},
		startWithProposal:      true,
		withSecondResponseStop: true,
	})

	// introducee side Bob
	go checkAndHandle(&flow{
		t:            t,
		controller:   ctrl,
		wg:           &wg,
		svc:          bob,
		transport:    transport,
		dependency:   bobDep,
		didEvent:     didEventBob,
		transportKey: Bob,
		recipients: []*introduce.Recipient{
			{MyDID: Bob, TheirDID: Alice},
		},
	})

	// introducee side Carol
	go checkAndHandle(&flow{
		t:            t,
		controller:   ctrl,
		wg:           &wg,
		svc:          carol,
		transport:    transport,
		dependency:   carolDep,
		didEvent:     didEventCarol,
		transportKey: Carol,
		recipients: []*introduce.Recipient{
			{MyDID: Carol, TheirDID: Alice},
		},
	})

	wg.Wait()
}

// This test describes the following flow :
// 1. Bob sends introduce.Request to the Alice
// 2. Alice sends introduce.Proposal to the Bob
// 3. Bob sends introduce.Response to the Alice
// 4. Alice sends introduce.Proposal to the Carol
// 5. Carol sends introduce.Response to the Alice
// 6. Alice sends model.ProblemReport to the Bob
// 7. Alice sends model.ProblemReport to the Carol
// nolint: gocyclo
func TestService_ProposalIntroducerSecondStopWithRequest(t *testing.T) {
	var transport = transport()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	msgr := newMessenger(&flow{t: t, controller: ctrl, transport: transport})

	alice, aliceDep := setupIntroducer(&flow{
		t:            t,
		controller:   ctrl,
		transportKey: Alice,
		messenger:    msgr,
		transport:    transport,
		recipients: []*introduce.Recipient{
			{To: &introduce.To{Name: Carol}},
			{To: &introduce.To{Name: Bob}, MyDID: Alice, TheirDID: Carol},
		},
	})

	defer stop(t, alice)

	bob, bobDep, didEventBob := setupIntroducee(&flow{
		t:            t,
		controller:   ctrl,
		transportKey: Bob,
		messenger:    msgr,
		transport:    transport,
	})
	defer stop(t, bob)

	carol, carolDep, didEventCarol := setupIntroducee(&flow{
		t:            t,
		controller:   ctrl,
		transportKey: Carol,
		messenger:    msgr,
		transport:    transport,
	})
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
		recipients: []*introduce.Recipient{
			{MyDID: Alice, TheirDID: Bob},
		},
		withSecondResponseStop: true,
	})

	// introducee side Bob
	go checkAndHandle(&flow{
		t:          t,
		wg:         &wg,
		svc:        bob,
		transport:  transport,
		dependency: bobDep,
		didEvent:   didEventBob,
		recipients: []*introduce.Recipient{
			{MyDID: Bob, TheirDID: Alice},
		},
		transportKey:     Bob,
		startWithRequest: true,
	})

	// introducee side Carol
	go checkAndHandle(&flow{
		t:            t,
		controller:   ctrl,
		wg:           &wg,
		svc:          carol,
		transport:    transport,
		dependency:   carolDep,
		didEvent:     didEventCarol,
		transportKey: Carol,
		recipients: []*introduce.Recipient{
			{MyDID: Carol, TheirDID: Alice},
		},
	})

	wg.Wait()
}

func setupIntroducer(f *flow) (*introduce.Service, *introduceMocks.MockInvitationEnvelope) {
	ctrl := f.controller

	storageProvider := storageMocks.NewMockProvider(ctrl)
	storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(fakeStore(ctrl), nil)

	didService := serviceMocks.NewMockDIDComm(ctrl)
	didService.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
	didService.EXPECT().UnregisterMsgEvent(gomock.Any()).Return(nil)

	provider := introduceMocks.NewMockProvider(ctrl)
	provider.EXPECT().StorageProvider().Return(storageProvider)
	provider.EXPECT().Messenger().Return(f.messenger)
	provider.EXPECT().Service(didexchange.DIDExchange).Return(didService, nil)

	svc, err := introduce.New(provider)
	require.NoError(f.t, err)

	dep := introduceMocks.NewMockInvitationEnvelope(ctrl)

	dep.EXPECT().Invitation().Return(f.inv).AnyTimes()
	dep.EXPECT().Recipients().Return(f.recipients).AnyTimes()

	return svc, dep
}

func setupIntroducee(f *flow) (*introduce.Service, *introduceMocks.MockInvitationEnvelope, chan<- service.StateMsg) {
	ctrl := f.controller

	storageProvider := storageMocks.NewMockProvider(ctrl)
	storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(fakeStore(ctrl), nil)

	var didChan chan<- service.StateMsg

	didService := serviceMocks.NewMockDIDComm(ctrl)
	didService.EXPECT().RegisterMsgEvent(gomock.Any()).Do(func(ch chan<- service.StateMsg) error {
		didChan = ch
		return nil
	})
	didService.EXPECT().UnregisterMsgEvent(gomock.Any()).Return(nil)

	provider := introduceMocks.NewMockProvider(ctrl)
	provider.EXPECT().StorageProvider().Return(storageProvider)
	provider.EXPECT().Messenger().Return(f.messenger)
	provider.EXPECT().Service(didexchange.DIDExchange).Return(didService, nil)

	svc, err := introduce.New(provider)
	require.NoError(f.t, err)

	dep := introduceMocks.NewMockInvitationEnvelope(ctrl)
	dep.EXPECT().Invitation().Return(f.inv).AnyTimes()
	dep.EXPECT().Recipients().Return(f.recipients).AnyTimes()

	return svc, dep, didChan
}

func handleInbound(t *testing.T, svc service.InboundHandler, msg interface{}, myDID, theirDID string) {
	t.Helper()

	resp, err := service.ParseDIDCommMsgMap(toBytes(t, msg))
	require.NoError(t, err)
	_, err = svc.HandleInbound(resp, myDID, theirDID)
	require.NoError(t, err)
}

// nolint: gocyclo,gocognit
func checkAndHandle(f *flow) {
	defer f.wg.Done()

	// register action event channel
	aCh := make(chan service.DIDCommAction)
	require.NoError(f.t, f.svc.RegisterActionEvent(aCh))

	// register action event channel
	sCh := make(chan service.StateMsg)
	require.NoError(f.t, f.svc.RegisterMsgEvent(sCh))

	if f.startWithRequest {
		// creates request msg
		request, err := service.ParseDIDCommMsgMap(toBytes(f.t, introduce.Request{
			Type: introduce.RequestMsgType,
			// creates threadID
			ID: uuid.New().String(),
		}))
		require.NoError(f.t, err)

		go func() {
			// handle outbound Request msg
			require.NoError(f.t, f.svc.HandleOutbound(request, f.recipients[0].MyDID, f.recipients[0].TheirDID))
		}()
		checkStateMsg(f.t, sCh, service.PreState, introduce.RequestMsgType, "requesting")
		checkStateMsg(f.t, sCh, service.PostState, introduce.RequestMsgType, "requesting")
	}

	if f.startWithProposal {
		// creates proposal msg
		proposal, err := service.ParseDIDCommMsgMap(toBytes(f.t, introduce.Proposal{
			Type: introduce.ProposalMsgType,
			// creates threadID
			ID: uuid.New().String(),
			To: f.recipients[0].To,
		}))
		require.NoError(f.t, err)

		go func() {
			// handle outbound Proposal msg
			require.NoError(f.t, f.svc.HandleOutbound(proposal, f.recipients[0].MyDID, f.recipients[0].TheirDID))
		}()
		checkStateMsg(f.t, sCh, service.PreState, introduce.ProposalMsgType, "arranging")
		checkStateMsg(f.t, sCh, service.PostState, introduce.ProposalMsgType, "arranging")
	}

	var responseCounter int

	for {
		var incomingMsg service.DIDCommMsg
		select {
		case incomingMsg = <-f.transport[f.transportKey]:
		case <-time.After(time.Second):
			f.t.Error("timeout")
			return
		}

		switch incomingMsg.Type() {
		case introduce.RequestMsgType:
			go handleInbound(f.t, f.svc, incomingMsg, f.recipients[0].MyDID, f.recipients[0].TheirDID)

			if f.withRequestStop {
				continueActionStop(f.t, aCh, introduce.RequestMsgType)

				checkStateMsg(f.t, sCh, service.PreState, introduce.RequestMsgType, "abandoning")
				checkStateMsg(f.t, sCh, service.PostState, introduce.RequestMsgType, "abandoning")
				checkStateMsg(f.t, sCh, service.PreState, introduce.RequestMsgType, "done")
				checkStateMsg(f.t, sCh, service.PostState, introduce.RequestMsgType, "done")

				return
			}

			continueAction(f.t, aCh, introduce.RequestMsgType, f.dependency)

			checkStateMsg(f.t, sCh, service.PreState, introduce.RequestMsgType, "arranging")
			checkStateMsg(f.t, sCh, service.PostState, introduce.RequestMsgType, "arranging")
		case introduce.ResponseMsgType:
			responseCounter++

			go handleInbound(f.t, f.svc, incomingMsg, f.recipients[0].MyDID, f.recipients[0].TheirDID)

			if f.withResponseStop {
				continueActionStop(f.t, aCh, introduce.ResponseMsgType)
				checkStateMsg(f.t, sCh, service.PreState, introduce.ResponseMsgType, "abandoning")
				checkStateMsg(f.t, sCh, service.PostState, introduce.ResponseMsgType, "abandoning")

				checkStateMsg(f.t, sCh, service.PreState, introduce.ResponseMsgType, "done")
				checkStateMsg(f.t, sCh, service.PostState, introduce.ResponseMsgType, "done")

				return
			}

			if f.withSecondResponseStop && responseCounter == 2 {
				continueActionStop(f.t, aCh, introduce.ResponseMsgType)

				checkStateMsg(f.t, sCh, service.PreState, introduce.ResponseMsgType, "abandoning")
				checkStateMsg(f.t, sCh, service.PostState, introduce.ResponseMsgType, "abandoning")
				checkStateMsg(f.t, sCh, service.PreState, introduce.ResponseMsgType, "done")
				checkStateMsg(f.t, sCh, service.PostState, introduce.ResponseMsgType, "done")

				return
			}

			continueAction(f.t, aCh, introduce.ResponseMsgType, f.dependency)

			if f.skipProposal {
				checkStateMsg(f.t, sCh, service.PreState, introduce.ResponseMsgType, "arranging")
				checkStateMsg(f.t, sCh, service.PostState, introduce.ResponseMsgType, "arranging")

				checkStateMsg(f.t, sCh, service.PreState, introduce.ResponseMsgType, "delivering")
				checkStateMsg(f.t, sCh, service.PostState, introduce.ResponseMsgType, "delivering")

				if f.withResponseError {
					checkStateMsg(f.t, sCh, service.PreState, introduce.ResponseMsgType, "abandoning")
					checkStateMsg(f.t, sCh, service.PostState, introduce.ResponseMsgType, "abandoning")
				}

				checkStateMsg(f.t, sCh, service.PreState, introduce.ResponseMsgType, "done")
				checkStateMsg(f.t, sCh, service.PostState, introduce.ResponseMsgType, "done")

				return
			}

			// represents the Response from the first introducee
			if responseCounter == 1 {
				checkStateMsg(f.t, sCh, service.PreState, introduce.ResponseMsgType, "arranging")
				checkStateMsg(f.t, sCh, service.PostState, introduce.ResponseMsgType, "arranging")

				if f.withResponseError {
					checkStateMsg(f.t, sCh, service.PreState, introduce.ResponseMsgType, "abandoning")
					checkStateMsg(f.t, sCh, service.PostState, introduce.ResponseMsgType, "abandoning")

					checkStateMsg(f.t, sCh, service.PreState, introduce.ResponseMsgType, "done")
					checkStateMsg(f.t, sCh, service.PostState, introduce.ResponseMsgType, "done")

					return
				}

				break
			}

			checkStateMsg(f.t, sCh, service.PreState, introduce.ResponseMsgType, "delivering")
			checkStateMsg(f.t, sCh, service.PostState, introduce.ResponseMsgType, "delivering")

			if f.withSecondResponseError {
				checkStateMsg(f.t, sCh, service.PreState, introduce.ResponseMsgType, "abandoning")
				checkStateMsg(f.t, sCh, service.PostState, introduce.ResponseMsgType, "abandoning")
			} else {
				checkStateMsg(f.t, sCh, service.PreState, introduce.ResponseMsgType, "confirming")
				checkStateMsg(f.t, sCh, service.PostState, introduce.ResponseMsgType, "confirming")
			}

			checkStateMsg(f.t, sCh, service.PreState, introduce.ResponseMsgType, "done")
			checkStateMsg(f.t, sCh, service.PostState, introduce.ResponseMsgType, "done")

			return
		case introduce.ProposalMsgType:
			go handleInbound(f.t, f.svc, incomingMsg, f.recipients[0].MyDID, f.recipients[0].TheirDID)

			if f.withProposalStop {
				continueActionStop(f.t, aCh, introduce.ProposalMsgType)

				checkStateMsg(f.t, sCh, service.PreState, introduce.ProposalMsgType, "deciding")
				checkStateMsg(f.t, sCh, service.PostState, introduce.ProposalMsgType, "deciding")
				checkStateMsg(f.t, sCh, service.PreState, introduce.ProposalMsgType, "abandoning")
				checkStateMsg(f.t, sCh, service.PostState, introduce.ProposalMsgType, "abandoning")
				checkStateMsg(f.t, sCh, service.PreState, introduce.ProposalMsgType, "done")
				checkStateMsg(f.t, sCh, service.PostState, introduce.ProposalMsgType, "done")

				return
			}

			continueAction(f.t, aCh, introduce.ProposalMsgType, f.dependency)

			checkStateMsg(f.t, sCh, service.PreState, introduce.ProposalMsgType, "deciding")
			checkStateMsg(f.t, sCh, service.PostState, introduce.ProposalMsgType, "deciding")
			checkStateMsg(f.t, sCh, service.PreState, introduce.ProposalMsgType, "waiting")
			checkStateMsg(f.t, sCh, service.PostState, introduce.ProposalMsgType, "waiting")
		case introduce.ProblemReportMsgType:
			go handleInbound(f.t, f.svc, incomingMsg, f.recipients[0].MyDID, f.recipients[0].TheirDID)
			checkStateMsg(f.t, sCh, service.PreState, introduce.ProblemReportMsgType, "abandoning")
			checkStateMsg(f.t, sCh, service.PostState, introduce.ProblemReportMsgType, "abandoning")
			checkStateMsg(f.t, sCh, service.PreState, introduce.ProblemReportMsgType, "done")
			checkStateMsg(f.t, sCh, service.PostState, introduce.ProblemReportMsgType, "done")

			return
		case introduce.AckMsgType:
			go handleInbound(f.t, f.svc, incomingMsg, f.recipients[0].MyDID, f.recipients[0].TheirDID)
			checkStateMsg(f.t, sCh, service.PreState, introduce.AckMsgType, "done")
			checkStateMsg(f.t, sCh, service.PostState, introduce.AckMsgType, "done")

			return
		case didexchange.InvitationMsgType:
			go func() {
				f.didEvent <- service.StateMsg{
					Type:    service.PostState,
					StateID: "invited",
					Msg:     incomingMsg,
				}
			}()
			checkStateMsg(f.t, sCh, service.PreState, introduce.AckMsgType, "done")
			checkStateMsg(f.t, sCh, service.PostState, introduce.AckMsgType, "done")

			return
		}
	}
}

func transport() map[string]chan service.DIDCommMsg {
	// the map of channels which is responsible for the communication
	return map[string]chan service.DIDCommMsg{
		Alice: make(chan service.DIDCommMsg),
		Bob:   make(chan service.DIDCommMsg),
		Carol: make(chan service.DIDCommMsg),
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
		require.Equal(t, dType, res.Msg.Type())
		require.Equal(t, stateID, res.StateID)

		return
	case <-time.After(time.Second):
		t.Fatalf("timeout: waiting for %d %s - %s", sType, dType, stateID)
	}
}

func continueActionStop(t *testing.T, ch chan service.DIDCommAction, action string) {
	t.Helper()

	select {
	case res := <-ch:
		require.Equal(t, action, res.Message.Type())

		res.Stop(errors.New("stop error"))

		return
	case <-time.After(time.Second):
		t.Error("timeout")
	}
}

func continueAction(t *testing.T, ch chan service.DIDCommAction, action string, dep introduce.InvitationEnvelope) {
	t.Helper()

	select {
	case res := <-ch:
		require.Equal(t, action, res.Message.Type())

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

func TestService_InvitationReceived(t *testing.T) {
	t.Run("PreState is not correct", func(t *testing.T) {
		svc := &introduce.Service{}
		msg, err := service.ParseDIDCommMsgMap(toBytes(t, &didexchange.Invitation{Thread: &decorator.Thread{ID: "ID"}}))
		require.NoError(t, err)
		require.NoError(t, svc.InvitationReceived(service.StateMsg{
			Type:    service.PreState,
			StateID: "invited",
			Msg:     msg,
		}))
	})

	t.Run("StateID is not correct", func(t *testing.T) {
		// should not panic
		svc := &introduce.Service{}
		msg, err := service.ParseDIDCommMsgMap(toBytes(t, &didexchange.Invitation{}))
		require.NoError(t, err)
		require.NoError(t, svc.InvitationReceived(service.StateMsg{
			Type: service.PostState,
			Msg:  msg,
		}))
	})

	t.Run("Thread is nil", func(t *testing.T) {
		// should not panic
		svc := &introduce.Service{}
		msg, err := service.ParseDIDCommMsgMap(toBytes(t, &didexchange.Invitation{}))
		require.NoError(t, err)
		require.NoError(t, svc.InvitationReceived(service.StateMsg{
			Type:    service.PostState,
			StateID: "invited",
			Msg:     msg,
		}))
	})

	t.Run("No PID in Thread", func(t *testing.T) {
		svc := &introduce.Service{}
		msg, err := service.ParseDIDCommMsgMap(toBytes(t, &didexchange.Invitation{Thread: &decorator.Thread{ID: "ID"}}))
		require.NoError(t, err)
		require.NoError(t, svc.InvitationReceived(service.StateMsg{
			Type:    service.PostState,
			StateID: "invited",
			Msg:     msg,
		}))
	})
}
