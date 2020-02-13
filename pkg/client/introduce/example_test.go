// +build ignore

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"fmt"
	"sync"
	"time"

	"github.com/golang/mock/gomock"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messenger"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/introduce"
	clientIntroduceMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/client/introduce"
	serviceMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/common/service"
	dispatcherMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/dispatcher"
	messengerMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/messenger"
	protocolIntroduceMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/protocol/introduce"
	storageMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// TODO: remove init function [Issue #1158]
// nolint: gochecknoinits
func init() {
	// turns warnings off
	log.SetLevel("aries-framework/didcomm/messenger", log.ERROR)
}

const (
	Alice = "Alice"
	Bob   = "Bob"
	Carol = "Carol"
)

type transportMsg struct {
	msg      service.DIDCommMsg
	myDID    string
	theirDID string
}

func fakeStore(ctrl *gomock.Controller) storage.Store {
	mu := sync.Mutex{}
	store := storageMocks.NewMockStore(ctrl)
	data := make(map[string][]byte)

	store.EXPECT().Put(gomock.Any(), gomock.Any()).DoAndReturn(func(k string, v []byte) error {
		mu.Lock()
		data[k] = v
		mu.Unlock()
		return nil
	}).AnyTimes()
	store.EXPECT().Get(gomock.Any()).DoAndReturn(func(k string) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()

		v, ok := data[k]
		if !ok {
			return nil, storage.ErrDataNotFound
		}

		return v, nil
	}).AnyTimes()

	return store
}

func stateMsg(msg service.DIDCommMsg) service.StateMsg {
	return service.StateMsg{
		Type:    1,
		StateID: "invited",
		Msg:     msg,
	}
}

// nolint: gocyclo, gocognit
func provider(agent string, transport map[string]chan transportMsg) (Provider, chan struct{}) {
	ctrl := gomock.NewController(nil)

	// creates storage provider
	storageProvider := storageMocks.NewMockProvider(ctrl)
	storageProvider.EXPECT().
		OpenStore(introduce.Introduce).
		Return(fakeStore(ctrl), nil).
		AnyTimes()

	storageProvider.EXPECT().OpenStore(gomock.Any()).Return(fakeStore(ctrl), nil)
	dispatcherOutbound := dispatcherMocks.NewMockOutbound(ctrl)
	messengerProvider := messengerMocks.NewMockProvider(ctrl)
	messengerProvider.EXPECT().StorageProvider().Return(storageProvider)
	messengerProvider.EXPECT().OutboundDispatcher().Return(dispatcherOutbound)
	// use real messenger
	msgr, err := messenger.NewMessenger(messengerProvider)
	if err != nil {
		fmt.Println("messenger.NewMessenger", err)
	}

	dispatcherOutbound.EXPECT().
		SendToDID(gomock.Any(), gomock.Any(), gomock.Any()).
		Do(func(msg service.DIDCommMsg, myDID string, theirDID string) error {
			// sends a message
			transport[theirDID] <- transportMsg{
				msg:      msg.(service.DIDCommMsgMap),
				myDID:    myDID,
				theirDID: theirDID,
			}
			return nil
		}).AnyTimes()

	// creates didexchange service
	didexchangeService := serviceMocks.NewMockDIDComm(ctrl)
	didexchangeService.EXPECT().
		RegisterMsgEvent(gomock.Any()).
		Return(nil)

	// creates provider for the introduce
	introduceProvider := protocolIntroduceMocks.NewMockProvider(ctrl)
	introduceProvider.EXPECT().
		StorageProvider().
		Return(storageProvider)
	introduceProvider.EXPECT().
		Messenger().
		Return(msgr)
	introduceProvider.EXPECT().
		Service(didexchange.DIDExchange).
		Return(didexchangeService, nil)

	// creates introduce service
	svc, err := introduce.New(introduceProvider)
	if err != nil {
		fmt.Println("introduce.New", err)
		return nil, nil
	}

	done := make(chan struct{})

	stateMsgCh := make(chan service.StateMsg)

	err = svc.RegisterMsgEvent(stateMsgCh)
	if err != nil {
		fmt.Println("svc.RegisterMsgEvent", err)
		return nil, nil
	}

	go func() {
		for state := range stateMsgCh {
			if state.StateID == "done" && state.Type == service.PostState {
				close(done)
			}
		}
	}()

	go func() {
		for {
			select {
			case <-done:
				return
			case <-time.After(time.Second * 3):
				fmt.Println("timeout")
				close(done)
			case inboundMsg := <-transport[agent]:
				err = msgr.HandleInbound(inboundMsg.msg.(service.DIDCommMsgMap), inboundMsg.theirDID, inboundMsg.myDID)
				if err != nil {
					fmt.Println("HandleInbound", err)
				}

				if inboundMsg.msg.Type() != didexchange.InvitationMsgType {
					if _, err := svc.HandleInbound(inboundMsg.msg, inboundMsg.theirDID, inboundMsg.myDID); err != nil {
						fmt.Println("svc.HandleInbound", err)
						return
					}
				}

				// mocks didexchange logic by calling directly InvitationReceived function from the introduce service
				if err := svc.InvitationReceived(stateMsg(inboundMsg.msg)); err != nil {
					fmt.Println("InvitationReceived", err)
					return
				}
			}
		}
	}()

	clientStorageProvider := storageMocks.NewMockProvider(ctrl)
	clientStorageProvider.EXPECT().
		OpenStore(introduce.Introduce).
		Return(fakeStore(ctrl), nil).
		AnyTimes()

	introduceClientProvider := clientIntroduceMocks.NewMockProvider(ctrl)
	introduceClientProvider.EXPECT().
		Service(introduce.Introduce).
		Return(svc, nil)
	introduceClientProvider.EXPECT().
		StorageProvider().
		Return(clientStorageProvider)

	return introduceClientProvider, done
}

// nolint: gocyclo, govet
func ExampleTwoParticipants() {
	wg := sync.WaitGroup{}
	defer wg.Wait()

	var transport = map[string]chan transportMsg{
		Alice: make(chan transportMsg),
		Bob:   make(chan transportMsg),
	}

	// prepare the clients contexts
	aliceCtx, aliceDone := provider(Alice, transport)
	bobCtx, bobDone := provider(Bob, transport)

	// create client
	alice, err := New(aliceCtx, nil)
	if err != nil {
		fmt.Println("Alice client:", err)
	}

	// register for action events
	aliceActions := make(chan service.DIDCommAction)

	err = alice.RegisterActionEvent(aliceActions)
	if err != nil {
		fmt.Println("Alice RegisterActionEvent:", err)
	}

	// create client
	bob, err := New(bobCtx, nil)
	if err != nil {
		fmt.Println("Bob client:", err)
	}

	// register for action events
	bobActions := make(chan service.DIDCommAction)

	err = bob.RegisterActionEvent(bobActions)
	if err != nil {
		fmt.Println("Bob RegisterActionEvent:", err)
	}

	// Handle actions
	wg.Add(1)

	go func() {
		defer wg.Done()

		for {
			select {
			case <-aliceDone:
				return
			case action := <-aliceActions:
				var (
					thID string
					// nolint: govet
					err error
				)

				thID, err = action.Message.ThreadID()
				if err != nil {
					fmt.Println("Message.ThreadID", err)
				}

				action.Continue(alice.InvitationEnvelope(thID))
				fmt.Println("alice received", action.Message.Type())
			}
		}
	}()

	// Handle actions
	wg.Add(1)

	go func() {
		defer wg.Done()

		for {
			select {
			case <-bobDone:
				return
			case action := <-bobActions:
				var (
					thID string
					// nolint: govet
					err error
				)

				thID, err = action.Message.ThreadID()
				if err != nil {
					fmt.Println("Message.ThreadID", err)
				}

				fmt.Println("bob received", action.Message.Type())
				action.Continue(bob.InvitationEnvelope(thID))
			}
		}
	}()

	// Send proposal
	err = alice.SendProposalWithInvitation(&didexchange.Invitation{
		Type: didexchange.InvitationMsgType},
		&introduce.Recipient{
			To: &introduce.To{
				Name: "Carol",
			},
			MyDID:    Alice,
			TheirDID: Bob,
		})
	if err != nil {
		fmt.Println("SendProposalWithInvitation", err)
	}

	// Output:
	// bob received https://didcomm.org/introduce/1.0/proposal
	// alice received https://didcomm.org/introduce/1.0/response
}

// nolint: gocyclo, gocognit, govet
func ExampleThreeParticipants() {
	wg := sync.WaitGroup{}
	defer wg.Wait()

	var transport = map[string]chan transportMsg{
		Alice: make(chan transportMsg),
		Bob:   make(chan transportMsg),
		Carol: make(chan transportMsg),
	}

	// prepare the clients contexts
	aliceCtx, aliceDone := provider(Alice, transport)
	bobCtx, bobDone := provider(Bob, transport)
	carolCtx, carolDone := provider(Carol, transport)

	// create client
	alice, err := New(aliceCtx, nil)
	if err != nil {
		fmt.Println("Alice client:", err)
	}

	// register for action events
	aliceActions := make(chan service.DIDCommAction)

	err = alice.RegisterActionEvent(aliceActions)
	if err != nil {
		fmt.Println("Alice RegisterActionEvent:", err)
	}

	// create client
	bob, err := New(bobCtx, nil)
	if err != nil {
		fmt.Println("Bob client:", err)
	}

	// register for action events
	bobActions := make(chan service.DIDCommAction)

	err = bob.RegisterActionEvent(bobActions)
	if err != nil {
		fmt.Println("Bob RegisterActionEvent:", err)
	}

	// create client
	carol, err := New(carolCtx, &didexchange.Invitation{Type: didexchange.InvitationMsgType})
	if err != nil {
		fmt.Println("Carol client:", err)
	}

	// register for action events
	carolActions := make(chan service.DIDCommAction)

	err = carol.RegisterActionEvent(carolActions)
	if err != nil {
		fmt.Println("Carol  RegisterActionEvent:", err)
	}

	// Handle actions
	wg.Add(1)

	go func() {
		defer wg.Done()

		for {
			select {
			case <-aliceDone:
				return
			case action := <-aliceActions:
				var (
					thID string
					// nolint: govet
					err error
				)

				thID, err = action.Message.ThreadID()
				if err != nil {
					fmt.Println("Message.ThreadID", err)
				}

				action.Continue(alice.InvitationEnvelope(thID))
				fmt.Println("alice received", action.Message.Type())
			}
		}
	}()

	// Handle actions
	wg.Add(1)

	go func() {
		defer wg.Done()

		for {
			select {
			case <-bobDone:
				return
			case action := <-bobActions:
				var (
					thID string
					// nolint: govet
					err error
				)

				thID, err = action.Message.ThreadID()
				if err != nil {
					fmt.Println("Message.ThreadID", err)
				}

				fmt.Println("bob received", action.Message.Type())
				action.Continue(bob.InvitationEnvelope(thID))
			}
		}
	}()

	// Handle actions
	wg.Add(1)

	go func() {
		defer wg.Done()

		for {
			select {
			case <-carolDone:
				return
			case action := <-carolActions:
				var (
					thID string
					// nolint: govet
					err error
				)

				thID, err = action.Message.ThreadID()
				if err != nil {
					fmt.Println("Message.ThreadID", err)
				}

				fmt.Println("carol received", action.Message.Type())
				action.Continue(carol.InvitationEnvelope(thID))
			}
		}
	}()

	// Send proposal
	err = alice.SendProposal(&introduce.Recipient{
		To: &introduce.To{
			Name: "Carol",
		},
		MyDID:    Alice,
		TheirDID: Bob,
	}, &introduce.Recipient{
		To: &introduce.To{
			Name: "Bob",
		},
		MyDID:    Alice,
		TheirDID: Carol,
	})
	if err != nil {
		fmt.Println("SendProposalWithInvitation", err)
	}

	// Output:
	// bob received https://didcomm.org/introduce/1.0/proposal
	// alice received https://didcomm.org/introduce/1.0/response
	// carol received https://didcomm.org/introduce/1.0/proposal
	// alice received https://didcomm.org/introduce/1.0/response
}
