/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang/mock/gomock"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messenger"
	protocolDidexchange "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/introduce"
	serviceMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/common/service"
	dispatcherMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/dispatcher"
	messengerMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/messenger"
	introduceServiceMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/protocol/introduce"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"
)

const (
	// Alice always plays introducer role
	Alice = "Alice"
	// Bob always plays introducee (first) role
	Bob = "Bob"
	// Bob always plays introducee (second) role
	Carol = "Carol"
)

// payload represents a transport message structure
type payload struct {
	msg      []byte
	myDID    string
	theirDID string
}

// nolint: gocyclo, gocognit
func mockContext(agent string, tr map[string]chan payload, done chan struct{}) Provider {
	ctrl := gomock.NewController(nil)

	// NOTE: two fakeStore stores should be provided to prevent collision
	storageProvider := mem.NewProvider()

	didSvc := serviceMocks.NewMockEvent(ctrl)
	didSvc.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)

	outbound := dispatcherMocks.NewMockOutbound(ctrl)
	outbound.EXPECT().
		SendToDID(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(msg interface{}, myDID, theirDID string) error {
			src, err := json.Marshal(msg)
			if err != nil {
				fmt.Println(err)
			}

			// this Sleep is necessary to make our examples works as expected
			switch theirDID {
			case Carol:
				time.Sleep(time.Millisecond * 20)
			case Bob:
				time.Sleep(time.Millisecond * 10)
			}

			tr[theirDID] <- payload{
				msg:      src,
				myDID:    theirDID,
				theirDID: myDID,
			}

			return nil
		}).AnyTimes()

	mProvider := messengerMocks.NewMockProvider(ctrl)
	mProvider.EXPECT().StorageProvider().Return(storageProvider)
	mProvider.EXPECT().OutboundDispatcher().Return(outbound)

	provider := introduceServiceMocks.NewMockProvider(ctrl)
	provider.EXPECT().StorageProvider().Return(storageProvider)
	provider.EXPECT().Service(gomock.Any()).Return(didSvc, nil)

	msgSvc, err := messenger.NewMessenger(mProvider)
	if err != nil {
		fmt.Println(err)
	}

	provider.EXPECT().Messenger().Return(msgSvc)

	svc, err := introduce.New(provider)
	if err != nil {
		fmt.Println(err)
	}

	go func() {
		for {
			select {
			case <-done:
				return
			case msg := <-tr[agent]:
				didMap, err := service.ParseDIDCommMsgMap(msg.msg)
				if err != nil {
					fmt.Println(err)
				}

				fmt.Println(agent, "received", didMap.Type(), "from", msg.theirDID)

				if didMap.Type() == didexchange.InvitationMsgType {
					err = svc.InvitationReceived(service.StateMsg{
						Type:    service.PostState,
						StateID: "invited",
						Msg:     didMap,
					})

					if err != nil {
						fmt.Println(err)
					}

					close(done)

					continue
				}

				if err = msgSvc.HandleInbound(didMap, msg.myDID, msg.theirDID); err != nil {
					fmt.Println(err)
				}

				_, err = svc.HandleInbound(didMap, msg.myDID, msg.theirDID)
				if err != nil {
					fmt.Println(err)
				}
			case <-time.After(time.Second):
				return
			}
		}
	}()

	provider = introduceServiceMocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(gomock.Any()).Return(svc, nil)

	return provider
}

// nolint: gocyclo, govet
func ExampleSendProposal() {
	transport := map[string]chan payload{
		Alice: make(chan payload),
		Bob:   make(chan payload),
		Carol: make(chan payload),
	}

	var done = make(chan struct{})

	// Alice creates client
	clientAlice, err := New(mockContext(Alice, transport, done))
	if err != nil {
		panic(err)
	}

	// Alice registers channel for actions
	actionsAlice := make(chan service.DIDCommAction)

	err = clientAlice.RegisterActionEvent(actionsAlice)
	if err != nil {
		panic(err)
	}

	// Bob creates client
	clientBob, err := New(mockContext(Bob, transport, done))
	if err != nil {
		panic(err)
	}

	// Bob registers channel for actions
	actionsBob := make(chan service.DIDCommAction)

	err = clientBob.RegisterActionEvent(actionsBob)
	if err != nil {
		panic(err)
	}

	// Bob creates client
	clientCarol, err := New(mockContext(Carol, transport, done))
	if err != nil {
		panic(err)
	}

	// Carol registers channel for actions
	actionsCarol := make(chan service.DIDCommAction)

	err = clientCarol.RegisterActionEvent(actionsCarol)
	if err != nil {
		panic(err)
	}

	go func() {
		for {
			select {
			case e := <-actionsAlice:
				e.Continue(nil)
			case e := <-actionsBob:
				e.Continue(nil)
			case e := <-actionsCarol:
				e.Continue(WithInvitation(&didexchange.Invitation{
					Invitation: &protocolDidexchange.Invitation{
						Type: didexchange.InvitationMsgType,
					},
				}))
			}
		}
	}()

	err = clientAlice.SendProposal(
		&introduce.Recipient{
			MyDID:    Alice,
			TheirDID: Bob,
		},
		&introduce.Recipient{
			MyDID:    Alice,
			TheirDID: Carol,
		},
	)

	if err != nil {
		fmt.Println(err)
	}

	<-done

	// Output:
	// Bob received https://didcomm.org/introduce/1.0/proposal from Alice
	// Alice received https://didcomm.org/introduce/1.0/response from Bob
	// Carol received https://didcomm.org/introduce/1.0/proposal from Alice
	// Alice received https://didcomm.org/introduce/1.0/response from Carol
	// Bob received https://didcomm.org/didexchange/1.0/invitation from Alice
}

// nolint: gocyclo, govet
func ExampleSendProposalWithInvitation() {
	transport := map[string]chan payload{
		Alice: make(chan payload),
		Bob:   make(chan payload),
	}

	var done = make(chan struct{})

	// Alice creates client
	clientAlice, err := New(mockContext(Alice, transport, done))
	if err != nil {
		panic(err)
	}

	// Alice registers channel for actions
	actionsAlice := make(chan service.DIDCommAction)

	err = clientAlice.RegisterActionEvent(actionsAlice)
	if err != nil {
		panic(err)
	}

	// Bob creates client
	clientBob, err := New(mockContext(Bob, transport, done))
	if err != nil {
		panic(err)
	}

	// Bob registers channel for actions
	actionsBob := make(chan service.DIDCommAction)

	err = clientBob.RegisterActionEvent(actionsBob)
	if err != nil {
		panic(err)
	}

	go func() {
		for {
			select {
			case e := <-actionsAlice:
				e.Continue(nil)
			case e := <-actionsBob:
				e.Continue(nil)
			}
		}
	}()

	err = clientAlice.SendProposalWithInvitation(
		&didexchange.Invitation{
			Invitation: &protocolDidexchange.Invitation{
				Type: didexchange.InvitationMsgType,
			},
		},
		&introduce.Recipient{
			MyDID:    Alice,
			TheirDID: Bob,
		},
	)

	if err != nil {
		fmt.Println(err)
	}

	<-done

	// Output:
	// Bob received https://didcomm.org/introduce/1.0/proposal from Alice
	// Alice received https://didcomm.org/introduce/1.0/response from Bob
	// Bob received https://didcomm.org/didexchange/1.0/invitation from Alice
}

// nolint: gocyclo, govet
func ExampleSendRequest() {
	transport := map[string]chan payload{
		Alice: make(chan payload),
		Bob:   make(chan payload),
		Carol: make(chan payload),
	}

	var done = make(chan struct{})

	// Alice creates client
	clientAlice, err := New(mockContext(Alice, transport, done))
	if err != nil {
		panic(err)
	}

	// Alice registers channel for actions
	actionsAlice := make(chan service.DIDCommAction)

	err = clientAlice.RegisterActionEvent(actionsAlice)
	if err != nil {
		panic(err)
	}

	// Bob creates client
	clientBob, err := New(mockContext(Bob, transport, done))
	if err != nil {
		panic(err)
	}

	// Bob registers channel for actions
	actionsBob := make(chan service.DIDCommAction)

	err = clientBob.RegisterActionEvent(actionsBob)
	if err != nil {
		panic(err)
	}

	// Bob creates client
	clientCarol, err := New(mockContext(Carol, transport, done))
	if err != nil {
		panic(err)
	}

	// Carol registers channel for actions
	actionsCarol := make(chan service.DIDCommAction)

	err = clientCarol.RegisterActionEvent(actionsCarol)
	if err != nil {
		panic(err)
	}

	go func() {
		for {
			select {
			case e := <-actionsAlice:
				e.Continue(WithRecipients(&introduce.To{Name: Carol}, &introduce.Recipient{
					To:       &introduce.To{Name: Bob},
					MyDID:    Alice,
					TheirDID: Carol,
				}))
			case e := <-actionsBob:
				e.Continue(nil)
			case e := <-actionsCarol:
				e.Continue(WithInvitation(&didexchange.Invitation{
					Invitation: &protocolDidexchange.Invitation{
						Type: didexchange.InvitationMsgType,
					},
				}))
			}
		}
	}()

	err = clientBob.SendRequest(
		&introduce.PleaseIntroduceTo{
			To: introduce.To{Name: Carol},
		},
		Bob, Alice,
	)

	if err != nil {
		fmt.Println(err)
	}

	<-done

	// Output:
	// Alice received https://didcomm.org/introduce/1.0/request from Bob
	// Bob received https://didcomm.org/introduce/1.0/proposal from Alice
	// Alice received https://didcomm.org/introduce/1.0/response from Bob
	// Carol received https://didcomm.org/introduce/1.0/proposal from Alice
	// Alice received https://didcomm.org/introduce/1.0/response from Carol
	// Bob received https://didcomm.org/didexchange/1.0/invitation from Alice
}

// nolint: gocyclo, govet
func ExampleSendRequestWithPublicInvitation() {
	transport := map[string]chan payload{
		Alice: make(chan payload),
		Bob:   make(chan payload),
		Carol: make(chan payload),
	}

	var done = make(chan struct{})

	// Alice creates client
	clientAlice, err := New(mockContext(Alice, transport, done))
	if err != nil {
		panic(err)
	}

	// Alice registers channel for actions
	actionsAlice := make(chan service.DIDCommAction)

	err = clientAlice.RegisterActionEvent(actionsAlice)
	if err != nil {
		panic(err)
	}

	// Bob creates client
	clientBob, err := New(mockContext(Bob, transport, done))
	if err != nil {
		panic(err)
	}

	// Bob registers channel for actions
	actionsBob := make(chan service.DIDCommAction)

	err = clientBob.RegisterActionEvent(actionsBob)
	if err != nil {
		panic(err)
	}

	go func() {
		for {
			select {
			case e := <-actionsAlice:
				e.Continue(WithPublicInvitation(&didexchange.Invitation{
					Invitation: &protocolDidexchange.Invitation{
						Type: didexchange.InvitationMsgType,
					},
				}, &introduce.To{Name: Carol}))
			case e := <-actionsBob:
				e.Continue(nil)
			}
		}
	}()

	err = clientBob.SendRequest(
		&introduce.PleaseIntroduceTo{
			To: introduce.To{Name: Carol},
		},
		Bob, Alice,
	)

	if err != nil {
		fmt.Println(err)
	}

	<-done

	// Output:
	// Alice received https://didcomm.org/introduce/1.0/request from Bob
	// Bob received https://didcomm.org/introduce/1.0/proposal from Alice
	// Alice received https://didcomm.org/introduce/1.0/response from Bob
	// Bob received https://didcomm.org/didexchange/1.0/invitation from Alice
}
