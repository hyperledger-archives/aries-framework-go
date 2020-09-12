/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang/mock/gomock"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messenger"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	mocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/client/presentproof"
	dispatchermocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/dispatcher"
	messengermocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/messenger"
	protocolmocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/protocol/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"
)

// payload represents a transport message structure.
type payload struct {
	msg      []byte
	myDID    string
	theirDID string
}

func mockContext(agent string, tr map[string]chan payload) Provider {
	ctrl := gomock.NewController(nil)

	outbound := dispatchermocks.NewMockOutbound(ctrl)
	outbound.EXPECT().
		SendToDID(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(msg interface{}, myDID, theirDID string) error {
			src, err := json.Marshal(msg)
			if err != nil {
				fmt.Println(err)
			}

			tr[theirDID] <- payload{
				msg:      src,
				myDID:    theirDID,
				theirDID: myDID,
			}

			return nil
		}).AnyTimes()

	store := mem.NewProvider()

	mProvider := messengermocks.NewMockProvider(ctrl)
	mProvider.EXPECT().StorageProvider().Return(store)
	mProvider.EXPECT().OutboundDispatcher().Return(outbound)

	msgSvc, err := messenger.NewMessenger(mProvider)
	if err != nil {
		fmt.Println(err)
	}

	provider := protocolmocks.NewMockProvider(ctrl)
	provider.EXPECT().StorageProvider().Return(store)
	provider.EXPECT().Messenger().Return(msgSvc)

	svc, err := issuecredential.New(provider)
	if err != nil {
		fmt.Println(err)
	}

	go func() {
		for {
			select {
			case msg := <-tr[agent]:
				didMap, err := service.ParseDIDCommMsgMap(msg.msg)
				if err != nil {
					fmt.Println(err)
				}

				fmt.Println(agent, "received", didMap.Type(), "from", msg.theirDID)

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

	mockProvider := mocks.NewMockProvider(ctrl)
	mockProvider.EXPECT().Service(gomock.Any()).Return(svc, nil)

	return mockProvider
}

func ExampleClient_SendOffer() {
	transport := map[string]chan payload{
		Alice: make(chan payload),
		Bob:   make(chan payload),
	}

	// Alice creates client
	clientAlice, err := New(mockContext(Alice, transport))
	if err != nil {
		panic(err)
	}

	// Alice registers channel for actions.
	actionsAlice := make(chan service.DIDCommAction)

	err = clientAlice.RegisterActionEvent(actionsAlice)
	if err != nil {
		panic(err)
	}

	// Bob creates client.
	clientBob, err := New(mockContext(Bob, transport))
	if err != nil {
		panic(err)
	}

	// Bob registers channel for actions.
	actionsBob := make(chan service.DIDCommAction)

	err = clientBob.RegisterActionEvent(actionsBob)
	if err != nil {
		panic(err)
	}

	go func() {
		for {
			var acceptErr error

			select {
			case e := <-actionsAlice:
				acceptErr = clientAlice.AcceptRequest(e.Properties.All()["piid"].(string), &IssueCredential{})
			case e := <-actionsBob:
				acceptErr = clientBob.AcceptOffer(e.Properties.All()["piid"].(string))
			}

			if acceptErr != nil {
				fmt.Println(acceptErr)
			}
		}
	}()

	// Alice.
	waitForAlice := waitForFn(clientAlice)
	// Bob.
	waitForBob := waitForFn(clientBob)

	_, err = clientAlice.SendOffer(&OfferCredential{}, Alice, Bob)
	if err != nil {
		fmt.Println(err)
	}

	waitForAlice()
	waitForBob()

	// Output:
	// Bob received https://didcomm.org/issue-credential/2.0/offer-credential from Alice
	// Alice received https://didcomm.org/issue-credential/2.0/request-credential from Bob
	// Bob received https://didcomm.org/issue-credential/2.0/issue-credential from Alice
	// Alice received https://didcomm.org/issue-credential/2.0/ack from Bob
}

// nolint: gocyclo
func ExampleClient_SendProposal() {
	transport := map[string]chan payload{
		Alice: make(chan payload),
		Bob:   make(chan payload),
	}

	// Alice creates client.
	clientAlice, err := New(mockContext(Alice, transport))
	if err != nil {
		panic(err)
	}

	// Alice registers channel for actions.
	actionsAlice := make(chan service.DIDCommAction)

	err = clientAlice.RegisterActionEvent(actionsAlice)
	if err != nil {
		panic(err)
	}

	// Bob creates client.
	clientBob, err := New(mockContext(Bob, transport))
	if err != nil {
		panic(err)
	}

	// Bob registers channel for actions.
	actionsBob := make(chan service.DIDCommAction)

	err = clientBob.RegisterActionEvent(actionsBob)
	if err != nil {
		panic(err)
	}

	go func() {
		for {
			var acceptErr error

			var e service.DIDCommAction

			select {
			case e = <-actionsAlice:
			case e = <-actionsBob:
			}

			piid, ok := e.Properties.All()["piid"].(string)
			if !ok {
				fmt.Println("empty piid")
			}

			if e.Message.Type() == issuecredential.ProposeCredentialMsgType {
				acceptErr = clientAlice.AcceptProposal(piid, &OfferCredential{})
			}

			if e.Message.Type() == issuecredential.RequestCredentialMsgType {
				acceptErr = clientAlice.AcceptRequest(piid, &IssueCredential{})
			}

			if e.Message.Type() == issuecredential.OfferCredentialMsgType {
				acceptErr = clientBob.AcceptOffer(piid)
			}

			if e.Message.Type() == issuecredential.IssueCredentialMsgType {
				acceptErr = clientBob.AcceptCredential(piid)
			}

			if acceptErr != nil {
				fmt.Println(acceptErr)
			}
		}
	}()

	// Alice.
	waitForAlice := waitForFn(clientAlice)
	// Bob.
	waitForBob := waitForFn(clientBob)

	_, err = clientBob.SendProposal(&ProposeCredential{}, Bob, Alice)
	if err != nil {
		fmt.Println(err)
	}

	waitForAlice()
	waitForBob()

	// Output:
	// Alice received https://didcomm.org/issue-credential/2.0/propose-credential from Bob
	// Bob received https://didcomm.org/issue-credential/2.0/offer-credential from Alice
	// Alice received https://didcomm.org/issue-credential/2.0/request-credential from Bob
	// Bob received https://didcomm.org/issue-credential/2.0/issue-credential from Alice
	// Alice received https://didcomm.org/issue-credential/2.0/ack from Bob
}

func ExampleClient_SendRequest() {
	transport := map[string]chan payload{
		Alice: make(chan payload),
		Bob:   make(chan payload),
	}

	// Alice creates client.
	clientAlice, err := New(mockContext(Alice, transport))
	if err != nil {
		panic(err)
	}

	// Alice registers channel for actions.
	actionsAlice := make(chan service.DIDCommAction)

	err = clientAlice.RegisterActionEvent(actionsAlice)
	if err != nil {
		panic(err)
	}

	// Bob creates client.
	clientBob, err := New(mockContext(Bob, transport))
	if err != nil {
		panic(err)
	}

	// Bob registers channel for actions.
	actionsBob := make(chan service.DIDCommAction)

	err = clientBob.RegisterActionEvent(actionsBob)
	if err != nil {
		panic(err)
	}

	go func() {
		for {
			var acceptErr error

			select {
			case e := <-actionsAlice:
				acceptErr = clientAlice.AcceptRequest(e.Properties.All()["piid"].(string), &IssueCredential{})
			case e := <-actionsBob:
				acceptErr = clientBob.AcceptCredential(e.Properties.All()["piid"].(string))
			}

			if acceptErr != nil {
				fmt.Println(acceptErr)
			}
		}
	}()

	// Alice.
	waitForAlice := waitForFn(clientAlice)
	// Bob.
	waitForBob := waitForFn(clientBob)

	_, err = clientBob.SendRequest(&RequestCredential{}, Bob, Alice)
	if err != nil {
		fmt.Println(err)
	}

	waitForAlice()
	waitForBob()

	// Output:
	// Alice received https://didcomm.org/issue-credential/2.0/request-credential from Bob
	// Bob received https://didcomm.org/issue-credential/2.0/issue-credential from Alice
	// Alice received https://didcomm.org/issue-credential/2.0/ack from Bob
}

func waitForFn(c *Client) func() {
	const stateDone = "done"

	agent := make(chan service.StateMsg, 10)

	if err := c.RegisterMsgEvent(agent); err != nil {
		panic(err)
	}

	done := make(chan struct{})

	return func() {
		go func() {
			for st := range agent {
				if st.StateID == stateDone && st.Type == service.PostState {
					done <- struct{}{}
				}
			}
		}()

		select {
		case <-done:
		case <-time.After(time.Second):
			fmt.Println("timeout")
		}
	}
}
