/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang/mock/gomock"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messenger"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
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

	provider := protocolmocks.NewMockProvider(ctrl)
	provider.EXPECT().StorageProvider().Return(store)

	msgSvc, err := messenger.NewMessenger(mProvider)
	if err != nil {
		fmt.Println(err)
	}

	provider.EXPECT().Messenger().Return(msgSvc)

	svc, err := presentproof.New(provider)
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

	provider1 := mocks.NewMockProvider(ctrl)
	provider1.EXPECT().Service(gomock.Any()).Return(svc, nil)

	return provider1
}

func ExampleClient_SendRequestPresentation() {
	transport := map[string]chan payload{
		Alice: make(chan payload),
		Bob:   make(chan payload),
	}

	// Alice creates client
	clientAlice, err := New(mockContext(Alice, transport))
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
	clientBob, err := New(mockContext(Bob, transport))
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
			var acceptErr error

			select {
			case e := <-actionsAlice:
				acceptErr = clientAlice.AcceptPresentation(e.Properties.All()["piid"].(string))
			case e := <-actionsBob:
				acceptErr = clientBob.AcceptRequestPresentation(e.Properties.All()["piid"].(string), &Presentation{})
			}

			if acceptErr != nil {
				fmt.Println(acceptErr)
			}
		}
	}()

	// Alice
	waitForAlice := waitForFn(clientAlice)
	// Bob
	waitForBob := waitForFn(clientBob)

	_, err = clientAlice.SendRequestPresentation(&RequestPresentation{}, Alice, Bob)
	if err != nil {
		fmt.Println(err)
	}

	waitForAlice()
	waitForBob()

	// Output:
	// Bob received https://didcomm.org/present-proof/2.0/request-presentation from Alice
	// Alice received https://didcomm.org/present-proof/2.0/presentation from Bob
}

func ExampleClient_SendRequestPresentation_second() {
	transport := map[string]chan payload{
		Alice: make(chan payload),
		Bob:   make(chan payload),
	}

	// Alice creates client
	clientAlice, err := New(mockContext(Alice, transport))
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
	clientBob, err := New(mockContext(Bob, transport))
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
			var acceptErr error

			select {
			case e := <-actionsAlice:
				acceptErr = clientAlice.AcceptPresentation(e.Properties.All()["piid"].(string))
			case e := <-actionsBob:
				acceptErr = clientBob.AcceptRequestPresentation(e.Properties.All()["piid"].(string), &Presentation{})
			}

			if acceptErr != nil {
				fmt.Println(acceptErr)
			}
		}
	}()

	// Alice
	waitForAlice := waitForFn(clientAlice)
	// Bob
	waitForBob := waitForFn(clientBob)

	_, err = clientAlice.SendRequestPresentation(&RequestPresentation{WillConfirm: true}, Alice, Bob)
	if err != nil {
		fmt.Println(err)
	}

	waitForAlice()
	waitForBob()

	// Output:
	// Bob received https://didcomm.org/present-proof/2.0/request-presentation from Alice
	// Alice received https://didcomm.org/present-proof/2.0/presentation from Bob
	// Bob received https://didcomm.org/present-proof/2.0/ack from Alice
}

// nolint: gocyclo
func ExampleClient_SendProposePresentation() {
	transport := map[string]chan payload{
		Alice: make(chan payload),
		Bob:   make(chan payload),
	}

	// Alice creates client
	clientAlice, err := New(mockContext(Alice, transport))
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
	clientBob, err := New(mockContext(Bob, transport))
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

			if e.Message.Type() == presentproof.PresentationMsgType {
				acceptErr = clientBob.AcceptPresentation(piid)
			}

			if e.Message.Type() == presentproof.ProposePresentationMsgType {
				acceptErr = clientBob.AcceptProposePresentation(piid, &RequestPresentation{WillConfirm: true})
			}

			if e.Message.Type() == presentproof.RequestPresentationMsgType {
				acceptErr = clientAlice.AcceptRequestPresentation(piid, &Presentation{})
			}

			if acceptErr != nil {
				fmt.Println(acceptErr)
			}
		}
	}()

	// Alice
	waitForAlice := waitForFn(clientAlice)
	// Bob
	waitForBob := waitForFn(clientBob)

	_, err = clientAlice.SendProposePresentation(&ProposePresentation{}, Alice, Bob)
	if err != nil {
		fmt.Println(err)
	}

	waitForAlice()
	waitForBob()

	// Output:
	// Bob received https://didcomm.org/present-proof/2.0/propose-presentation from Alice
	// Alice received https://didcomm.org/present-proof/2.0/request-presentation from Bob
	// Bob received https://didcomm.org/present-proof/2.0/presentation from Alice
	// Alice received https://didcomm.org/present-proof/2.0/ack from Bob
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
