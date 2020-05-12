/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofband

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/client/route"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	didsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"
	routesvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/route"
	mockdidexchange "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol/didexchange"
	mockroute "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol/route"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/internal/mock/provider"
	mocklegacykms "github.com/hyperledger/aries-framework-go/pkg/mock/kms/legacykms"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"
)

const (
	// Router is a router that sends an out-of-band request to the edge agent.
	Router = "Router"
	// Alice is an edge agent.
	Alice = "Alice"
	// Bob is an edge agent.
	Bob = "Bob"
)

var agentActions = make(map[string]chan service.DIDCommAction) //nolint:gochecknoglobals

// Example of an edge agent accepting an out-of-band request from a router.
func ExampleClient_AcceptRequest() { //nolint:gocyclo,gocognit
	// set up the router
	routerCtx := getContext(Router)

	router, err := New(routerCtx)
	if err != nil {
		panic(err)
	}

	routerDIDs, err := didexchange.New(routerCtx)
	if err != nil {
		panic(err)
	}

	routerClient, err := route.New(routerCtx)
	if err != nil {
		panic(err)
	}

	routerEvents := makeActionsChannel(Router)

	err = routerDIDs.RegisterActionEvent(routerEvents)
	if err != nil {
		panic(err)
	}

	err = routerClient.RegisterActionEvent(routerEvents)
	if err != nil {
		panic(err)
	}

	// set up the edge agent
	bobCtx := getContext(Bob)

	bob, err := New(bobCtx)
	if err != nil {
		panic(err)
	}

	// router creates the route-request message
	routeRequest, err := json.Marshal(route.NewRequest())
	if err != nil {
		panic(err)
	}

	// router creates outofband request and embeds the route-request message in it
	req, err := router.CreateRequest(
		[]*decorator.Attachment{{
			ID: uuid.New().String(),
			Data: decorator.AttachmentData{
				Base64: base64.StdEncoding.EncodeToString(routeRequest),
			},
		}},
		WithLabel(Router),
	)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s creates an out-of-band request with an embedded route-request message\n", Router)

	// the edge agent accepts the outofband request
	bobConnID, err := bob.AcceptRequest(req, Bob)
	if err != nil {
		panic(err)
	}

	fmt.Printf(
		"%s accepts the out-of-band request received via an out of band channel and created connectionID %s\n",
		Bob, bobConnID)

	done := make(chan struct{}) // ends this example

	go func() {
		for event := range routerEvents {
			fmt.Printf("%s received %s from %s\n", Router, event.Message.Type(), Bob)

			switch event.ProtocolName {
			case didexchange.ProtocolName:
				if event.Message.Type() == didexchange.RequestMsgType {
					didExchangeRequest := &didsvc.Request{}

					err = event.Message.Decode(didExchangeRequest)
					if err != nil {
						panic(err)
					}

					if didExchangeRequest.Label != Bob {
						err = fmt.Errorf(
							"%s expected a didexchange request from %s but got %s",
							Router, Bob, didExchangeRequest.Label,
						)

						event.Stop(err)
						panic(err)
					}

					props, ok := event.Properties.(didexchange.Event)
					if !ok {
						panic("failed to cast event properties (shouldn't happen)")
					}

					fmt.Printf("%s created connectionID %s\n", Router, props.ConnectionID())

					event.Continue(nil)
				}
			case route.ProtocolName:
				if event.Message.Type() == route.RequestMsgType {
					event.Continue(nil)
					done <- struct{}{}
				}
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(time.Second): // timeout varies in your environment
		panic("timeout")
	}

	bobRoutes, err := route.New(bobCtx)
	if err != nil {
		panic(err)
	}

	config, err := bobRoutes.GetConfig()
	if err != nil {
		panic(err)
	}

	fmt.Printf(
		"%s has registered a route on %s with routerEndpoint %s and routingKeys %+v\n",
		Bob, Router, config.Endpoint(), config.Keys())

	// Output:
	// Router creates an out-of-band request with an embedded route-request message
	// Bob accepts the out-of-band request received via an out of band channel and created connectionID xyz
	// Router received https://didcomm.org/didexchange/1.0/request from Bob
	// Router created connectionID xyz
	// Router received https://didcomm.org/routecoordination/1.0/route-request from Bob
	// Bob has registered a route on Router with routerEndpoint http://routers-r-us.com and routingKeys [key-1 key-2]
}

// Example of an edge agent sending an out-of-band request to another edge agent.
func ExampleClient_AcceptInvitation() { //nolint:gocyclo,gocognit
	// set up the router
	aliceCtx := getContext(Alice)

	alice, err := New(aliceCtx)
	if err != nil {
		panic(err)
	}

	aliceDIDs, err := didexchange.New(aliceCtx)
	if err != nil {
		panic(err)
	}

	aliceRouting, err := route.New(aliceCtx)
	if err != nil {
		panic(err)
	}

	aliceEvents := makeActionsChannel(Alice)

	err = aliceDIDs.RegisterActionEvent(aliceEvents)
	if err != nil {
		panic(err)
	}

	err = aliceRouting.RegisterActionEvent(aliceEvents)
	if err != nil {
		panic(err)
	}

	// set up the edge agent
	bob, err := New(getContext(Bob))
	if err != nil {
		panic(err)
	}

	// alice creates an outofband invitation
	inv, err := alice.CreateInvitation(nil, WithLabel(Alice))
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s creates an out-of-band invitation\n", Alice)

	// the edge agent accepts the outofband invitation
	bobConnID, err := bob.AcceptInvitation(inv, Bob)
	if err != nil {
		panic(err)
	}

	fmt.Printf(
		"%s accepts the out-of-band invitation received via an out of band channel and created connectionID %s\n",
		Bob, bobConnID)

	done := make(chan struct{}) // ends this example

	go func() {
		for event := range aliceEvents {
			fmt.Printf("%s received %s from %s\n", Alice, event.Message.Type(), Bob)

			if event.ProtocolName == didexchange.ProtocolName &&
				event.Message.Type() == didexchange.RequestMsgType {
				didExchangeRequest := &didsvc.Request{}

				err = event.Message.Decode(didExchangeRequest)
				if err != nil {
					panic(err)
				}

				if didExchangeRequest.Label != Bob {
					err = fmt.Errorf(
						"%s expected a didexchange request from %s but got %s",
						Alice, Bob, didExchangeRequest.Label,
					)

					event.Stop(err)
					panic(err)
				}

				props, ok := event.Properties.(didexchange.Event)
				if !ok {
					panic("failed to cast event properties (shouldn't happen)")
				}

				fmt.Printf("%s created connectionID %s\n", Alice, props.ConnectionID())

				event.Continue(nil)
				done <- struct{}{}
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(time.Second): // timeout varies in your environment
		panic("timeout")
	}

	// Output:
	// Alice creates an out-of-band invitation
	// Bob accepts the out-of-band invitation received via an out of band channel and created connectionID abcdefg
	// Alice received https://didcomm.org/didexchange/1.0/request from Bob
	// Alice created connectionID xyz
}

func getContext(agent string) *mockprovider.Provider {
	return &mockprovider.Provider{
		LegacyKMSValue:                &mocklegacykms.CloseableKMS{},
		StorageProviderValue:          mem.NewProvider(),
		TransientStorageProviderValue: mem.NewProvider(),
		ServiceMap: map[string]interface{}{
			outofband.Name: &stubOOBService{
				Event: nil,
				acceptReqFunc: func(r *outofband.Request, myLabel string) (string, error) {
					agentActions[r.Label] <- service.DIDCommAction{
						ProtocolName: didsvc.DIDExchange,
						Message: service.NewDIDCommMsgMap(&didsvc.Request{
							Type:  didsvc.RequestMsgType,
							Label: agent,
						}),
						Continue: func(interface{}) {
							agentActions[r.Label] <- service.DIDCommAction{
								ProtocolName: route.ProtocolName,
								Message:      service.NewDIDCommMsgMap(route.NewRequest()),
								Continue:     func(interface{}) {},
							}
						},
						Properties: &didexchangeEvent{connID: "xyz"},
					}

					return "xyz", nil
				},
				acceptInvFunc: func(i *outofband.Invitation, myLabel string) (string, error) {
					agentActions[i.Label] <- service.DIDCommAction{
						ProtocolName: didsvc.DIDExchange,
						Message: service.NewDIDCommMsgMap(&didsvc.Request{
							Type:  didsvc.RequestMsgType,
							Label: agent,
						}),
						Continue:   func(interface{}) {},
						Properties: &didexchangeEvent{connID: "xyz"},
					}

					return "abcdefg", nil
				},
				saveReqFunc: func(*outofband.Request) error { return nil },
				saveInvFunc: func(*outofband.Invitation) error { return nil },
			},
			didsvc.DIDExchange: &mockdidexchange.MockDIDExchangeSvc{},
			routesvc.Coordination: &mockroute.MockRouteSvc{
				RouterEndpoint: "http://routers-r-us.com",
				RoutingKeys:    []string{"key-1", "key-2"},
			},
		},
	}
}

func makeActionsChannel(agent string) chan service.DIDCommAction {
	c := make(chan service.DIDCommAction, 5)
	agentActions[agent] = c

	return c
}

type didexchangeEvent struct {
	connID string
	invID  string
}

func (d *didexchangeEvent) ConnectionID() string {
	return d.connID
}

func (d *didexchangeEvent) InvitationID() string {
	return d.invID
}
