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

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/client/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	didsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	routesvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"
	mockdidexchange "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/didexchange"
	mockroute "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/mediator"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
)

const (
	// Router is a router that sends an out-of-band invitation to the edge agent.
	Router = "Router"
	// Bob is an edge agent.
	Bob = "Bob"
)

var agentActions = make(map[string]chan service.DIDCommAction) //nolint:gochecknoglobals

// Example of an edge agent accepting an out-of-band invitation from a router.
func ExampleClient_AcceptInvitation() { //nolint:gocyclo,gocognit
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

	routerClient, err := mediator.New(routerCtx)
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
	routeRequest, err := json.Marshal(mediator.NewRequest())
	if err != nil {
		panic(err)
	}

	// router creates outofband request and embeds the route-request message in it
	inv, err := router.CreateInvitation(
		nil,
		WithLabel(Router),
		WithAttachments(&decorator.Attachment{
			ID: uuid.New().String(),
			Data: decorator.AttachmentData{
				Base64: base64.StdEncoding.EncodeToString(routeRequest),
			},
		}),
	)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s creates an out-of-band invitation with an embedded route-request message\n", Router)

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
			case mediator.ProtocolName:
				if event.Message.Type() == mediator.RequestMsgType {
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

	bobRoutes, err := mediator.New(bobCtx)
	if err != nil {
		panic(err)
	}

	config, err := bobRoutes.GetConfig("xyz")
	if err != nil {
		panic(err)
	}

	fmt.Printf(
		"%s has registered a route on %s with routerEndpoint %s and routingKeys %+v\n",
		Bob, Router, config.Endpoint(), config.Keys())

	// Output:
	// Router creates an out-of-band invitation with an embedded route-request message
	// Bob accepts the out-of-band invitation received via an out of band channel and created connectionID xyz
	// Router received https://didcomm.org/didexchange/1.0/request from Bob
	// Router created connectionID xyz
	// Router received https://didcomm.org/coordinatemediation/1.0/mediate-request from Bob
	// Bob has registered a route on Router with routerEndpoint http://routers-r-us.com and routingKeys [key-1 key-2]
}

func getContext(agent string) *mockprovider.Provider {
	return &mockprovider.Provider{
		KMSValue:                          &mockkms.KeyManager{},
		StorageProviderValue:              mem.NewProvider(),
		ProtocolStateStorageProviderValue: mem.NewProvider(),
		ServiceMap: map[string]interface{}{
			outofband.Name: &stubOOBService{
				Event: nil,
				acceptInvFunc: func(i *outofband.Invitation, options outofband.Options) (string, error) {
					agentActions[i.Label] <- service.DIDCommAction{
						ProtocolName: didsvc.DIDExchange,
						Message: service.NewDIDCommMsgMap(&didsvc.Request{
							Type:  didsvc.RequestMsgType,
							Label: agent,
						}),
						Continue: func(interface{}) {
							agentActions[i.Label] <- service.DIDCommAction{
								ProtocolName: mediator.ProtocolName,
								Message:      service.NewDIDCommMsgMap(mediator.NewRequest()),
								Continue:     func(interface{}) {},
							}
						},
						Properties: &didexchangeEvent{connID: "xyz"},
					}

					return "xyz", nil
				},
				saveInvFunc: func(*outofband.Invitation) error { return nil },
			},
			didsvc.DIDExchange: &mockdidexchange.MockDIDExchangeSvc{},
			routesvc.Coordination: &mockroute.MockMediatorSvc{
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

func (d *didexchangeEvent) All() map[string]interface{} {
	return map[string]interface{}{
		"connectionID": d.ConnectionID(),
		"invitationID": d.InvitationID(),
	}
}
