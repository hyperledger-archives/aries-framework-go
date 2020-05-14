/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mediator

import (
	"errors"
	"fmt"

	didexClient "github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	mockprotocol "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol"
	mockroute "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol/mediator"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/internal/mock/provider"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms/legacykms"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
)

func Example() {
	// Create DID Exchange Client and perform DID Exchange with the Router
	didExClient, err := didexClient.New(didClientMockContext())
	if err != nil {
		fmt.Println("failed to create client for Alice")
	}

	// Get the connection ID
	routerConnID := performDIDExchangeWithRouter(didExClient)

	// Create Route Client
	client, err := New(mockContext())
	if err != nil {
		fmt.Println("failed to create route client")
	}

	// Register agent with the router
	err = client.Register(routerConnID)
	if err != nil {
		fmt.Printf("failed to register the agent with router : %s\n", err.Error())
	}

	fmt.Println("successfully registered with router")

	// generate invitation after route has been registered
	invitation, err := didExClient.CreateInvitation("alice-agent")
	if err != nil {
		fmt.Println("failed to create invitation after route registration")
	}

	fmt.Println(invitation.ServiceEndpoint)
	fmt.Println(invitation.RoutingKeys)

	// Output: successfully registered with router
	// http://router.example.com
	// [abc xyz]
}

func performDIDExchangeWithRouter(client *didexClient.Client) string {
	router, err := didexClient.New(didClientMockContext())
	if err != nil {
		fmt.Println("failed to create client for Bob")
	}

	routerActions := make(chan service.DIDCommAction)

	err = router.RegisterActionEvent(routerActions)
	if err != nil {
		fmt.Println("failed to create Bob's action channel")
	}

	go func() {
		service.AutoExecuteActionEvent(routerActions)
	}()

	aliceActions := make(chan service.DIDCommAction)

	err = client.RegisterActionEvent(aliceActions)
	if err != nil {
		fmt.Println("failed to create Alice's action channel")
	}

	go func() {
		service.AutoExecuteActionEvent(aliceActions)
	}()

	invitation, err := router.CreateInvitation("router invites alice")
	if err != nil {
		fmt.Printf("failed to create invitation: %s\n", err)
	}

	connectionID, err := client.HandleInvitation(invitation)
	if err != nil {
		fmt.Printf("failed to handle invitation: %s\n", err)
	}

	return connectionID
}

func didClientMockContext() *mockprovider.Provider {
	transientStoreProvider := mockstore.NewMockStoreProvider()
	storeProvider := mockstore.NewMockStoreProvider()
	mockProvider := &mockprotocol.MockProvider{
		TransientStoreProvider: transientStoreProvider,
		StoreProvider:          storeProvider,
		ServiceMap: map[string]interface{}{
			mediator.Coordination: &mockroute.MockMediatorSvc{},
		},
	}

	svc, err := didexchange.New(mockProvider)
	if err != nil {
		panic(err)
	}

	context := &mockprovider.Provider{
		LegacyKMSValue:                &mockkms.CloseableKMS{CreateSigningKeyValue: "sample-key"},
		TransientStorageProviderValue: transientStoreProvider,
		StorageProviderValue:          storeProvider,
		ServiceMap: map[string]interface{}{
			didexchange.DIDExchange: svc,
			mediator.Coordination:   routeService(),
		},
	}

	return context
}

func mockContext() provider {
	return &mockprovider.Provider{
		ServiceValue: routeService(),
	}
}

func routeService() *mockroute.MockMediatorSvc {
	return &mockroute.MockMediatorSvc{
		RegisterFunc: func(connectionID string) error {
			if connectionID == "" {
				return errors.New("connection ID is mandatory")
			}

			return nil
		},
		RouterEndpoint: "http://router.example.com",
		RoutingKeys:    []string{"abc", "xyz"},
	}
}
