/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	mockprotocol "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol"
	mockroute "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/mediator"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
)

func Example() {
	bob, err := New(mockContext())
	if err != nil {
		fmt.Println("failed to create client for Bob")
	}

	bobActions := make(chan service.DIDCommAction, 1)

	err = bob.RegisterActionEvent(bobActions)
	if err != nil {
		fmt.Println("failed to create Bob's action channel")
	}

	go func() {
		service.AutoExecuteActionEvent(bobActions)
	}()

	alice, err := New(mockContext())
	if err != nil {
		fmt.Println("failed to create client for Alice")
	}

	aliceActions := make(chan service.DIDCommAction, 1)

	err = alice.RegisterActionEvent(aliceActions)
	if err != nil {
		fmt.Println("failed to create Alice's action channel")
	}

	go func() {
		service.AutoExecuteActionEvent(aliceActions)
	}()

	invitation, err := bob.CreateInvitation("bob invites alice")
	if err != nil {
		fmt.Printf("failed to create invitation: %s\n", err)
	}

	connectionID, err := alice.HandleInvitation(invitation)
	if err != nil {
		fmt.Printf("failed to handle invitation: %s\n", err)
	}

	connection, err := alice.GetConnection(connectionID)
	if err != nil {
		fmt.Printf("failed to get connection: %s\n", err)
	}

	fmt.Println(connection.TheirLabel)

	// Output: bob invites alice
}

func ExampleNew() {
	ctx := mockContext()

	c, err := New(ctx)
	if err != nil {
		fmt.Println(err)
	}

	if c != nil {
		fmt.Println("client created")
	} else {
		fmt.Println("client is nil")
	}

	// Output: client created
}

func ExampleClient_CreateInvitation() {
	bob, err := New(mockContext())
	if err != nil {
		fmt.Println("failed to create client for Bob")
	}

	invitation, err := bob.CreateInvitation("bob invites julia")
	if err != nil {
		fmt.Printf("failed to create invitation: %s\n", err)
	}

	fmt.Println(invitation.Label)

	// Output: bob invites julia
}

func ExampleClient_CreateInvitationWithDID() {
	bob, err := New(mockContext())
	if err != nil {
		fmt.Println("failed to create client for Bob")
	}

	invitation, err := bob.CreateInvitationWithDID("bob invites maria", "did:example:abc-123")
	if err != nil {
		fmt.Printf("failed to create invitation with DID: %s\n", err)
	}

	fmt.Println(invitation.DID)

	// Output: did:example:abc-123
}

func mockContext() provider {
	protocolStateStoreProvider := mockstore.NewMockStoreProvider()
	storeProvider := mockstore.NewMockStoreProvider()
	mockProvider := &mockprotocol.MockProvider{
		ProtocolStateStoreProvider: protocolStateStoreProvider,
		StoreProvider:              storeProvider,
		ServiceMap: map[string]interface{}{
			mediator.Coordination: &mockroute.MockMediatorSvc{},
		},
	}

	svc, err := didexchange.New(mockProvider)
	if err != nil {
		panic(err)
	}

	mockSigningKey, err := mockkms.CreateMockED25519KeyHandle()
	if err != nil {
		panic(err)
	}

	context := &mockprovider.Provider{
		KMSValue: &mockkms.KeyManager{
			CreateKeyID:    "signing-key-123",
			CreateKeyValue: mockSigningKey,
		},
		ProtocolStateStorageProviderValue: protocolStateStoreProvider,
		StorageProviderValue:              storeProvider,
		ServiceMap: map[string]interface{}{
			didexchange.DIDExchange: svc,
			mediator.Coordination:   &mockroute.MockMediatorSvc{},
		},
	}

	return context
}
