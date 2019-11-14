/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	mockprotocol "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/internal/mock/kms"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/internal/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
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
		if e := service.AutoExecuteActionEvent(bobActions); e != nil {
			fmt.Println("failed to setup auto execute")
		}
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
		if e := service.AutoExecuteActionEvent(aliceActions); e != nil {
			fmt.Println("failed to setup auto execute")
		}
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
	transientStoreProvider := mockstore.NewMockStoreProvider()
	storeProvider := mockstore.NewMockStoreProvider()
	mockProvider := &mockprotocol.MockProvider{
		TransientStoreProvider: transientStoreProvider,
		StoreProvider:          storeProvider}

	svc, err := didexchange.New(mockProvider)
	if err != nil {
		panic(err)
	}

	context := &mockprovider.Provider{
		KMSValue:                      &mockkms.CloseableKMS{CreateEncryptionKeyValue: "sample-key"},
		TransientStorageProviderValue: transientStoreProvider,
		StorageProviderValue:          storeProvider,
		ServiceValue:                  svc}

	return context
}
