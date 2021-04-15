/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
)

func Example() {
	// create the framework with user options
	framework, err := New(
		WithInboundTransport(newMockInTransport()),
		WithStoreProvider(mem.NewProvider()),
		WithProtocolStateStoreProvider(mem.NewProvider()),
	)
	if err != nil {
		fmt.Println("failed to create framework")
	}

	// get the context from the framework
	ctx, err := framework.Context()
	if err != nil {
		fmt.Println("failed to create framework context")
	}

	fmt.Println("context created successfully")
	fmt.Println(ctx.ServiceEndpoint())

	// Output:
	// context created successfully
	// http://server
}

// mock inbound transport.
type mockInTransport struct{}

func newMockInTransport() *mockInTransport {
	return &mockInTransport{}
}

func (c *mockInTransport) Start(prov transport.Provider) error {
	return nil
}

func (c *mockInTransport) Stop() error {
	return nil
}

func (c *mockInTransport) Endpoint() string {
	return "http://server"
}
