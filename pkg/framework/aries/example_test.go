/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

func Example() {
	// create the framework with user options
	framework, err := New(
		WithInboundTransport(newMockInTransport()),
		WithStoreProvider(newMockDBProvider()),
		WithTransientStoreProvider(newMockDBProvider()),
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
	fmt.Println(ctx.InboundTransportEndpoint())

	// Output:
	// context created successfully
	// http://server
}

// mock inbound transport
type mockInTransport struct {
}

func newMockInTransport() *mockInTransport {
	return &mockInTransport{}
}

func (c *mockInTransport) Start(prov transport.InboundProvider) error {
	return nil
}

func (c *mockInTransport) Stop() error {
	return nil
}
func (c *mockInTransport) Endpoint() string {
	return "http://server"
}

// mock DB provider
type mockDBProvider struct {
}

func newMockDBProvider() *mockDBProvider {
	return &mockDBProvider{}
}

func (c *mockDBProvider) OpenStore(name string) (storage.Store, error) {
	return nil, nil
}

func (c *mockDBProvider) CloseStore(name string) error {
	return nil
}
func (c *mockDBProvider) Close() error {
	return nil
}
