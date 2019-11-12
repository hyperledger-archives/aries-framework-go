/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
)

func Example() {
	// db path manipulation - ignore this for actual implementation
	path, cleanup := tempDir()
	defer cleanup()

	dbPath = path

	// create the framework with user options
	framework, err := New(WithInboundTransport(newMockInTransport()))
	if err != nil {
		fmt.Println("failed to create framework")
	}

	// get the context from the framework
	ctx, err := framework.Context()
	if err != nil {
		fmt.Println("failed to create framework context")
	}

	// create the client by passing the context
	client := newMockClient(ctx)

	fmt.Println(client.endPoint())

	// Output: http://server
}

// mock client implementation with custom provider (subset of context).
type provider interface {
	InboundTransportEndpoint() string
}

type mockClient struct {
	inboundTransportEndpoint string
}

func newMockClient(prov provider) *mockClient {
	return &mockClient{inboundTransportEndpoint: prov.InboundTransportEndpoint()}
}

func (c *mockClient) endPoint() string {
	return c.inboundTransportEndpoint
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

func tempDir() (string, func()) {
	path, err := ioutil.TempDir("", "db")
	if err != nil {
		fmt.Println("Failed to create leveldb directory")
	}

	return path, func() {
		err := os.RemoveAll(path)
		if err != nil {
			fmt.Println("Failed to clear leveldb directory")
		}
	}
}
