/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries

import (
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/exchange"
	mocktransport "github.com/hyperledger/aries-framework-go/pkg/internal/didcomm/transport/mock"
	"github.com/stretchr/testify/require"
	errors "golang.org/x/xerrors"
)

func TestFramework(t *testing.T) {
	// framework new - error
	_, err := New(func(opts *Aries) error {
		return errors.New("error creating the framework option")
	})
	require.Error(t, err)

	// framework new - success
	aries, err := New(WithTransportProviderFactory(&mockTransportProviderFactory{}))
	require.NoError(t, err)

	// context
	ctx, err := aries.Context()
	require.NoError(t, err)

	// exchange client
	exClient := exchange.New(ctx)
	require.NoError(t, err)

	req := &exchange.Request{
		ID:    "5678876542345",
		Label: "Bob",
	}
	require.NoError(t, exClient.SendExchangeRequest(req, "http://example/didexchange"))
	require.Error(t, exClient.SendExchangeRequest(req, ""))
}

type mockTransportProviderFactory struct {
}

func (f *mockTransportProviderFactory) CreateOutboundTransport() transport.OutboundTransport {
	return mocktransport.NewOutboundTransport("success")
}
