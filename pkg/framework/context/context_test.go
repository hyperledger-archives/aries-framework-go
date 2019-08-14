/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"testing"

	mocktransport "github.com/hyperledger/aries-framework-go/pkg/internal/didcomm/transport/mock"
	"github.com/stretchr/testify/require"
	errors "golang.org/x/xerrors"
)

func TestNewProvider(t *testing.T) {
	prov, err := New()
	require.NoError(t, err)
	require.Empty(t, prov.OutboundTransport())

	prov, err = New(WithOutboundTransport(mocktransport.NewOutboundTransport("success")))
	require.NoError(t, err)
	require.NotEmpty(t, prov.OutboundTransport())

	_, err = New(func(opts *Provider) error {
		return errors.New("error creating the framework option")
	})
	require.Error(t, err)
}
