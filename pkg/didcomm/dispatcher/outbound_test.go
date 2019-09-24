/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dispatcher

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	mockdidcomm "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm"
	mockwallet "github.com/hyperledger/aries-framework-go/pkg/internal/mock/wallet"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

func TestOutboundDispatcher_Send(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		o := NewOutbound(&provider{walletValue: &mockwallet.CloseableWallet{},
			outboundTransportsValue: []transport.OutboundTransport{&mockdidcomm.MockOutboundTransport{AcceptValue: true}}})
		require.NoError(t, o.Send("data", "", &Destination{ServiceEndpoint: "url"}))
	})

	t.Run("test no outbound transport found", func(t *testing.T) {
		o := NewOutbound(&provider{walletValue: &mockwallet.CloseableWallet{},
			outboundTransportsValue: []transport.OutboundTransport{&mockdidcomm.MockOutboundTransport{AcceptValue: false}}})
		err := o.Send("data", "", &Destination{ServiceEndpoint: "url"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "no outbound transport found for serviceEndpoint: url")
	})

	t.Run("test pack msg failure", func(t *testing.T) {
		o := NewOutbound(&provider{walletValue: &mockwallet.CloseableWallet{PackErr: fmt.Errorf("pack error")},
			outboundTransportsValue: []transport.OutboundTransport{&mockdidcomm.MockOutboundTransport{AcceptValue: true}}})
		err := o.Send("data", "", &Destination{ServiceEndpoint: "url"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "pack error")
	})

	t.Run("test outbound send failure", func(t *testing.T) {
		o := NewOutbound(&provider{walletValue: &mockwallet.CloseableWallet{},
			outboundTransportsValue: []transport.OutboundTransport{
				&mockdidcomm.MockOutboundTransport{AcceptValue: true, SendErr: fmt.Errorf("send error")}}})
		err := o.Send("data", "", &Destination{ServiceEndpoint: "url"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "send error")
	})
}

type provider struct {
	walletValue             wallet.Pack
	outboundTransportsValue []transport.OutboundTransport
}

func (p *provider) PackWallet() wallet.Pack {
	return p.walletValue
}

func (p *provider) OutboundTransports() []transport.OutboundTransport {
	return p.outboundTransportsValue
}
