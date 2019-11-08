/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dispatcher

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	commontransport "github.com/hyperledger/aries-framework-go/pkg/didcomm/common/transport"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	mockdidcomm "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm"
	mockpackager "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/packager"
)

func TestOutboundDispatcher_Send(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		o := NewOutbound(&provider{packagerValue: &mockpackager.Packager{},
			outboundTransportsValue: []transport.OutboundTransport{&mockdidcomm.MockOutboundTransport{AcceptValue: true}}})
		require.NoError(t, o.Send("data", "", &service.Destination{ServiceEndpoint: "url"}))
	})

	t.Run("test no outbound transport found", func(t *testing.T) {
		o := NewOutbound(&provider{packagerValue: &mockpackager.Packager{},
			outboundTransportsValue: []transport.OutboundTransport{&mockdidcomm.MockOutboundTransport{AcceptValue: false}}})
		err := o.Send("data", "", &service.Destination{ServiceEndpoint: "url"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "no outbound transport found for serviceEndpoint: url")
	})

	t.Run("test pack msg failure", func(t *testing.T) {
		o := NewOutbound(&provider{packagerValue: &mockpackager.Packager{PackErr: fmt.Errorf("pack error")},
			outboundTransportsValue: []transport.OutboundTransport{&mockdidcomm.MockOutboundTransport{AcceptValue: true}}})
		err := o.Send("data", "", &service.Destination{ServiceEndpoint: "url"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "pack error")
	})

	t.Run("test outbound send failure", func(t *testing.T) {
		o := NewOutbound(&provider{packagerValue: &mockpackager.Packager{},
			outboundTransportsValue: []transport.OutboundTransport{
				&mockdidcomm.MockOutboundTransport{AcceptValue: true, SendErr: fmt.Errorf("send error")}}})
		err := o.Send("data", "", &service.Destination{ServiceEndpoint: "url"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "send error")
	})
}

type provider struct {
	packagerValue           commontransport.Packager
	outboundTransportsValue []transport.OutboundTransport
}

func (p *provider) Packager() commontransport.Packager {
	return p.packagerValue
}

func (p *provider) OutboundTransports() []transport.OutboundTransport {
	return p.outboundTransportsValue
}
