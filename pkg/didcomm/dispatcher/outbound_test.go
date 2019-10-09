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
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/envelope"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	mockdidcomm "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm"
	mockpackager "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/envelope"
)

func TestOutboundDispatcher_Send(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		o := NewOutbound(&provider{packagerValue: &mockpackager.BasePackager{},
			outboundTransportsValue: []transport.OutboundTransport{&mockdidcomm.MockOutboundTransport{AcceptValue: true}}})
		require.NoError(t, o.Send("data", "", &service.Destination{ServiceEndpoint: "url"}))
	})

	t.Run("test no outbound transport found", func(t *testing.T) {
		o := NewOutbound(&provider{packagerValue: &mockpackager.BasePackager{},
			outboundTransportsValue: []transport.OutboundTransport{&mockdidcomm.MockOutboundTransport{AcceptValue: false}}})
		err := o.Send("data", "", &service.Destination{ServiceEndpoint: "url"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "no outbound transport found for serviceEndpoint: url")
	})

	t.Run("test pack msg failure", func(t *testing.T) {
		o := NewOutbound(&provider{packagerValue: &mockpackager.BasePackager{PackErr: fmt.Errorf("pack error")},
			outboundTransportsValue: []transport.OutboundTransport{&mockdidcomm.MockOutboundTransport{AcceptValue: true}}})
		err := o.Send("data", "", &service.Destination{ServiceEndpoint: "url"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "pack error")
	})

	t.Run("test outbound send failure", func(t *testing.T) {
		o := NewOutbound(&provider{packagerValue: &mockpackager.BasePackager{},
			outboundTransportsValue: []transport.OutboundTransport{
				&mockdidcomm.MockOutboundTransport{AcceptValue: true, SendErr: fmt.Errorf("send error")}}})
		err := o.Send("data", "", &service.Destination{ServiceEndpoint: "url"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "send error")
	})
}

type provider struct {
	packagerValue           envelope.Packager
	outboundTransportsValue []transport.OutboundTransport
}

func (p *provider) Packager() envelope.Packager {
	return p.packagerValue
}

func (p *provider) OutboundTransports() []transport.OutboundTransport {
	return p.outboundTransportsValue
}
