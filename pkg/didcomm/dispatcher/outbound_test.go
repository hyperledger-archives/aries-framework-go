/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dispatcher

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	commontransport "github.com/hyperledger/aries-framework-go/pkg/didcomm/common/transport"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	mockdidcomm "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm"
	mockpackager "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/packager"
)

func TestOutboundDispatcher_Send(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		o := NewOutbound(&mockProvider{
			packagerValue:           &mockpackager.Packager{},
			outboundTransportsValue: []transport.OutboundTransport{&mockdidcomm.MockOutboundTransport{AcceptValue: true}},
		})
		require.NoError(t, o.Send("data", "", &service.Destination{ServiceEndpoint: "url"}))
	})

	t.Run("test no outbound transport found", func(t *testing.T) {
		o := NewOutbound(&mockProvider{packagerValue: &mockpackager.Packager{},
			outboundTransportsValue: []transport.OutboundTransport{&mockdidcomm.MockOutboundTransport{AcceptValue: false}}})
		err := o.Send("data", "", &service.Destination{ServiceEndpoint: "url"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "no outbound transport found for serviceEndpoint: url")
	})

	t.Run("test pack msg failure", func(t *testing.T) {
		o := NewOutbound(&mockProvider{packagerValue: &mockpackager.Packager{PackErr: fmt.Errorf("pack error")},
			outboundTransportsValue: []transport.OutboundTransport{&mockdidcomm.MockOutboundTransport{AcceptValue: true}}})
		err := o.Send("data", "", &service.Destination{ServiceEndpoint: "url"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "pack error")
	})

	t.Run("test outbound send failure", func(t *testing.T) {
		o := NewOutbound(&mockProvider{packagerValue: &mockpackager.Packager{},
			outboundTransportsValue: []transport.OutboundTransport{
				&mockdidcomm.MockOutboundTransport{AcceptValue: true, SendErr: fmt.Errorf("send error")}}})
		err := o.Send("data", "", &service.Destination{ServiceEndpoint: "url"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "send error")
	})
}

func TestOutboundDispatcherTransportReturnRoute(t *testing.T) {
	t.Run("transport route option - value set all", func(t *testing.T) {
		transportReturnRoute := "all"
		req := &decorator.Thread{
			ID: uuid.New().String(),
		}

		outboundReq := struct {
			*decorator.Transport
			*decorator.Thread
		}{
			&decorator.Transport{ReturnRoute: &decorator.ReturnRoute{Value: transportReturnRoute}},
			req,
		}
		expectedRequest, err := json.Marshal(outboundReq)
		require.NoError(t, err)
		require.NotNil(t, expectedRequest)

		o := NewOutbound(&mockProvider{
			packagerValue: &mockPackager{},
			outboundTransportsValue: []transport.OutboundTransport{&mockOutboundTransport{
				expectedRequest: string(expectedRequest)},
			},
			transportReturnRoute: transportReturnRoute,
		})

		require.NoError(t, o.Send(req, "", &service.Destination{ServiceEndpoint: "url"}))
	})

	t.Run("transport route option - value set thread", func(t *testing.T) {
		transportReturnRoute := "thread"
		req := &decorator.Thread{
			ID: uuid.New().String(),
		}

		outboundReq := struct {
			*decorator.Transport
			*decorator.Thread
		}{
			&decorator.Transport{ReturnRoute: &decorator.ReturnRoute{Value: transportReturnRoute}},
			req,
		}
		expectedRequest, err := json.Marshal(outboundReq)
		require.NoError(t, err)
		require.NotNil(t, expectedRequest)

		o := NewOutbound(&mockProvider{
			packagerValue: &mockPackager{},
			outboundTransportsValue: []transport.OutboundTransport{&mockOutboundTransport{
				expectedRequest: string(expectedRequest)},
			},
			transportReturnRoute: transportReturnRoute,
		})

		require.NoError(t, o.Send(req, "", &service.Destination{ServiceEndpoint: "url"}))
	})

	t.Run("transport route option - no value set", func(t *testing.T) {
		req := &decorator.Thread{
			ID: uuid.New().String(),
		}

		expectedRequest, err := json.Marshal(req)
		require.NoError(t, err)
		require.NotNil(t, expectedRequest)

		o := NewOutbound(&mockProvider{
			packagerValue: &mockPackager{},
			outboundTransportsValue: []transport.OutboundTransport{&mockOutboundTransport{
				expectedRequest: string(expectedRequest)},
			},
			transportReturnRoute: "",
		})

		require.NoError(t, o.Send(req, "", &service.Destination{ServiceEndpoint: "url"}))
	})
}

// mockProvider mock provider
type mockProvider struct {
	packagerValue           commontransport.Packager
	outboundTransportsValue []transport.OutboundTransport
	transportReturnRoute    string
}

func (p *mockProvider) Packager() commontransport.Packager {
	return p.packagerValue
}

func (p *mockProvider) OutboundTransports() []transport.OutboundTransport {
	return p.outboundTransportsValue
}

func (p *mockProvider) TransportReturnRoute() string {
	return p.transportReturnRoute
}

// mockOutboundTransport mock outbound transport
type mockOutboundTransport struct {
	expectedRequest string
	acceptRecipient bool
}

func (o *mockOutboundTransport) Start(prov transport.Provider) error {
	return nil
}

func (o *mockOutboundTransport) Send(data []byte, destination *service.Destination) (string, error) {
	if string(data) != o.expectedRequest {
		return "", errors.New("invalid request")
	}

	return "", nil
}

func (o *mockOutboundTransport) AcceptRecipient([]string) bool {
	return o.acceptRecipient
}

func (o *mockOutboundTransport) Accept(url string) bool {
	return true
}

// mockPackager mock packager
type mockPackager struct {
}

func (m *mockPackager) PackMessage(e *commontransport.Envelope) ([]byte, error) {
	return e.Message, nil
}

func (m *mockPackager) UnpackMessage(encMessage []byte) (*commontransport.Envelope, error) {
	return nil, nil
}
