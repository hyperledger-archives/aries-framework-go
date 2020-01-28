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

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	commontransport "github.com/hyperledger/aries-framework-go/pkg/didcomm/common/transport"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	mockdidcomm "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm"
	mockpackager "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/packager"
	mockdiddoc "github.com/hyperledger/aries-framework-go/pkg/internal/mock/diddoc"
	mockvdri "github.com/hyperledger/aries-framework-go/pkg/internal/mock/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
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

	t.Run("test send with forward message - success", func(t *testing.T) {
		o := NewOutbound(&mockProvider{
			packagerValue:           &mockpackager.Packager{PackValue: createPackedMsgForForward(t)},
			outboundTransportsValue: []transport.OutboundTransport{&mockdidcomm.MockOutboundTransport{AcceptValue: true}},
		})

		require.NoError(t, o.Send("data", "", &service.Destination{
			ServiceEndpoint: "url",
			RecipientKeys:   []string{"abc"},
			RoutingKeys:     []string{"xyz"},
		}))
	})

	t.Run("test send with forward message - create key failure", func(t *testing.T) {
		o := NewOutbound(&mockProvider{
			packagerValue:           &mockpackager.Packager{PackValue: createPackedMsgForForward(t)},
			outboundTransportsValue: []transport.OutboundTransport{&mockdidcomm.MockOutboundTransport{AcceptValue: true}},
			kms: &mockKMS{
				CreateKeyErr: errors.New("create key error"),
			},
		})

		err := o.Send("data", "", &service.Destination{
			ServiceEndpoint: "url",
			RecipientKeys:   []string{"abc"},
			RoutingKeys:     []string{"xyz"},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "create forward msg")
	})

	t.Run("test send with forward message - packer error", func(t *testing.T) {
		o := NewOutbound(&mockProvider{
			packagerValue:           &mockpackager.Packager{PackErr: errors.New("pack error")},
			outboundTransportsValue: []transport.OutboundTransport{&mockdidcomm.MockOutboundTransport{AcceptValue: true}},
		})

		_, err := o.createForwardMessage(createPackedMsgForForward(t), &service.Destination{
			ServiceEndpoint: "url",
			RecipientKeys:   []string{"abc"},
			RoutingKeys:     []string{"xyz"},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "pack forward msg")
	})

	t.Run("test send with forward message - envelop unmarshal error", func(t *testing.T) {
		o := NewOutbound(&mockProvider{
			packagerValue:           &mockpackager.Packager{},
			outboundTransportsValue: []transport.OutboundTransport{},
		})

		_, err := o.createForwardMessage([]byte("invalid json"), &service.Destination{
			ServiceEndpoint: "url",
			RecipientKeys:   []string{"abc"},
			RoutingKeys:     []string{"xyz"},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "unmarshal envelope ")
	})
}

func TestOutboundDispatcher_SendToDID(t *testing.T) {
	mockDoc := mockdiddoc.GetMockDIDDoc()

	t.Run("success", func(t *testing.T) {
		o := NewOutbound(&mockProvider{
			packagerValue: &mockpackager.Packager{PackValue: createPackedMsgForForward(t)},
			vdriRegistry: &mockvdri.MockVDRIRegistry{
				ResolveValue: mockDoc,
			},
			outboundTransportsValue: []transport.OutboundTransport{
				&mockdidcomm.MockOutboundTransport{AcceptValue: true},
			},
		})

		require.NoError(t, o.SendToDID("data", "", ""))
	})

	t.Run("resolve err", func(t *testing.T) {
		o := NewOutbound(&mockProvider{
			packagerValue: &mockpackager.Packager{},
			vdriRegistry: &mockvdri.MockVDRIRegistry{
				ResolveErr: fmt.Errorf("resolve error"),
			},
			outboundTransportsValue: []transport.OutboundTransport{
				&mockdidcomm.MockOutboundTransport{AcceptValue: true},
			},
		})

		err := o.SendToDID("data", "", "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "resolve error")
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

func TestOutboundDispatcher_Forward(t *testing.T) {
	t.Run("test forward - success", func(t *testing.T) {
		o := NewOutbound(&mockProvider{
			packagerValue:           &mockpackager.Packager{},
			outboundTransportsValue: []transport.OutboundTransport{&mockdidcomm.MockOutboundTransport{AcceptValue: true}},
		})
		require.NoError(t, o.Forward("data", &service.Destination{ServiceEndpoint: "url"}))
	})

	t.Run("test forward - no outbound transport found", func(t *testing.T) {
		o := NewOutbound(&mockProvider{packagerValue: &mockpackager.Packager{},
			outboundTransportsValue: []transport.OutboundTransport{&mockdidcomm.MockOutboundTransport{AcceptValue: false}}})
		err := o.Forward("data", &service.Destination{ServiceEndpoint: "url"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "no outbound transport found for serviceEndpoint: url")
	})

	t.Run("test forward - outbound send failure", func(t *testing.T) {
		o := NewOutbound(&mockProvider{packagerValue: &mockpackager.Packager{},
			outboundTransportsValue: []transport.OutboundTransport{
				&mockdidcomm.MockOutboundTransport{AcceptValue: true, SendErr: fmt.Errorf("send error")}}})
		err := o.Forward("data", &service.Destination{ServiceEndpoint: "url"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "send error")
	})
}

func createPackedMsgForForward(t *testing.T) []byte {
	packedMsg := &model.Envelope{}

	msg, err := json.Marshal(packedMsg)
	require.NoError(t, err)

	return msg
}

// mockProvider mock provider
type mockProvider struct {
	packagerValue           commontransport.Packager
	outboundTransportsValue []transport.OutboundTransport
	transportReturnRoute    string
	vdriRegistry            vdri.Registry
	kms                     legacykms.KMS
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

func (p *mockProvider) VDRIRegistry() vdri.Registry {
	return p.vdriRegistry
}

func (p *mockProvider) KMS() legacykms.KeyManager {
	if p.kms != nil {
		return p.kms
	}

	return &mockKMS{}
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

// mockKMS mock Key Management Service (KMS)
type mockKMS struct {
	CreateEncryptionKeyValue string
	CreateSigningKeyValue    string
	CreateKeyErr             error
}

func (m *mockKMS) Close() error {
	return nil
}

func (m *mockKMS) CreateKeySet() (string, string, error) {
	return m.CreateEncryptionKeyValue, m.CreateSigningKeyValue, m.CreateKeyErr
}

func (m *mockKMS) FindVerKey(candidateKeys []string) (int, error) {
	return 0, nil
}

func (m *mockKMS) SignMessage(message []byte, fromVerKey string) ([]byte, error) {
	return nil, nil
}

func (m *mockKMS) DeriveKEK(alg, apu, fromKey, toPubKey []byte) ([]byte, error) {
	return nil, nil
}

func (m *mockKMS) GetEncryptionKey(verKey []byte) ([]byte, error) {
	return nil, nil
}

func (m *mockKMS) ConvertToEncryptionKey(key []byte) ([]byte, error) {
	return nil, nil
}
