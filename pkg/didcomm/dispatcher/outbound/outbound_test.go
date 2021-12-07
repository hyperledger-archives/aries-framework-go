/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outbound

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/didrotate"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockdidcomm "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm"
	mockpackager "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/packager"
	mockdiddoc "github.com/hyperledger/aries-framework-go/pkg/mock/diddoc"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

func TestNewOutbound(t *testing.T) {
	t.Run("error if cannot init connection lookup", func(t *testing.T) {
		expected := errors.New("test")
		_, err := NewOutbound(&mockProvider{
			protoStorageProvider: mockstore.NewMockStoreProvider(),
			storageProvider: &mockstore.MockStoreProvider{
				ErrOpenStoreHandle: expected,
			},
			mediaTypeProfiles: []string{transport.MediaTypeDIDCommV2Profile},
		})
		require.ErrorIs(t, err, expected)
	})
}

func TestOutboundDispatcher_Send(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		o, err := NewOutbound(&mockProvider{
			packagerValue:           &mockpackager.Packager{},
			outboundTransportsValue: []transport.OutboundTransport{&mockdidcomm.MockOutboundTransport{AcceptValue: true}},
			storageProvider:         mockstore.NewMockStoreProvider(),
			protoStorageProvider:    mockstore.NewMockStoreProvider(),
			mediaTypeProfiles:       []string{transport.MediaTypeV1PlaintextPayload},
		})
		require.NoError(t, err)
		require.NoError(t, o.Send("data", mockdiddoc.MockDIDKey(t), &service.Destination{ServiceEndpoint: "url"}))
	})

	t.Run("test success", func(t *testing.T) {
		o, err := NewOutbound(&mockProvider{
			packagerValue:           &mockpackager.Packager{},
			outboundTransportsValue: []transport.OutboundTransport{&mockdidcomm.MockOutboundTransport{AcceptValue: true}},
			storageProvider:         mockstore.NewMockStoreProvider(),
			protoStorageProvider:    mockstore.NewMockStoreProvider(),
			mediaTypeProfiles:       []string{transport.MediaTypeDIDCommV2Profile},
		})
		require.NoError(t, err)

		fromDIDDoc := mockdiddoc.GetMockDIDDocWithDIDCommV2Bloc(t, "alice")
		toDIDDoc := mockdiddoc.GetMockDIDDocWithDIDCommV2Bloc(t, "bob")

		require.NoError(t, o.Send("data", fromDIDDoc.KeyAgreement[0].VerificationMethod.ID, &service.Destination{
			RecipientKeys:     []string{toDIDDoc.KeyAgreement[0].VerificationMethod.ID},
			ServiceEndpoint:   "url",
			MediaTypeProfiles: []string{transport.MediaTypeDIDCommV2Profile},
		}))
	})

	t.Run("test no outbound transport found", func(t *testing.T) {
		o, err := NewOutbound(&mockProvider{
			packagerValue:           &mockpackager.Packager{},
			outboundTransportsValue: []transport.OutboundTransport{&mockdidcomm.MockOutboundTransport{AcceptValue: false}},
			storageProvider:         mockstore.NewMockStoreProvider(),
			protoStorageProvider:    mockstore.NewMockStoreProvider(),
			mediaTypeProfiles:       []string{transport.MediaTypeDIDCommV2Profile},
		})
		require.NoError(t, err)
		err = o.Send("data", mockdiddoc.MockDIDKey(t), &service.Destination{ServiceEndpoint: "url"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "outboundDispatcher.Send: no transport found for destination")
	})

	t.Run("test pack msg failure", func(t *testing.T) {
		o, err := NewOutbound(&mockProvider{
			packagerValue:           &mockpackager.Packager{PackErr: fmt.Errorf("pack error")},
			outboundTransportsValue: []transport.OutboundTransport{&mockdidcomm.MockOutboundTransport{AcceptValue: true}},
			storageProvider:         mockstore.NewMockStoreProvider(),
			protoStorageProvider:    mockstore.NewMockStoreProvider(),
			mediaTypeProfiles:       []string{transport.MediaTypeDIDCommV2Profile},
		})
		require.NoError(t, err)
		err = o.Send("data", mockdiddoc.MockDIDKey(t), &service.Destination{ServiceEndpoint: "url"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "pack error")
	})

	t.Run("test outbound send failure", func(t *testing.T) {
		o, err := NewOutbound(&mockProvider{
			packagerValue: &mockpackager.Packager{},
			outboundTransportsValue: []transport.OutboundTransport{
				&mockdidcomm.MockOutboundTransport{AcceptValue: true, SendErr: fmt.Errorf("send error")},
			},
			storageProvider:      mockstore.NewMockStoreProvider(),
			protoStorageProvider: mockstore.NewMockStoreProvider(),
			mediaTypeProfiles:    []string{transport.MediaTypeDIDCommV2Profile},
		})
		require.NoError(t, err)
		err = o.Send("data", mockdiddoc.MockDIDKey(t), &service.Destination{ServiceEndpoint: "url"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "send error")
	})

	t.Run("test send with forward message - success", func(t *testing.T) {
		o, err := NewOutbound(&mockProvider{
			packagerValue:           &mockpackager.Packager{PackValue: createPackedMsgForForward(t)},
			outboundTransportsValue: []transport.OutboundTransport{&mockdidcomm.MockOutboundTransport{AcceptValue: true}},
			storageProvider:         mockstore.NewMockStoreProvider(),
			protoStorageProvider:    mockstore.NewMockStoreProvider(),
			mediaTypeProfiles:       []string{transport.MediaTypeDIDCommV2Profile},
		})
		require.NoError(t, err)

		require.NoError(t, o.Send("data", mockdiddoc.MockDIDKey(t), &service.Destination{
			ServiceEndpoint: "url",
			RecipientKeys:   []string{"abc"},
			RoutingKeys:     []string{"xyz"},
		}))
	})

	t.Run("test send with forward message with multiple media type profiles- success", func(t *testing.T) {
		o, err := NewOutbound(&mockProvider{
			packagerValue:           &mockpackager.Packager{PackValue: createPackedMsgForForward(t)},
			outboundTransportsValue: []transport.OutboundTransport{&mockdidcomm.MockOutboundTransport{AcceptValue: true}},
			storageProvider:         mockstore.NewMockStoreProvider(),
			protoStorageProvider:    mockstore.NewMockStoreProvider(),
			mediaTypeProfiles: []string{
				transport.MediaTypeProfileDIDCommAIP1,
				transport.MediaTypeAIP2RFC0019Profile,
				transport.MediaTypeDIDCommV2Profile,
			},
		})
		require.NoError(t, err)

		require.NoError(t, o.Send("data", mockdiddoc.MockDIDKey(t), &service.Destination{
			ServiceEndpoint: "url",
			RecipientKeys:   []string{"abc"},
			RoutingKeys:     []string{"xyz"},
		}))
	})

	t.Run("test send with forward message - create key failure", func(t *testing.T) {
		o, err := NewOutbound(&mockProvider{
			packagerValue:           &mockpackager.Packager{PackValue: createPackedMsgForForward(t)},
			outboundTransportsValue: []transport.OutboundTransport{&mockdidcomm.MockOutboundTransport{AcceptValue: true}},
			kms: &mockkms.KeyManager{
				CrAndExportPubKeyErr: errors.New("create and export key error"),
			},
			storageProvider:      mockstore.NewMockStoreProvider(),
			protoStorageProvider: mockstore.NewMockStoreProvider(),
			mediaTypeProfiles:    []string{transport.MediaTypeAIP2RFC0019Profile},
		})
		require.NoError(t, err)

		err = o.Send("data", mockdiddoc.MockDIDKey(t), &service.Destination{
			ServiceEndpoint: "url",
			RecipientKeys:   []string{"abc"},
			RoutingKeys:     []string{"xyz"},
		})
		require.EqualError(t, err, "outboundDispatcher.Send: failed to create forward msg: failed Create "+
			"and export Encryption Key: create and export key error")
	})

	t.Run("test send with forward message - packer error", func(t *testing.T) {
		o, err := NewOutbound(&mockProvider{
			packagerValue:           &mockpackager.Packager{PackErr: errors.New("pack error")},
			outboundTransportsValue: []transport.OutboundTransport{&mockdidcomm.MockOutboundTransport{AcceptValue: true}},
			storageProvider:         mockstore.NewMockStoreProvider(),
			protoStorageProvider:    mockstore.NewMockStoreProvider(),
			mediaTypeProfiles:       []string{transport.MediaTypeDIDCommV2Profile},
		})
		require.NoError(t, err)

		_, err = o.createForwardMessage(createPackedMsgForForward(t), &service.Destination{
			ServiceEndpoint: "url",
			RecipientKeys:   []string{"abc"},
			RoutingKeys:     []string{"xyz"},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "pack forward msg")
	})
}

func TestOutboundDispatcher_SendToDID(t *testing.T) {
	mockDoc := mockdiddoc.GetMockDIDDoc(t)

	t.Run("success with existing connection record", func(t *testing.T) {
		o, err := NewOutbound(&mockProvider{
			packagerValue: &mockpackager.Packager{PackValue: createPackedMsgForForward(t)},
			vdr: &mockvdr.MockVDRegistry{
				ResolveValue: mockDoc,
			},
			outboundTransportsValue: []transport.OutboundTransport{
				&mockdidcomm.MockOutboundTransport{AcceptValue: true},
			},
			storageProvider:      mockstore.NewMockStoreProvider(),
			protoStorageProvider: mockstore.NewMockStoreProvider(),
			mediaTypeProfiles:    []string{transport.MediaTypeDIDCommV2Profile},
		})
		require.NoError(t, err)

		o.connections = &mockConnectionLookup{
			getConnectionByDIDsVal: "mock1",
			getConnectionRecordVal: &connection.Record{},
		}

		require.NoError(t, o.SendToDID("data", "", ""))
	})

	t.Run("success with did rotation check", func(t *testing.T) {
		o, err := NewOutbound(&mockProvider{
			packagerValue: &mockpackager.Packager{PackValue: createPackedMsgForForward(t)},
			vdr: &mockvdr.MockVDRegistry{
				ResolveValue: mockDoc,
			},
			outboundTransportsValue: []transport.OutboundTransport{
				&mockdidcomm.MockOutboundTransport{AcceptValue: true},
			},
			storageProvider:      mockstore.NewMockStoreProvider(),
			protoStorageProvider: mockstore.NewMockStoreProvider(),
			mediaTypeProfiles:    []string{transport.MediaTypeDIDCommV2Profile},
			didRotator:           didrotate.DIDRotator{},
		})
		require.NoError(t, err)

		o.connections = &mockConnectionLookup{
			getConnectionByDIDsVal: "mock1",
			getConnectionRecordVal: &connection.Record{},
		}

		require.NoError(t, o.SendToDID(service.DIDCommMsgMap{
			"id":   "123",
			"type": "abc",
		}, "", ""))
	})

	t.Run("did rotation err", func(t *testing.T) {
		o, err := NewOutbound(&mockProvider{
			packagerValue: &mockpackager.Packager{PackValue: createPackedMsgForForward(t)},
			vdr: &mockvdr.MockVDRegistry{
				ResolveValue: mockDoc,
			},
			outboundTransportsValue: []transport.OutboundTransport{
				&mockdidcomm.MockOutboundTransport{AcceptValue: true},
			},
			storageProvider:      mockstore.NewMockStoreProvider(),
			protoStorageProvider: mockstore.NewMockStoreProvider(),
			mediaTypeProfiles:    []string{transport.MediaTypeDIDCommV2Profile},
			didRotator:           didrotate.DIDRotator{},
		})
		require.NoError(t, err)

		o.connections = &mockConnectionLookup{
			getConnectionByDIDsVal: "mock1",
			getConnectionRecordVal: &connection.Record{},
		}

		// did rotation err is logged, not returned
		require.NoError(t, o.SendToDID(&service.DIDCommMsgMap{
			"invalid": "message",
		}, "", ""))
	})

	t.Run("resolve err", func(t *testing.T) {
		o, err := NewOutbound(&mockProvider{
			packagerValue: &mockpackager.Packager{},
			vdr: &mockvdr.MockVDRegistry{
				ResolveErr: fmt.Errorf("resolve error"),
			},
			outboundTransportsValue: []transport.OutboundTransport{
				&mockdidcomm.MockOutboundTransport{AcceptValue: true},
			},
			storageProvider:      mockstore.NewMockStoreProvider(),
			protoStorageProvider: mockstore.NewMockStoreProvider(),
			mediaTypeProfiles:    []string{transport.MediaTypeDIDCommV2Profile},
		})
		require.NoError(t, err)

		o.connections = &mockConnectionLookup{
			getConnectionRecordVal: &connection.Record{},
		}

		err = o.SendToDID("data", "", "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "resolve error")
	})

	t.Run("resolve err 2", func(t *testing.T) {
		o, err := NewOutbound(&mockProvider{
			packagerValue: &mockpackager.Packager{},
			vdr: &mockvdr.MockVDRegistry{
				ResolveFunc: countDownMockResolveFunc(mockDoc, 1, fmt.Errorf("resolve error")),
			},
			outboundTransportsValue: []transport.OutboundTransport{
				&mockdidcomm.MockOutboundTransport{AcceptValue: true},
			},
			storageProvider:      mockstore.NewMockStoreProvider(),
			protoStorageProvider: mockstore.NewMockStoreProvider(),
			mediaTypeProfiles:    []string{transport.MediaTypeDIDCommV2Profile},
		})
		require.NoError(t, err)

		o.connections = &mockConnectionLookup{
			getConnectionRecordVal: &connection.Record{},
		}

		err = o.SendToDID("data", "", "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "resolve error")
	})

	t.Run("error if cannot fetch connection record", func(t *testing.T) {
		o, err := NewOutbound(&mockProvider{
			packagerValue: &mockpackager.Packager{},
			vdr: &mockvdr.MockVDRegistry{
				ResolveValue: mockDoc,
			},
			outboundTransportsValue: []transport.OutboundTransport{
				&mockdidcomm.MockOutboundTransport{AcceptValue: true},
			},
			storageProvider:      mockstore.NewMockStoreProvider(),
			protoStorageProvider: mockstore.NewMockStoreProvider(),
			mediaTypeProfiles:    []string{transport.MediaTypeV1EncryptedEnvelope},
		})
		require.NoError(t, err)

		expected := errors.New("test")

		o.connections = &mockConnectionLookup{
			getConnectionByDIDsVal: "mock1",
			getConnectionRecordErr: expected,
		}

		err = o.SendToDID("data", "", "")
		require.ErrorIs(t, err, expected)
		require.Contains(t, err.Error(), "failed to fetch connection record")
	})

	t.Run("create destination err", func(t *testing.T) {
		o, err := NewOutbound(&mockProvider{
			packagerValue: &mockpackager.Packager{PackValue: createPackedMsgForForward(t)},
			vdr: &mockvdr.MockVDRegistry{
				ResolveValue: &did.Doc{},
			},
			outboundTransportsValue: []transport.OutboundTransport{
				&mockdidcomm.MockOutboundTransport{AcceptValue: true},
			},
			storageProvider:      mockstore.NewMockStoreProvider(),
			protoStorageProvider: mockstore.NewMockStoreProvider(),
			mediaTypeProfiles:    []string{transport.MediaTypeDIDCommV2Profile},
		})
		require.NoError(t, err)

		o.connections = &mockConnectionLookup{
			getConnectionByDIDsVal: "mock1",
			getConnectionRecordVal: &connection.Record{},
		}

		err = o.SendToDID("data", "abc", "def")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get didcomm destination")
	})

	t.Run("create destination err 2", func(t *testing.T) {
		o, err := NewOutbound(&mockProvider{
			packagerValue: &mockpackager.Packager{PackValue: createPackedMsgForForward(t)},
			vdr: &mockvdr.MockVDRegistry{
				ResolveFunc: countDownMockResolveFunc(&did.Doc{}, 1, mockDoc),
			},
			outboundTransportsValue: []transport.OutboundTransport{
				&mockdidcomm.MockOutboundTransport{AcceptValue: true},
			},
			storageProvider:      mockstore.NewMockStoreProvider(),
			protoStorageProvider: mockstore.NewMockStoreProvider(),
			mediaTypeProfiles:    []string{transport.MediaTypeDIDCommV2Profile},
		})
		require.NoError(t, err)

		o.connections = &mockConnectionLookup{
			getConnectionByDIDsVal: "mock1",
			getConnectionRecordVal: &connection.Record{},
		}

		err = o.SendToDID("data", "abc", "def")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get didcomm destination")
	})

	t.Run("success event with nil connection record, using default media type profile", func(t *testing.T) {
		o, err := NewOutbound(&mockProvider{
			packagerValue: &mockpackager.Packager{PackValue: createPackedMsgForForward(t)},
			vdr: &mockvdr.MockVDRegistry{
				ResolveValue: mockDoc,
			},
			outboundTransportsValue: []transport.OutboundTransport{
				&mockdidcomm.MockOutboundTransport{AcceptValue: true},
			},
			storageProvider:      mockstore.NewMockStoreProvider(),
			protoStorageProvider: mockstore.NewMockStoreProvider(),
			mediaTypeProfiles:    []string{transport.MediaTypeV1EncryptedEnvelope},
		})
		require.NoError(t, err)

		expected := storage.ErrDataNotFound

		o.connections = &mockConnectionLookup{
			getConnectionRecordErr: expected,
		}

		require.NoError(t, o.SendToDID("data", "", ""))
	})

	t.Run("fail with nil connection record, unable to save new record", func(t *testing.T) {
		o, err := NewOutbound(&mockProvider{
			packagerValue: &mockpackager.Packager{PackValue: createPackedMsgForForward(t)},
			vdr: &mockvdr.MockVDRegistry{
				ResolveValue: mockDoc,
			},
			outboundTransportsValue: []transport.OutboundTransport{
				&mockdidcomm.MockOutboundTransport{AcceptValue: true},
			},
			storageProvider:      mockstore.NewMockStoreProvider(),
			protoStorageProvider: mockstore.NewMockStoreProvider(),
			mediaTypeProfiles:    []string{transport.MediaTypeV1EncryptedEnvelope},
		})
		require.NoError(t, err)

		expected := fmt.Errorf("store error")

		o.connections = &mockConnectionLookup{
			getConnectionRecordErr: storage.ErrDataNotFound,
			saveConnectionErr:      expected,
		}

		err = o.SendToDID("data", "", "")
		require.ErrorIs(t, err, expected)
		require.Contains(t, err.Error(), "failed to save new connection")
	})

	t.Run("success event with nil connection record, using default media type profile with "+
		"priority", func(t *testing.T) {
		o, err := NewOutbound(&mockProvider{
			packagerValue: &mockpackager.Packager{PackValue: createPackedMsgForForward(t)},
			vdr: &mockvdr.MockVDRegistry{
				ResolveValue: mockDoc,
			},
			outboundTransportsValue: []transport.OutboundTransport{
				&mockdidcomm.MockOutboundTransport{AcceptValue: true},
			},
			storageProvider:      mockstore.NewMockStoreProvider(),
			protoStorageProvider: mockstore.NewMockStoreProvider(),
			mediaTypeProfiles: []string{
				transport.MediaTypeRFC0019EncryptedEnvelope,
				transport.MediaTypeV1EncryptedEnvelope,
				transport.MediaTypeV2EncryptedEnvelope,
			},
		})
		require.NoError(t, err)

		expected := storage.ErrDataNotFound

		o.connections = &mockConnectionLookup{
			getConnectionByDIDsVal: "mock1",
			getConnectionRecordErr: expected,
		}

		require.NoError(t, o.SendToDID("data", "", ""))
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

		o, err := NewOutbound(&mockProvider{
			packagerValue: &mockPackager{},
			outboundTransportsValue: []transport.OutboundTransport{
				&mockOutboundTransport{
					expectedRequest: string(expectedRequest),
				},
			},
			transportReturnRoute: transportReturnRoute,
			protoStorageProvider: mockstore.NewMockStoreProvider(),
			storageProvider:      mockstore.NewMockStoreProvider(),
			mediaTypeProfiles:    []string{transport.MediaTypeDIDCommV2Profile},
		})
		require.NoError(t, err)

		require.NoError(t, o.Send(req, mockdiddoc.MockDIDKey(t), &service.Destination{ServiceEndpoint: "url"}))
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

		o, err := NewOutbound(&mockProvider{
			packagerValue: &mockPackager{},
			outboundTransportsValue: []transport.OutboundTransport{
				&mockOutboundTransport{
					expectedRequest: string(expectedRequest),
				},
			},
			transportReturnRoute: transportReturnRoute,
			storageProvider:      mockstore.NewMockStoreProvider(),
			protoStorageProvider: mockstore.NewMockStoreProvider(),
			mediaTypeProfiles:    []string{transport.MediaTypeDIDCommV2Profile},
		})
		require.NoError(t, err)

		require.NoError(t, o.Send(req, mockdiddoc.MockDIDKey(t), &service.Destination{ServiceEndpoint: "url"}))
	})

	t.Run("transport route option - no value set", func(t *testing.T) {
		req := &decorator.Thread{
			ID: uuid.New().String(),
		}

		expectedRequest, err := json.Marshal(req)
		require.NoError(t, err)
		require.NotNil(t, expectedRequest)

		o, err := NewOutbound(&mockProvider{
			packagerValue: &mockPackager{},
			outboundTransportsValue: []transport.OutboundTransport{
				&mockOutboundTransport{
					expectedRequest: string(expectedRequest),
				},
			},
			transportReturnRoute: "",
			storageProvider:      mockstore.NewMockStoreProvider(),
			protoStorageProvider: mockstore.NewMockStoreProvider(),
			mediaTypeProfiles:    []string{transport.MediaTypeDIDCommV2Profile},
		})
		require.NoError(t, err)

		require.NoError(t, o.Send(req, mockdiddoc.MockDIDKey(t), &service.Destination{ServiceEndpoint: "url"}))
	})

	t.Run("transport route option - forward message", func(t *testing.T) {
		transportReturnRoute := "thread"
		o, err := NewOutbound(&mockProvider{
			packagerValue:        &mockPackager{},
			transportReturnRoute: transportReturnRoute,
			storageProvider:      mockstore.NewMockStoreProvider(),
			protoStorageProvider: mockstore.NewMockStoreProvider(),
			mediaTypeProfiles:    []string{transport.MediaTypeDIDCommV2Profile},
		})
		require.NoError(t, err)

		testData := []byte("testData")

		data, err := o.addTransportRouteOptions(testData, &service.Destination{RoutingKeys: []string{"abc"}})
		require.NoError(t, err)
		require.Equal(t, testData, data)
	})
}

func TestOutboundDispatcher_Forward(t *testing.T) {
	t.Run("test forward - success", func(t *testing.T) {
		o, err := NewOutbound(&mockProvider{
			packagerValue:           &mockpackager.Packager{},
			outboundTransportsValue: []transport.OutboundTransport{&mockdidcomm.MockOutboundTransport{AcceptValue: true}},
			storageProvider:         mockstore.NewMockStoreProvider(),
			protoStorageProvider:    mockstore.NewMockStoreProvider(),
			mediaTypeProfiles:       []string{transport.MediaTypeDIDCommV2Profile},
		})
		require.NoError(t, err)
		require.NoError(t, o.Forward("data", &service.Destination{ServiceEndpoint: "url"}))
	})

	t.Run("test forward - no outbound transport found", func(t *testing.T) {
		o, err := NewOutbound(&mockProvider{
			packagerValue:           &mockpackager.Packager{},
			outboundTransportsValue: []transport.OutboundTransport{&mockdidcomm.MockOutboundTransport{AcceptValue: false}},
			storageProvider:         mockstore.NewMockStoreProvider(),
			protoStorageProvider:    mockstore.NewMockStoreProvider(),
			mediaTypeProfiles:       []string{transport.MediaTypeDIDCommV2Profile},
		})
		require.NoError(t, err)
		err = o.Forward("data", &service.Destination{ServiceEndpoint: "url"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "outboundDispatcher.Forward: no transport found for serviceEndpoint: url")
	})

	t.Run("test forward - outbound send failure", func(t *testing.T) {
		o, err := NewOutbound(&mockProvider{
			packagerValue: &mockpackager.Packager{},
			outboundTransportsValue: []transport.OutboundTransport{
				&mockdidcomm.MockOutboundTransport{AcceptValue: true, SendErr: fmt.Errorf("send error")},
			},
			storageProvider:      mockstore.NewMockStoreProvider(),
			protoStorageProvider: mockstore.NewMockStoreProvider(),
			mediaTypeProfiles:    []string{transport.MediaTypeDIDCommV2Profile},
		})
		require.NoError(t, err)
		err = o.Forward("data", &service.Destination{ServiceEndpoint: "url"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "send error")
	})
}

func createPackedMsgForForward(_ *testing.T) []byte {
	return []byte("")
}

// mockProvider mock provider.
type mockProvider struct {
	packagerValue           transport.Packager
	outboundTransportsValue []transport.OutboundTransport
	transportReturnRoute    string
	vdr                     vdrapi.Registry
	kms                     kms.KeyManager
	storageProvider         storage.Provider
	protoStorageProvider    storage.Provider
	mediaTypeProfiles       []string
	keyAgreementType        kms.KeyType
	didRotator              didrotate.DIDRotator
}

func (p *mockProvider) Packager() transport.Packager {
	return p.packagerValue
}

func (p *mockProvider) OutboundTransports() []transport.OutboundTransport {
	return p.outboundTransportsValue
}

func (p *mockProvider) TransportReturnRoute() string {
	return p.transportReturnRoute
}

func (p *mockProvider) VDRegistry() vdrapi.Registry {
	return p.vdr
}

func (p *mockProvider) KMS() kms.KeyManager {
	if p.kms != nil {
		return p.kms
	}

	return &mockkms.KeyManager{}
}

func (p *mockProvider) StorageProvider() storage.Provider {
	return p.storageProvider
}

func (p *mockProvider) ProtocolStateStorageProvider() storage.Provider {
	return p.protoStorageProvider
}

func (p *mockProvider) MediaTypeProfiles() []string {
	return p.mediaTypeProfiles
}

func (p *mockProvider) KeyAgreementType() kms.KeyType {
	return p.keyAgreementType
}

func (p *mockProvider) DIDRotator() *didrotate.DIDRotator {
	return &p.didRotator
}

// mockOutboundTransport mock outbound transport.
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

// mockPackager mock packager.
type mockPackager struct{}

func (m *mockPackager) PackMessage(e *transport.Envelope) ([]byte, error) {
	return e.Message, nil
}

func (m *mockPackager) UnpackMessage(encMessage []byte) (*transport.Envelope, error) {
	return nil, nil
}

type mockConnectionLookup struct {
	getConnectionByDIDsVal string
	getConnectionByDIDsErr error
	getConnectionRecordVal *connection.Record
	getConnectionRecordErr error
	saveConnectionErr      error
}

func (m *mockConnectionLookup) GetConnectionIDByDIDs(myDID, theirDID string) (string, error) {
	return m.getConnectionByDIDsVal, m.getConnectionByDIDsErr
}

func (m *mockConnectionLookup) GetConnectionRecord(s string) (*connection.Record, error) {
	return m.getConnectionRecordVal, m.getConnectionRecordErr
}

func (m *mockConnectionLookup) GetConnectionRecordByDIDs(myDID, theirDID string) (*connection.Record, error) {
	if m.getConnectionByDIDsErr != nil {
		return nil, m.getConnectionByDIDsErr
	}

	return m.getConnectionRecordVal, m.getConnectionRecordErr
}

func (m *mockConnectionLookup) SaveConnectionRecord(record *connection.Record) error {
	return m.saveConnectionErr
}

func countDownMockResolveFunc(first interface{}, countFirst int, rest interface{},
) func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	var (
		firstDoc *did.Doc
		restDoc  *did.Doc
		firstErr error
		restErr  error
	)

	switch f := first.(type) {
	case *did.Doc:
		firstDoc = f
	case error:
		firstErr = f
	}

	switch r := rest.(type) {
	case *did.Doc:
		restDoc = r
	case error:
		restErr = r
	}

	return func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
		if countFirst <= 0 {
			return &did.DocResolution{DIDDocument: restDoc}, restErr
		}

		countFirst--

		return &did.DocResolution{DIDDocument: firstDoc}, firstErr
	}
}
