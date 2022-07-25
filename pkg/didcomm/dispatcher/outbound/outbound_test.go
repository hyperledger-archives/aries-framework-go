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
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/middleware"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
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

func TestOutBoundDispatcher_createPackedNestedForwards(t *testing.T) {
	t.Run("test send with nested forward message - success", func(t *testing.T) {
		data := "data"
		recKey1 := "recKey1"
		rtKey1 := "rtKey1"
		rtKey2 := "rtKey2"
		packager := &mockPackager{}
		expectedRequest := `{"protected":"","iv":"","ciphertext":"","tag":""}`

		o, err := NewOutbound(&mockProvider{
			packagerValue:           packager,
			outboundTransportsValue: []transport.OutboundTransport{&mockOutboundTransport{expectedRequest: expectedRequest}},
			storageProvider:         mockstore.NewMockStoreProvider(),
			protoStorageProvider:    mockstore.NewMockStoreProvider(),
			mediaTypeProfiles:       []string{transport.MediaTypeDIDCommV2Profile},
		})
		require.NoError(t, err)

		packager.On("PackMessage", []string{recKey1}).Return([]byte(expectedRequest))
		packager.On("PackMessage", []string{rtKey1}).Return([]byte(expectedRequest))
		packager.On("PackMessage", []string{rtKey2}).Return([]byte(expectedRequest))

		require.NoError(t, o.Send(data, "", &service.Destination{
			ServiceEndpoint: model.NewDIDCommV2Endpoint([]model.DIDCommV2Endpoint{
				{URI: "url", RoutingKeys: []string{rtKey1, rtKey2}},
			}),
			RecipientKeys: []string{recKey1},
		}))
		packager.AssertExpectations(t)
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
		require.NoError(t, o.Send("data", mockdiddoc.MockDIDKey(t), &service.Destination{
			ServiceEndpoint: model.NewDIDCommV1Endpoint("url"),
		}))
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
			RecipientKeys: []string{toDIDDoc.KeyAgreement[0].VerificationMethod.ID},
			ServiceEndpoint: model.NewDIDCommV2Endpoint([]model.DIDCommV2Endpoint{{
				URI:    "url",
				Accept: []string{transport.MediaTypeDIDCommV2Profile},
			}}),
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
		err = o.Send("data", mockdiddoc.MockDIDKey(t), &service.Destination{
			ServiceEndpoint: model.NewDIDCommV1Endpoint("url"),
		})
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
		err = o.Send("data", mockdiddoc.MockDIDKey(t), &service.Destination{
			ServiceEndpoint: model.NewDIDCommV1Endpoint("url"),
		})
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
		err = o.Send("data", mockdiddoc.MockDIDKey(t),
			&service.Destination{ServiceEndpoint: model.NewDIDCommV1Endpoint("url")})
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
			ServiceEndpoint: model.NewDIDCommV2Endpoint([]model.DIDCommV2Endpoint{
				{URI: "url", RoutingKeys: []string{"xyz"}},
			}),
			RecipientKeys: []string{"abc"},
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
			ServiceEndpoint: model.NewDIDCommV2Endpoint([]model.DIDCommV2Endpoint{
				{URI: "url", RoutingKeys: []string{"xyz"}},
			}),
			RecipientKeys: []string{"abc"},
		}))
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
			ServiceEndpoint: model.NewDIDCommV2Endpoint([]model.DIDCommV2Endpoint{
				{URI: "url", RoutingKeys: []string{"xyz"}},
			}),
			RecipientKeys: []string{"abc"},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "pack forward msg")
	})

	t.Run("test send with legacy forward message - success", func(t *testing.T) {
		o, err := NewOutbound(&mockProvider{
			packagerValue:           &mockpackager.Packager{PackValue: createPackedMsgForForward(t)},
			outboundTransportsValue: []transport.OutboundTransport{&mockdidcomm.MockOutboundTransport{AcceptValue: true}},
			storageProvider:         mockstore.NewMockStoreProvider(),
			protoStorageProvider:    mockstore.NewMockStoreProvider(),
			mediaTypeProfiles:       []string{transport.LegacyDIDCommV1Profile},
		})
		require.NoError(t, err)

		require.NoError(t, o.Send("data", mockdiddoc.MockDIDKey(t), &service.Destination{
			ServiceEndpoint: model.NewDIDCommV1Endpoint("url"),
			RecipientKeys:   []string{"abc"},
		}))
	})

	t.Run("test send with legacy forward message - did:key error", func(t *testing.T) {
		o, err := NewOutbound(&mockProvider{
			packagerValue:           &mockpackager.Packager{PackValue: createPackedMsgForForward(t)},
			outboundTransportsValue: []transport.OutboundTransport{&mockdidcomm.MockOutboundTransport{AcceptValue: true}},
			storageProvider:         mockstore.NewMockStoreProvider(),
			protoStorageProvider:    mockstore.NewMockStoreProvider(),
			mediaTypeProfiles:       []string{transport.LegacyDIDCommV1Profile},
		})
		require.NoError(t, err)

		env := []byte(`{"protected": "-", "iv": "-", "ciphertext": "-", "tag": "-"}`)
		_, err = o.createForwardMessage(env, &service.Destination{
			ServiceEndpoint: model.NewDIDCommV1Endpoint("url"),
			RecipientKeys:   []string{"did:key:invalid"},
			RoutingKeys:     []string{"did:key:invalid"},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "GetBase58PubKeyFromDIDKey: failed to parse public key bytes from")
	})
}

const testDID = "did:test:abc"

type mockMessage struct {
	Type string
}

func TestOutboundDispatcher_SendToDID(t *testing.T) {
	mockDoc := mockdiddoc.GetMockDIDDoc(t, false)

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

		require.NoError(t, o.SendToDID(service.DIDCommMsgMap{
			"@id":   "123",
			"@type": "abc",
		}, testDID, ""))
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
			didRotator:           middleware.DIDCommMessageMiddleware{},
		})
		require.NoError(t, err)

		o.connections = &mockConnectionLookup{
			getConnectionByDIDsVal: "mock1",
			getConnectionRecordVal: &connection.Record{
				PeerDIDInitialState: "mock-peer-initial-state",
				DIDCommVersion:      service.V2,
				ParentThreadID:      "parent-thread-id-value",
			},
		}

		require.NoError(t, o.SendToDID(service.DIDCommMsgMap{
			"id":   "123",
			"type": "abc",
			"thid": "123",
		}, testDID, ""))
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
			didRotator:           middleware.DIDCommMessageMiddleware{},
		})
		require.NoError(t, err)

		o.connections = &mockConnectionLookup{
			getConnectionByDIDsVal: "mock1",
			getConnectionRecordVal: &connection.Record{},
		}

		// did rotation err is logged, not returned
		require.NoError(t, o.SendToDID(&service.DIDCommMsgMap{
			"invalid": "message",
		}, testDID, ""))
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

		err = o.SendToDID(service.DIDCommMsgMap{}, testDID, "")
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

		err = o.SendToDID(service.DIDCommMsgMap{}, testDID, "")
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

		err = o.SendToDID(service.DIDCommMsgMap{}, testDID, "")
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

		err = o.SendToDID(service.DIDCommMsgMap{}, testDID, "def")
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

		err = o.SendToDID(&mockMessage{Type: "foo"}, testDID, "def")
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

		require.NoError(t, o.SendToDID(service.DIDCommMsgMap{}, testDID, ""))
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

		err = o.SendToDID(service.DIDCommMsgMap{}, testDID, "")
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

		require.NoError(t, o.SendToDID(service.DIDCommMsgMap{}, testDID, ""))
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

		require.NoError(t, o.Send(req, mockdiddoc.MockDIDKey(t),
			&service.Destination{ServiceEndpoint: model.NewDIDCommV2Endpoint([]model.DIDCommV2Endpoint{{URI: "url"}})}))
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

		require.NoError(t, o.Send(req, mockdiddoc.MockDIDKey(t),
			&service.Destination{ServiceEndpoint: model.NewDIDCommV2Endpoint([]model.DIDCommV2Endpoint{{URI: "url"}})}))
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

		require.NoError(t, o.Send(req, mockdiddoc.MockDIDKey(t),
			&service.Destination{ServiceEndpoint: model.NewDIDCommV2Endpoint([]model.DIDCommV2Endpoint{{URI: "url"}})}))
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

		data, err := o.addTransportRouteOptions(testData,
			&service.Destination{ServiceEndpoint: model.NewDIDCommV2Endpoint([]model.DIDCommV2Endpoint{
				{RoutingKeys: []string{"abc"}},
			})})
		require.NoError(t, err)
		require.Equal(t, testData, data)
	})
}

func TestOutboundDispatcher_Forward(t *testing.T) {
	t.Run("test forward - success", func(t *testing.T) {
		o, err := NewOutbound(&mockProvider{
			packagerValue: &mockpackager.Packager{},
			outboundTransportsValue: []transport.OutboundTransport{&mockdidcomm.MockOutboundTransport{
				AcceptValue: true,
			}},
			storageProvider:      mockstore.NewMockStoreProvider(),
			protoStorageProvider: mockstore.NewMockStoreProvider(),
			mediaTypeProfiles:    []string{transport.MediaTypeDIDCommV2Profile},
		})
		require.NoError(t, err)
		require.NoError(t, o.Forward("data", &service.Destination{
			ServiceEndpoint: model.NewDIDCommV2Endpoint([]model.DIDCommV2Endpoint{{URI: "url"}}),
		}))
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
		err = o.Forward("data", &service.Destination{
			ServiceEndpoint: model.NewDIDCommV2Endpoint([]model.DIDCommV2Endpoint{{URI: "url"}}),
		})
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
		err = o.Forward("data", &service.Destination{ServiceEndpoint: model.NewDIDCommV2Endpoint([]model.
			DIDCommV2Endpoint{{URI: "url"}})})
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
	didRotator              middleware.DIDCommMessageMiddleware
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

func (p *mockProvider) DIDRotator() *middleware.DIDCommMessageMiddleware {
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
type mockPackager struct {
	mock.Mock
}

func (m *mockPackager) PackMessage(e *transport.Envelope) ([]byte, error) {
	if len(m.ExpectedCalls) > 0 {
		args := m.Called(e.ToKeys)
		switch v := args.Get(0).(type) {
		case []byte:
			return v, nil
		default:
			return e.Message, nil
		}
	}

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
