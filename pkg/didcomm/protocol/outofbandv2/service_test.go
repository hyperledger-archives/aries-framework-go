/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofbandv2

import (
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/messagepickup"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol"
	mocksvc "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/service"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
)

func TestNew(t *testing.T) {
	t.Run("returns the service", func(t *testing.T) {
		s, err := New(testProvider(t))
		require.NoError(t, err)
		require.NotNil(t, s)
	})
	t.Run("wraps error thrown from protocol state store when it cannot be opened", func(t *testing.T) {
		expected := errors.New("test")
		provider := testProvider(t)
		provider.ProtocolStateStoreProvider = &mockstore.MockStoreProvider{
			ErrOpenStoreHandle: expected,
		}
		_, err := New(provider)
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
	t.Run("wraps error thrown from protocol state store when setting its store config", func(t *testing.T) {
		expected := errors.New("test")
		provider := testProvider(t)
		provider.ProtocolStateStoreProvider = &mockstore.MockStoreProvider{
			ErrSetStoreConfig: expected,
		}
		_, err := New(provider)
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
}

func TestService_Initialize(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		prov := testProvider(t)
		svc := Service{}

		err := svc.Initialize(prov)
		require.NoError(t, err)

		// second init is no-op
		err = svc.Initialize(prov)
		require.NoError(t, err)
	})

	t.Run("failure, not given a valid provider", func(t *testing.T) {
		svc := Service{}

		err := svc.Initialize("not a provider")
		require.Error(t, err)
		require.Contains(t, err.Error(), "expected provider of type")
	})
}

func TestName(t *testing.T) {
	s, err := New(testProvider(t))
	require.NoError(t, err)
	require.Equal(t, s.Name(), Name)
}

func TestAccept(t *testing.T) {
	t.Run("accepts out-of-band/2.0 invitation messages", func(t *testing.T) {
		s, err := New(testProvider(t))
		require.NoError(t, err)
		require.True(t, s.Accept("https://didcomm.org/out-of-band/2.0/invitation"))
	})
	t.Run("rejects unsupported messages", func(t *testing.T) {
		s, err := New(testProvider(t))
		require.NoError(t, err)
		require.False(t, s.Accept("unsupported"))
	})
}

func TestHandleOutbound(t *testing.T) {
	t.Run("out-of-band Outbound not supported", func(t *testing.T) {
		s := newAutoService(t, testProvider(t))
		_, err := s.HandleOutbound(nil, "", "")
		require.EqualError(t, err, "oob/2.0 not implemented")
	})
}

func TestHandleInbound(t *testing.T) {
	t.Run("accepts out-of-band invitation messages", func(t *testing.T) {
		s := newAutoService(t, testProvider(t))
		_, err := s.HandleInbound(service.NewDIDCommMsgMap(newInvitation()), service.EmptyDIDCommContext())
		require.NoError(t, err)
	})
	t.Run("nil out-of-band invitation messages", func(t *testing.T) {
		s := newAutoService(t, testProvider(t))
		_, err := s.HandleInbound(nil, service.EmptyDIDCommContext())
		require.EqualError(t, err, "oob/2.0 cannot handle nil inbound message")
	})
	t.Run("rejects unsupported message types", func(t *testing.T) {
		s, err := New(testProvider(t))
		require.NoError(t, err)
		req := newInvitation()
		req.Type = "invalid"
		_, err = s.HandleInbound(service.NewDIDCommMsgMap(req), service.EmptyDIDCommContext())
		require.Error(t, err)
	})
}

func TestListener(t *testing.T) {
	t.Run("invokes handleReqFunc", func(t *testing.T) {
		invoked := make(chan struct{})
		callbacks := make(chan *callback)
		handleReqFunc := func(*callback) error {
			invoked <- struct{}{}
			return nil
		}
		go listener(callbacks, handleReqFunc)()

		callbacks <- &callback{
			msg: service.NewDIDCommMsgMap(newInvitation()),
		}

		select {
		case <-invoked:
		case <-time.After(1 * time.Second):
			t.Error("timeout")
		}
	})
}

func TestAcceptInvitation(t *testing.T) {
	t.Run("error if invitation has invalid accept values", func(t *testing.T) {
		provider := testProvider(t)
		s := newAutoService(t, provider)
		inv := newInvitation()
		inv.Body.Accept = []string{"INVALID"}
		err := s.AcceptInvitation(inv)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no acceptable media type profile found in invitation")
	})
	t.Run("error if invitation has invalid Type values", func(t *testing.T) {
		provider := testProvider(t)
		s := newAutoService(t, provider)
		inv := newInvitation()
		inv.Type = "invalidType"
		inv.Body.Accept = []string{transport.MediaTypeDIDCommV2Profile}
		err := s.AcceptInvitation(inv)
		require.EqualError(t, err, "oob/2.0 failed to accept invitation : unsupported message type: invalidType")
	})
	t.Run("invitation valid accept values", func(t *testing.T) {
		provider := testProvider(t)
		s := newAutoService(t, provider)
		inv := newInvitation()
		inv.Body.Accept = []string{transport.MediaTypeDIDCommV2Profile}
		err := s.AcceptInvitation(inv)
		require.NoError(t, err)
	})
	t.Run("invitation accept values with a valid presentproof V3 target code", func(t *testing.T) {
		msg := service.NewDIDCommMsgMap(presentproof.PresentationV3{
			Type: presentproof.RequestPresentationMsgTypeV3,
			Attachments: []decorator.AttachmentV2{{
				Data: decorator.AttachmentData{
					Base64: base64.StdEncoding.EncodeToString([]byte(`{}`)),
				},
			}},
		})

		provider := testProvider(t)
		s := newAutoService(t, provider)
		inv := newInvitation()
		inv.Body.Goal = "propose a present-proof V3.0"
		inv.Body.GoalCode = "present-proof/3.0/propose-presentation"
		inv.Body.Accept = []string{transport.MediaTypeDIDCommV2Profile}
		inv.Requests = []*decorator.AttachmentV2{
			{
				ID:          uuid.New().String(),
				Description: "PresentProof V3 propose presentation request",
				FileName:    "presentproofv3.json",
				MediaType:   "application/json",
				LastModTime: time.Time{},
				Data: decorator.AttachmentData{
					JSON: msg,
				},
			},
		}

		err := s.AcceptInvitation(inv)
		require.NoError(t, err)
	})

	t.Run("invitation accept values with a invalid presentproof V3 target code", func(t *testing.T) {
		provider := testProvider(t)
		s := newAutoService(t, provider)
		inv := newInvitation()
		inv.Body.Goal = "propose a present-proof V3.0"
		inv.Body.GoalCode = "present-proof/3.0/propose-presentation"
		inv.Body.Accept = []string{transport.MediaTypeDIDCommV2Profile}
		inv.Requests = []*decorator.AttachmentV2{
			{
				ID:          uuid.New().String(),
				Description: "PresentProof V3 propose presentation request",
				FileName:    "presentproofv3.json",
				MediaType:   "application/json",
				LastModTime: time.Time{},
				Data:        decorator.AttachmentData{}, // empty Data should triggers an error on 'atchmnt.Data.Fetch()'
			},
		}

		err := s.AcceptInvitation(inv)
		require.NoError(t, err)

		inv.Requests = []*decorator.AttachmentV2{
			{
				ID:          uuid.New().String(),
				Description: "PresentProof V3 propose presentation request",
				FileName:    "presentproofv3.json",
				MediaType:   "application/json",
				LastModTime: time.Time{},
				// invalid json triggers an error on 'didCommMsgRequest.UnmarshalJSON(serviceRequest)'
				Data: decorator.AttachmentData{JSON: "invalid{}"},
			},
		}

		err = s.AcceptInvitation(inv)
		require.NoError(t, err)

		ppv3Response := &presentproof.PresentationV3{
			Attachments: []decorator.AttachmentV2{{
				MediaType: "application/ld+json",
				Data: decorator.AttachmentData{
					JSON: &verifiable.Credential{
						ID:      "http://example.edu/credentials/1872",
						Context: []string{verifiable.ContextURI},
						Types:   []string{verifiable.VCType},
						Subject: "did:example:76e12ec712ebc6f1c221ebfeb1f",
						Issued: &util.TimeWrapper{
							Time: time.Now(),
						},
						Issuer: verifiable.Issuer{
							ID: "did:example:76e12ec712ebc6f1c221ebfeb1f",
						},
						CustomFields: map[string]interface{}{
							"first_name": "First name",
							"last_name":  "Last name",
							"info":       "Info",
						},
					},
				},
			}, {
				MediaType: "application/json",
				Data: decorator.AttachmentData{
					JSON: map[string]struct{}{},
				},
			}},
		}

		didCommMsg := service.NewDIDCommMsgMap(ppv3Response)

		inv.Requests = []*decorator.AttachmentV2{
			{
				ID:          uuid.New().String(),
				Description: "PresentProof V3 propose presentation request",
				FileName:    "presentproofv3.json",
				MediaType:   "application/json",
				LastModTime: time.Time{},
				// setting ppv3Response as json triggers an error on 'srvc.HandleInbound(didCommMsgRequest,...)' since
				// present proof protocol was not initialized yet.
				Data: decorator.AttachmentData{JSON: didCommMsg},
			},
		}

		err = s.AcceptInvitation(inv)
		require.NoError(t, err)
	})
}

func testProvider(t *testing.T) *protocol.MockProvider {
	p := &protocol.MockProvider{
		StoreProvider:              mockstore.NewMockStoreProvider(),
		ProtocolStateStoreProvider: mockstore.NewMockStoreProvider(),
		CustomMessenger:            &mocksvc.MockMessenger{},
	}

	ppf, err := presentproof.New(p)
	require.NoError(t, err)

	// auto service for presentproof
	events := make(chan service.DIDCommAction)
	require.NoError(t, ppf.RegisterActionEvent(events))

	go service.AutoExecuteActionEvent(events)

	messagePickupService, err := messagepickup.New(p)
	require.NoError(t, err)

	// auto service for message pickup
	events = make(chan service.DIDCommAction)
	require.NoError(t, messagePickupService.RegisterActionEvent(events))

	go service.AutoExecuteActionEvent(events)

	return &protocol.MockProvider{
		StoreProvider:              mockstore.NewMockStoreProvider(),
		ProtocolStateStoreProvider: mockstore.NewMockStoreProvider(),
		MsgTypeServicesTargets: []dispatcher.MessageTypeTarget{
			{
				Target:  "present-proof/2.0/propose-presentation",
				MsgType: "https://didcomm.org/present-proof/2.0/propose-presentation",
			},
			{
				Target:  "present-proof/2.0/request-presentation",
				MsgType: "https://didcomm.org/present-proof/2.0/request-presentation",
			},
			{
				Target:  "present-proof/2.0/presentation",
				MsgType: "https://didcomm.org/present-proof/2.0/presentation",
			},
			{
				Target:  "present-proof/2.0/ack",
				MsgType: "https://didcomm.org/present-proof/2.0/ack",
			},
			{
				Target:  "present-proof/3.0/propose-presentation",
				MsgType: "https://didcomm.org/present-proof/3.0/propose-presentation",
			},
			{
				Target:  "present-proof/3.0/request-presentation",
				MsgType: "https://didcomm.org/present-proof/3.0/request-presentation",
			},
			{
				Target:  "present-proof/3.0/presentation",
				MsgType: "https://didcomm.org/present-proof/3.0/presentation",
			},
			{
				Target:  "present-proof/3.0/ack",
				MsgType: "https://didcomm.org/present-proof/3.0/ack",
			},
			{
				Target:  "messagepickup/1.0/status",
				MsgType: "https://didcomm.org/messagepickup/1.0/status",
			},
			{
				Target:  "messagepickup/1.0/status-request",
				MsgType: "https://didcomm.org/messagepickup/1.0/status-request",
			},
		},
		AllProtocolServices: []dispatcher.ProtocolService{
			ppf,
			messagePickupService,
		},
	}
}

func newInvitation() *Invitation {
	return &Invitation{
		ID:    uuid.New().String(),
		Type:  InvitationMsgType,
		Label: "test",
		Body: &InvitationBody{
			Goal:     "test",
			GoalCode: "test",
			Accept:   []string{transport.MediaTypeDIDCommV2Profile},
		},
		Requests: []*decorator.AttachmentV2{
			{
				ID:          uuid.New().String(),
				Description: "test",
				FileName:    "dont_open_this.exe",
				Data: decorator.AttachmentData{
					JSON: map[string]interface{}{
						"@id":   "123",
						"@type": "test-type",
					},
				},
			},
		},
	}
}

func newAutoService(t *testing.T, provider *protocol.MockProvider) *Service {
	s, err := New(provider)
	require.NoError(t, err)

	events := make(chan service.DIDCommAction)
	require.NoError(t, s.RegisterActionEvent(events))

	go service.AutoExecuteActionEvent(events)

	return s
}
