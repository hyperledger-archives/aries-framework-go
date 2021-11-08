/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofbandv2

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
)

const (
	myDID    = "did:example:mine"
	theirDID = "did:example:theirs"
)

func TestNew(t *testing.T) {
	t.Run("returns the service", func(t *testing.T) {
		s, err := New(testProvider())
		require.NoError(t, err)
		require.NotNil(t, s)
	})
	t.Run("wraps error thrown from protocol state store when it cannot be opened", func(t *testing.T) {
		expected := errors.New("test")
		provider := testProvider()
		provider.ProtocolStateStoreProvider = &mockstore.MockStoreProvider{
			ErrOpenStoreHandle: expected,
		}
		_, err := New(provider)
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
	t.Run("wraps error thrown from protocol state store when setting its store config", func(t *testing.T) {
		expected := errors.New("test")
		provider := testProvider()
		provider.ProtocolStateStoreProvider = &mockstore.MockStoreProvider{
			ErrSetStoreConfig: expected,
		}
		_, err := New(provider)
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
}

func TestName(t *testing.T) {
	s, err := New(testProvider())
	require.NoError(t, err)
	require.Equal(t, s.Name(), Name)
}

func TestAccept(t *testing.T) {
	t.Run("accepts out-of-band/2.0 invitation messages", func(t *testing.T) {
		s, err := New(testProvider())
		require.NoError(t, err)
		require.True(t, s.Accept("https://didcomm.org/out-of-band/2.0/invitation"))
	})
	t.Run("rejects unsupported messages", func(t *testing.T) {
		s, err := New(testProvider())
		require.NoError(t, err)
		require.False(t, s.Accept("unsupported"))
	})
}

func TestHandleInbound(t *testing.T) {
	t.Run("accepts out-of-band invitation messages", func(t *testing.T) {
		s := newAutoService(t, testProvider())
		_, err := s.HandleInbound(service.NewDIDCommMsgMap(newInvitation()), service.NewDIDCommContext(myDID, theirDID, nil))
		require.NoError(t, err)
	})
	t.Run("nil out-of-band invitation messages", func(t *testing.T) {
		s := newAutoService(t, testProvider())
		_, err := s.HandleInbound(nil, service.NewDIDCommContext(myDID, theirDID, nil))
		require.EqualError(t, err, "oob/2.0 cannot handle nil inbound message")
	})
	t.Run("rejects unsupported message types", func(t *testing.T) {
		s, err := New(testProvider())
		require.NoError(t, err)
		req := newInvitation()
		req.Type = "invalid"
		_, err = s.HandleInbound(service.NewDIDCommMsgMap(req), service.NewDIDCommContext(myDID, theirDID, nil))
		require.Error(t, err)
	})
	t.Run("fires off an action event", func(t *testing.T) {
		expected := service.NewDIDCommMsgMap(newInvitation())
		s, err := New(testProvider())
		require.NoError(t, err)
		events := make(chan service.DIDCommAction)
		err = s.RegisterActionEvent(events)
		require.NoError(t, err)
		_, err = s.HandleInbound(expected, service.NewDIDCommContext(myDID, theirDID, nil))
		require.NoError(t, err)
		select {
		case e := <-events:
			require.Equal(t, Name, e.ProtocolName)
			require.Equal(t, expected, e.Message)
			require.Nil(t, e.Properties)
		case <-time.After(1 * time.Second):
			t.Error("timeout waiting for action event")
		}
	})
	t.Run("Load context (error)", func(t *testing.T) {
		expected := service.NewDIDCommMsgMap(newInvitation())
		s := &Service{
			transientStore: &mockstore.MockStore{
				Store:  make(map[string]mockstore.DBEntry),
				ErrPut: fmt.Errorf("db error"),
			},
		}
		events := make(chan service.DIDCommAction)
		err := s.RegisterActionEvent(events)
		require.NoError(t, err)
		_, err = s.HandleInbound(expected, service.NewDIDCommContext(myDID, theirDID, nil))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to load current context")
	})
	t.Run("fails if no listeners have been registered for action events", func(t *testing.T) {
		s, err := New(testProvider())
		require.NoError(t, err)
		_, err = s.HandleInbound(service.NewDIDCommMsgMap(newInvitation()), service.NewDIDCommContext(myDID, theirDID, nil))
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
		provider := testProvider()
		s := newAutoService(t, provider)
		inv := newInvitation()
		inv.Body.Accept = []string{"INVALID"}
		err := s.AcceptInvitation(inv, &userOptions{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "no acceptable media type profile found in invitation")
	})
	t.Run("invitation valid accept values", func(t *testing.T) {
		provider := testProvider()
		s := newAutoService(t, provider)
		inv := newInvitation()
		inv.Body.Accept = []string{transport.MediaTypeDIDCommV2Profile}
		err := s.AcceptInvitation(inv, &userOptions{})
		require.NoError(t, err)
	})
}

func testProvider() *protocol.MockProvider {
	return &protocol.MockProvider{
		StoreProvider:              mockstore.NewMockStoreProvider(),
		ProtocolStateStoreProvider: mockstore.NewMockStoreProvider(),
		MsgTypeServicesTargets: []dispatcher.MessageTypeTarget{
			{
				Target:  "introduce",
				MsgType: "https://didcomm.org/introduce/1.0/proposal",
			},
			{
				Target:  "introduce",
				MsgType: "https://didcomm.org/introduce/1.0/request",
			},
			{
				Target:  "introduce",
				MsgType: "https://didcomm.org/introduce/1.0/response",
			},
			{
				Target:  "introduce",
				MsgType: "https://didcomm.org/introduce/1.0/ack",
			},
			{
				Target:  "messagepickup",
				MsgType: "https://didcomm.org/messagepickup/1.0/status",
			},
			{
				Target:  "messagepickup",
				MsgType: "https://didcomm.org/messagepickup/1.0/status-request",
			},
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
