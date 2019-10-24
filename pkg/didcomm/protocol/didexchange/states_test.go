/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	diddoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	mockdid "github.com/hyperledger/aries-framework-go/pkg/internal/mock/common/did"
	mockdispatcher "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol"
	mockdidresolver "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didresolver"
)

func TestNoopState(t *testing.T) {
	noop := &noOp{}
	require.Equal(t, "noop", noop.Name())

	t.Run("must not transition to any state", func(t *testing.T) {
		all := []state{&null{}, &invited{}, &requested{}, &responded{}, &completed{}}
		for _, s := range all {
			require.False(t, noop.CanTransitionTo(s))
		}
	})
}

// null state can transition to invited state or requested state
func TestNullState(t *testing.T) {
	null := &null{}
	require.Equal(t, "null", null.Name())
	require.False(t, null.CanTransitionTo(null))
	require.True(t, null.CanTransitionTo(&invited{}))
	require.True(t, null.CanTransitionTo(&requested{}))
	require.False(t, null.CanTransitionTo(&responded{}))
	require.False(t, null.CanTransitionTo(&completed{}))
}

// invited can only transition to requested state
func TestInvitedState(t *testing.T) {
	invited := &invited{}
	require.Equal(t, "invited", invited.Name())
	require.False(t, invited.CanTransitionTo(&null{}))
	require.False(t, invited.CanTransitionTo(invited))
	require.True(t, invited.CanTransitionTo(&requested{}))
	require.False(t, invited.CanTransitionTo(&responded{}))
	require.False(t, invited.CanTransitionTo(&completed{}))
}

// requested can only transition to responded state
func TestRequestedState(t *testing.T) {
	requested := &requested{}
	require.Equal(t, "requested", requested.Name())
	require.False(t, requested.CanTransitionTo(&null{}))
	require.False(t, requested.CanTransitionTo(&invited{}))
	require.False(t, requested.CanTransitionTo(requested))
	require.True(t, requested.CanTransitionTo(&responded{}))
	require.False(t, requested.CanTransitionTo(&completed{}))
}

// responded can only transition to completed state
func TestRespondedState(t *testing.T) {
	responded := &responded{}
	require.Equal(t, "responded", responded.Name())
	require.False(t, responded.CanTransitionTo(&null{}))
	require.False(t, responded.CanTransitionTo(&invited{}))
	require.False(t, responded.CanTransitionTo(&requested{}))
	require.False(t, responded.CanTransitionTo(responded))
	require.True(t, responded.CanTransitionTo(&completed{}))
}

// completed is an end state
func TestCompletedState(t *testing.T) {
	completed := &completed{}
	require.Equal(t, "completed", completed.Name())
	require.False(t, completed.CanTransitionTo(&null{}))
	require.False(t, completed.CanTransitionTo(&invited{}))
	require.False(t, completed.CanTransitionTo(&requested{}))
	require.False(t, completed.CanTransitionTo(&responded{}))
	require.False(t, completed.CanTransitionTo(completed))
}

func TestAbandonedState(t *testing.T) {
	abandoned := &abandoned{}
	require.Equal(t, stateNameAbandoned, abandoned.Name())
	require.False(t, abandoned.CanTransitionTo(&null{}))
	require.False(t, abandoned.CanTransitionTo(&invited{}))
	require.False(t, abandoned.CanTransitionTo(&requested{}))
	require.False(t, abandoned.CanTransitionTo(&responded{}))
	require.False(t, abandoned.CanTransitionTo(&completed{}))

	_, _, err := abandoned.Execute(&stateMachineMsg{}, "", context{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestStateFromMsgType(t *testing.T) {
	t.Run("invited", func(t *testing.T) {
		expected := &invited{}
		actual, err := stateFromMsgType(InvitationMsgType)
		require.NoError(t, err)
		require.Equal(t, expected.Name(), actual.Name())
	})
	t.Run("requested", func(t *testing.T) {
		expected := &requested{}
		actual, err := stateFromMsgType(RequestMsgType)
		require.NoError(t, err)
		require.Equal(t, expected.Name(), actual.Name())
	})
	t.Run("responded", func(t *testing.T) {
		expected := &responded{}
		actual, err := stateFromMsgType(ResponseMsgType)
		require.NoError(t, err)
		require.Equal(t, expected.Name(), actual.Name())
	})
	t.Run("completed", func(t *testing.T) {
		expected := &completed{}
		actual, err := stateFromMsgType(AckMsgType)
		require.NoError(t, err)
		require.Equal(t, expected.Name(), actual.Name())
	})
	t.Run("invalid", func(t *testing.T) {
		actual, err := stateFromMsgType("invalid")
		require.Nil(t, actual)
		require.Error(t, err)
		require.Equal(t, "unrecognized msgType: invalid", err.Error())
	})
}

func TestStateFromName(t *testing.T) {
	t.Run("noop", func(t *testing.T) {
		expected := &noOp{}
		actual, err := stateFromName(expected.Name())
		require.NoError(t, err)
		require.Equal(t, expected.Name(), actual.Name())
	})
	t.Run("null", func(t *testing.T) {
		expected := &null{}
		actual, err := stateFromName(expected.Name())
		require.NoError(t, err)
		require.Equal(t, expected.Name(), actual.Name())
	})
	t.Run("invited", func(t *testing.T) {
		expected := &invited{}
		actual, err := stateFromName(expected.Name())
		require.NoError(t, err)
		require.Equal(t, expected.Name(), actual.Name())
	})
	t.Run("requested", func(t *testing.T) {
		expected := &requested{}
		actual, err := stateFromName(expected.Name())
		require.NoError(t, err)
		require.Equal(t, expected.Name(), actual.Name())
	})
	t.Run("responded", func(t *testing.T) {
		expected := &responded{}
		actual, err := stateFromName(expected.Name())
		require.NoError(t, err)
		require.Equal(t, expected.Name(), actual.Name())
	})
	t.Run("completed", func(t *testing.T) {
		expected := &completed{}
		actual, err := stateFromName(expected.Name())
		require.NoError(t, err)
		require.Equal(t, expected.Name(), actual.Name())
	})
	t.Run("undefined", func(t *testing.T) {
		actual, err := stateFromName("undefined")
		require.Nil(t, actual)
		require.Error(t, err)
	})
}

// noOp.Execute() returns nil, error
func TestNoOpState_Execute(t *testing.T) {
	followup, _, err := (&noOp{}).Execute(&stateMachineMsg{}, "", context{})
	require.Error(t, err)
	require.Nil(t, followup)
}

// null.Execute() is a no-op
func TestNullState_Execute(t *testing.T) {
	followup, _, err := (&null{}).Execute(&stateMachineMsg{}, "", context{})
	require.NoError(t, err)
	require.IsType(t, &noOp{}, followup)
}

func TestInvitedState_Execute(t *testing.T) {
	t.Run("rejects msgs other than invitations", func(t *testing.T) {
		others := []string{RequestMsgType, ResponseMsgType, AckMsgType}
		for _, o := range others {
			_, _, err := (&invited{}).Execute(&stateMachineMsg{header: &service.Header{Type: o}}, "", context{})
			require.Error(t, err)
		}
	})
	t.Run("rejects outbound invitations", func(t *testing.T) {
		_, _, err := (&invited{}).Execute(&stateMachineMsg{
			header:   &service.Header{Type: InvitationMsgType},
			outbound: true,
		}, "", context{})
		require.Error(t, err)
	})
	t.Run("followup to 'requested' on inbound invitations", func(t *testing.T) {
		followup, _, err := (&invited{}).Execute(
			&stateMachineMsg{header: &service.Header{Type: InvitationMsgType}, outbound: false}, "", context{})
		require.NoError(t, err)
		require.Equal(t, (&requested{}).Name(), followup.Name())
	})
}

func TestRequestedState_Execute(t *testing.T) {
	prov := protocol.MockProvider{}
	ctx := context{outboundDispatcher: prov.OutboundDispatcher(),
		didCreator: &mockdid.MockDIDCreator{Doc: getMockDID()},
		signer:     &mockSigner{}}
	newDidDoc, err := ctx.didCreator.CreateDID()
	require.NoError(t, err)
	t.Run("rejects msgs other than invitations or requests", func(t *testing.T) {
		others := []string{ResponseMsgType, AckMsgType}
		for _, o := range others {
			_, _, e := (&requested{}).Execute(&stateMachineMsg{header: &service.Header{Type: o}}, "", context{})
			require.Error(t, e)
		}
	})
	t.Run("rejects outbound invitations", func(t *testing.T) {
		_, _, e := (&requested{}).Execute(&stateMachineMsg{
			header:   &service.Header{Type: InvitationMsgType},
			outbound: true,
		}, "", context{})
		require.Error(t, e)
	})
	// Alice receives an invitation from Bob
	invitationPayloadBytes, err := json.Marshal(
		&Invitation{
			Type:            InvitationMsgType,
			ID:              randomString(),
			Label:           "Bob",
			RecipientKeys:   []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
			ServiceEndpoint: "https://localhost:8090",
			RoutingKeys:     []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
		},
	)
	require.NoError(t, err)
	t.Run("no followup to inbound invitations", func(t *testing.T) {
		// nolint: govet
		msg, err := service.NewDIDCommMsg(invitationPayloadBytes)
		require.NoError(t, err)
		// nolint: govet
		thid, err := threadID(msg)
		require.NoError(t, err)
		_, _, e := (&requested{}).Execute(&stateMachineMsg{header: msg.Header, payload: msg.Payload}, thid, ctx)
		require.NoError(t, e)
	})
	// Bob sends an exchange request to Alice
	requestPayloadBytes, err := json.Marshal(
		&Request{
			Type:  RequestMsgType,
			ID:    randomString(),
			Label: "Bob",
			Connection: &Connection{
				DID:    newDidDoc.ID,
				DIDDoc: newDidDoc,
			},
		},
	)
	dest := &service.Destination{RecipientKeys: []string{"test", "test2"}, ServiceEndpoint: "xyz"}
	require.NoError(t, err)
	// outboundDestination needs to be present
	t.Run("no followup for outbound requests", func(t *testing.T) {
		followup, _, err := (&requested{}).Execute(&stateMachineMsg{
			header:              &service.Header{Type: RequestMsgType},
			payload:             requestPayloadBytes,
			outbound:            true,
			outboundDestination: dest,
		}, "", ctx)
		require.NoError(t, err)
		require.IsType(t, &noOp{}, followup)
	})
	t.Run("err in sendind outbound requests", func(t *testing.T) {
		ctx2 := context{outboundDispatcher: prov.OutboundDispatcher(),
			didCreator: &mockdid.MockDIDCreator{Doc: getMockDIDPublicKey()},
			signer:     &mockSigner{}}
		newDidDoc, err := ctx2.didCreator.CreateDID()
		require.NoError(t, err)
		requestPayloadBytes, err := json.Marshal(
			&Request{
				Type:  RequestMsgType,
				ID:    randomString(),
				Label: "Bob",
				Connection: &Connection{
					DID:    newDidDoc.ID,
					DIDDoc: newDidDoc,
				},
			},
		)
		require.NoError(t, err)
		followup, _, err := (&requested{}).Execute(&stateMachineMsg{
			header:              &service.Header{Type: RequestMsgType},
			payload:             requestPayloadBytes,
			outbound:            true,
			outboundDestination: dest,
		}, "", ctx2)
		require.Error(t, err)
		require.Nil(t, followup)
	})
	t.Run("followup to 'responded' on inbound requests", func(t *testing.T) {
		followup, _, err := (&requested{}).Execute(&stateMachineMsg{
			header:   &service.Header{Type: RequestMsgType},
			outbound: false,
		}, "", context{})
		require.NoError(t, err)
		require.Equal(t, (&responded{}).Name(), followup.Name())
	})
	t.Run("followup to 'responded' on inbound requests", func(t *testing.T) {
		followup, _, err := (&requested{}).Execute(&stateMachineMsg{
			header:   &service.Header{Type: RequestMsgType},
			payload:  nil,
			outbound: true,
		}, "", context{})
		require.Error(t, err)
		require.Nil(t, followup)
	})
	t.Run("inbound request error", func(t *testing.T) {
		followup, _, err := (&requested{}).Execute(&stateMachineMsg{
			header:   &service.Header{Type: InvitationMsgType},
			payload:  nil,
			outbound: false,
		}, "", context{})
		require.Error(t, err)
		require.Nil(t, followup)
	})
	t.Run("create DID error", func(t *testing.T) {
		ctx2 := context{outboundDispatcher: prov.OutboundDispatcher(),
			didCreator: &mockdid.MockDIDCreator{Failure: fmt.Errorf("create DID error")}}
		didDoc, err := ctx2.didCreator.CreateDID()
		require.Error(t, err)
		require.Nil(t, didDoc)
	})
	t.Run("handle inbound invitation  error", func(t *testing.T) {
		ctx2 := context{outboundDispatcher: &mockdispatcher.MockOutbound{SendErr: fmt.Errorf("error")},
			didCreator: &mockdid.MockDIDCreator{Doc: getMockDID()}, signer: &mockSigner{}}
		followup, action, err := (&requested{}).Execute(&stateMachineMsg{
			header:   &service.Header{Type: InvitationMsgType},
			payload:  invitationPayloadBytes,
			outbound: false,
		}, "", ctx2)
		require.NoError(t, err)
		require.NotNil(t, followup)
		require.Error(t, action())
	})
	t.Run("handle inbound invitation public key error", func(t *testing.T) {
		ctx2 := context{outboundDispatcher: prov.OutboundDispatcher(),
			didCreator: &mockdid.MockDIDCreator{Doc: getMockDIDPublicKey()},
			signer:     &mockSigner{}}
		followup, _, err := (&requested{}).Execute(&stateMachineMsg{
			header:   &service.Header{Type: InvitationMsgType},
			payload:  invitationPayloadBytes,
			outbound: false,
		}, "", ctx2)
		require.Error(t, err)
		require.Nil(t, followup)
	})
}

func TestRespondedState_Execute(t *testing.T) {
	prov := protocol.MockProvider{}
	ctx := context{outboundDispatcher: prov.OutboundDispatcher(),
		didCreator: &mockdid.MockDIDCreator{Doc: getMockDID()},
		signer:     &mockSigner{}}
	newDidDoc, err := ctx.didCreator.CreateDID()
	require.NoError(t, err)

	outboundDestination := &service.Destination{RecipientKeys: []string{"test", "test2"}, ServiceEndpoint: "xyz"}
	t.Run("rejects msgs other than requests and responses", func(t *testing.T) {
		others := []string{InvitationMsgType, AckMsgType}
		for _, o := range others {
			_, _, e := (&responded{}).Execute(&stateMachineMsg{header: &service.Header{Type: o}}, "", context{})
			require.Error(t, e)
		}
	})
	t.Run("rejects outbound requests", func(t *testing.T) {
		_, _, e := (&responded{}).Execute(&stateMachineMsg{
			header:   &service.Header{Type: RequestMsgType},
			outbound: true,
		}, "", context{})
		require.Error(t, e)
	})
	// Prepare did-exchange inbound request
	requestPayloadBytes, err := json.Marshal(
		&Request{
			Type:  RequestMsgType,
			ID:    randomString(),
			Label: "Bob",
			Connection: &Connection{
				DID:    newDidDoc.ID,
				DIDDoc: newDidDoc,
			},
		},
	)
	require.NoError(t, err)
	t.Run("no followup for inbound requests", func(t *testing.T) {
		followup, _, e := (&responded{}).Execute(&stateMachineMsg{
			header:   &service.Header{Type: RequestMsgType},
			outbound: false,
			payload:  requestPayloadBytes,
		}, "", ctx)
		require.NoError(t, e)
		require.IsType(t, &noOp{}, followup)
	})
	t.Run("followup to 'completed' on inbound responses", func(t *testing.T) {
		followup, _, e := (&responded{}).Execute(&stateMachineMsg{
			header:   &service.Header{Type: ResponseMsgType},
			outbound: false,
		}, "", ctx)
		require.NoError(t, e)
		require.Equal(t, (&completed{}).Name(), followup.Name())
	})
	// Prepare did-exchange outbound response
	connection := &Connection{
		DID:    newDidDoc.ID,
		DIDDoc: newDidDoc,
	}
	connectionSignature, err := prepareConnectionSignature(connection)
	require.NoError(t, err)

	response := &Response{
		Type:                RequestMsgType,
		ID:                  randomString(),
		ConnectionSignature: connectionSignature,
	}
	// Bob sends an exchange request to Alice
	responsePayloadBytes, err := json.Marshal(response)
	require.NoError(t, err)
	// outboundDestination needs to be present
	t.Run("no followup for outbound responses", func(t *testing.T) {
		m := stateMachineMsg{header: &service.Header{Type: ResponseMsgType},
			outbound: true, payload: responsePayloadBytes, outboundDestination: outboundDestination}
		followup, _, e := (&responded{}).Execute(&m, "", ctx)
		require.NoError(t, e)
		require.IsType(t, &noOp{}, followup)
	})

	t.Run("error for outbound responses", func(t *testing.T) {
		ctx2 := context{outboundDispatcher: prov.OutboundDispatcher(),
			didCreator: &mockdid.MockDIDCreator{Doc: getMockDIDPublicKey()},
			signer:     &mockSigner{}}
		newDidDoc, err = ctx2.didCreator.CreateDID()
		require.NoError(t, err)
		connection := &Connection{
			DID:    newDidDoc.ID,
			DIDDoc: newDidDoc,
		}
		connectionSignature, err = prepareConnectionSignature(connection)
		require.NoError(t, err)

		response := &Response{
			Type:                RequestMsgType,
			ID:                  randomString(),
			ConnectionSignature: connectionSignature,
		}
		// Bob sends an exchange request to Alice
		responsePayloadBytes, err = json.Marshal(response)
		require.NoError(t, err)
		m := stateMachineMsg{header: &service.Header{Type: ResponseMsgType},
			outbound: true, payload: responsePayloadBytes, outboundDestination: outboundDestination}
		followup, _, e := (&responded{}).Execute(&m, "", ctx2)
		require.Error(t, e)
		require.Nil(t, followup)
	})

	t.Run("no followup for outbound responses error", func(t *testing.T) {
		followup, _, e := (&responded{}).Execute(&stateMachineMsg{
			header:   &service.Header{Type: ResponseMsgType},
			payload:  nil,
			outbound: true,
		}, "", context{})
		require.Error(t, e)
		require.Nil(t, followup)
	})
	t.Run("inbound request error", func(t *testing.T) {
		followup, _, e := (&responded{}).Execute(&stateMachineMsg{
			header:   &service.Header{Type: RequestMsgType},
			payload:  nil,
			outbound: false,
		}, "", context{})
		require.Error(t, e)
		require.Nil(t, followup)
	})
	t.Run("handle inbound request  error", func(t *testing.T) {
		ctx2 := context{outboundDispatcher: &mockdispatcher.MockOutbound{SendErr: fmt.Errorf("error")},
			didCreator: &mockdid.MockDIDCreator{Doc: getMockDID()}, signer: &mockSigner{}}
		followup, action, e := (&responded{}).Execute(&stateMachineMsg{
			header:              &service.Header{Type: RequestMsgType},
			payload:             requestPayloadBytes,
			outbound:            false,
			outboundDestination: outboundDestination,
		}, "", ctx2)
		require.NoError(t, e)
		require.NotNil(t, followup)
		require.Error(t, action())
	})
	t.Run("outbound responses unmarshall connection error ", func(t *testing.T) {
		require.NoError(t, err)
		response := &Response{
			Type:                RequestMsgType,
			ID:                  randomString(),
			ConnectionSignature: &ConnectionSignature{},
		}
		responsePayloadBytes, err := json.Marshal(response)
		require.NoError(t, err)
		followup, _, err := (&responded{}).Execute(&stateMachineMsg{
			header:              &service.Header{Type: ResponseMsgType},
			outbound:            true,
			payload:             responsePayloadBytes,
			outboundDestination: outboundDestination,
		}, "", ctx)
		require.Error(t, err)
		require.Nil(t, followup)
	})
	t.Run("handle inbound request public key error", func(t *testing.T) {
		ctx2 := context{outboundDispatcher: prov.OutboundDispatcher(),
			didCreator: &mockdid.MockDIDCreator{Doc: getMockDIDPublicKey()}, signer: &mockSigner{}}
		followup, _, err := (&responded{}).Execute(&stateMachineMsg{
			header:   &service.Header{Type: RequestMsgType},
			payload:  requestPayloadBytes,
			outbound: false,
		}, "", ctx2)
		require.Error(t, err)
		require.Nil(t, followup)
	})
}

// completed is an end state
func TestCompletedState_Execute(t *testing.T) {
	prov := protocol.MockProvider{}
	ctx := context{outboundDispatcher: prov.OutboundDispatcher(),
		didCreator: &mockdid.MockDIDCreator{Doc: getMockDID()},
		signer:     &mockSigner{}}
	newDidDoc, err := ctx.didCreator.CreateDID()
	require.NoError(t, err)
	outboundDestination := &service.Destination{RecipientKeys: []string{"test", "test2"}, ServiceEndpoint: "xyz"}
	t.Run("rejects msgs other than responses and acks", func(t *testing.T) {
		others := []string{InvitationMsgType, RequestMsgType}
		for _, o := range others {
			_, _, err = (&completed{}).Execute(&stateMachineMsg{header: &service.Header{Type: o}}, "", context{})
			require.Error(t, err)
		}
	})
	ackPayloadBytes, err := json.Marshal(&model.Ack{
		Type:   AckMsgType,
		ID:     randomString(),
		Status: ackStatusOK,
		Thread: &decorator.Thread{
			ID: "responseID",
		},
	},
	)
	require.NoError(t, err)
	connection := &Connection{
		DID:    newDidDoc.ID,
		DIDDoc: newDidDoc,
	}
	connectionSignature, err := prepareConnectionSignature(connection)
	require.NoError(t, err)
	response := &Response{
		Type: RequestMsgType,
		ID:   randomString(),
		Thread: &decorator.Thread{
			ID: uuid.New().String(),
		},
		ConnectionSignature: connectionSignature,
	}
	responsePayloadBytes, err := json.Marshal(response)

	t.Run("rejects outbound responses", func(t *testing.T) {
		_, _, err = (&completed{}).Execute(&stateMachineMsg{
			header:   &service.Header{Type: ResponseMsgType},
			outbound: true,
		}, "", context{})
		require.Error(t, err)
	})
	t.Run("no followup for inbound responses", func(t *testing.T) {
		followup, _, e := (&completed{}).Execute(&stateMachineMsg{
			header:              &service.Header{Type: ResponseMsgType},
			outbound:            false,
			payload:             responsePayloadBytes,
			outboundDestination: outboundDestination,
		}, "", ctx)
		require.NoError(t, e)
		require.IsType(t, &noOp{}, followup)
	})
	t.Run("inbound responses unmarshall error ", func(t *testing.T) {
		response := &Response{
			Type: RequestMsgType,
			ID:   randomString(),
			Thread: &decorator.Thread{
				ID: "responseID",
			},
			ConnectionSignature: &ConnectionSignature{},
		}
		respPayloadBytes, err := json.Marshal(response)
		require.NoError(t, err)
		followup, _, err := (&completed{}).Execute(&stateMachineMsg{
			header:              &service.Header{Type: ResponseMsgType},
			outbound:            false,
			payload:             respPayloadBytes,
			outboundDestination: outboundDestination,
		}, "", ctx)
		require.Error(t, err)
		require.Nil(t, followup)
	})
	t.Run("no followup for inbound responses error", func(t *testing.T) {
		followup, _, err := (&completed{}).Execute(&stateMachineMsg{
			header:   &service.Header{Type: ResponseMsgType},
			outbound: false,
		}, "", context{})
		require.Error(t, err)
		require.Nil(t, followup)
	})
	t.Run("no followup for inbound acks", func(t *testing.T) {
		followup, _, err := (&completed{}).Execute(&stateMachineMsg{
			header:   &service.Header{Type: AckMsgType},
			outbound: false,
		}, "", context{})
		require.NoError(t, err)
		require.IsType(t, &noOp{}, followup)
	})

	t.Run("no followup for outbound acks error", func(t *testing.T) {
		followup, _, err := (&completed{}).Execute(&stateMachineMsg{
			header:              &service.Header{Type: AckMsgType},
			outbound:            true,
			payload:             ackPayloadBytes,
			outboundDestination: outboundDestination,
		}, "", ctx)
		require.NoError(t, err)
		require.IsType(t, &noOp{}, followup)
	})
	t.Run("no followup for outbound acks outbound destination error", func(t *testing.T) {
		followup, _, err := (&completed{}).Execute(&stateMachineMsg{
			header:   &service.Header{Type: AckMsgType},
			outbound: true,
			payload:  ackPayloadBytes,
		}, "", ctx)
		require.Error(t, err)
		require.Nil(t, followup)
	})
	t.Run("no followup for outbound acks error", func(t *testing.T) {
		followup, _, err := (&completed{}).Execute(&stateMachineMsg{
			header:              &service.Header{Type: AckMsgType},
			outbound:            true,
			outboundDestination: outboundDestination,
		}, "", ctx)
		require.Error(t, err)
		require.Nil(t, followup)
	})
	t.Run("handle inbound response  error", func(t *testing.T) {
		ctx2 := context{outboundDispatcher: &mockdispatcher.MockOutbound{SendErr: fmt.Errorf("error")},
			didCreator: &mockdid.MockDIDCreator{Doc: getMockDID()}, signer: &mockSigner{}}
		followup, action, err := (&completed{}).
			Execute(&stateMachineMsg{header: &service.Header{Type: ResponseMsgType}, payload: responsePayloadBytes,
				outbound: false, outboundDestination: outboundDestination}, "", ctx2)
		require.NoError(t, err)
		require.NotNil(t, followup)
		require.Error(t, action())
	})
}
func TestPrepareConnectionSignature(t *testing.T) {
	t.Run("prepare connection signature", func(t *testing.T) {
		prov := protocol.MockProvider{}
		ctx := context{outboundDispatcher: prov.OutboundDispatcher(), didCreator: &mockdid.MockDIDCreator{Doc: getMockDID()}}
		newDidDoc, err := ctx.didCreator.CreateDID()
		require.NoError(t, err)
		connection := &Connection{
			DID:    newDidDoc.ID,
			DIDDoc: newDidDoc,
		}
		connectionSignature, err := prepareConnectionSignature(connection)
		require.NoError(t, err)
		require.NotNil(t, connectionSignature)
		sigData, err := base64.URLEncoding.DecodeString(connectionSignature.SignedData)
		require.NoError(t, err)
		connBytes := sigData[bytes.IndexRune(sigData, '{'):]
		sigDataConnection := &Connection{}
		err = json.Unmarshal(connBytes, sigDataConnection)
		require.NoError(t, err)
		require.Equal(t, connection.DID, sigDataConnection.DID)
	})
}

func TestPrepareDestination(t *testing.T) {
	prov := protocol.MockProvider{}
	ctx := context{outboundDispatcher: prov.OutboundDispatcher(), didCreator: &mockdid.MockDIDCreator{Doc: getMockDID()}}
	newDidDoc, err := ctx.didCreator.CreateDID()
	require.NoError(t, err)
	dest := prepareDestination(newDidDoc)
	require.NotNil(t, dest)
	require.Equal(t, dest.ServiceEndpoint, "https://localhost:8090")
	// 2 Public keys inside the didDoc
	require.Len(t, dest.RecipientKeys, 3)
}

func TestNewRequestFromInvitation(t *testing.T) {
	t.Run("successful new request from invitation", func(t *testing.T) {
		prov := protocol.MockProvider{}
		ctx := context{outboundDispatcher: prov.OutboundDispatcher(), didCreator: &mockdid.MockDIDCreator{Doc: getMockDID()}}
		invitation := &Invitation{
			Type:            InvitationMsgType,
			ID:              randomString(),
			Label:           "Bob",
			RecipientKeys:   []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
			ServiceEndpoint: "https://localhost:8090",
			RoutingKeys:     []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
		}
		invitationBytes, err := json.Marshal(invitation)
		require.NoError(t, err)
		thid, err := threadID(&service.DIDCommMsg{
			Header:  &service.Header{Type: InvitationMsgType},
			Payload: invitationBytes,
		})
		require.NoError(t, err)
		_, err = ctx.handleInboundInvitation(invitation, thid)
		require.NoError(t, err)
	})
	t.Run("unsuccessful new request from invitation ", func(t *testing.T) {
		prov := protocol.MockProvider{}
		ctx := context{outboundDispatcher: prov.OutboundDispatcher(),
			didCreator: &mockdid.MockDIDCreator{Failure: fmt.Errorf("create DID error")}}
		invitation := &Invitation{}
		invitationBytes, err := json.Marshal(invitation)
		require.NoError(t, err)
		thid, err := threadID(&service.DIDCommMsg{
			Header:  &service.Header{Type: InvitationMsgType},
			Payload: invitationBytes,
		})
		require.NoError(t, err)
		_, err = ctx.handleInboundInvitation(invitation, thid)
		require.Error(t, err)
		require.Equal(t, "create DID error", err.Error())
	})
}

func TestNewResponseFromRequest(t *testing.T) {
	t.Run("successful new response from request", func(t *testing.T) {
		prov := protocol.MockProvider{}
		ctx := context{outboundDispatcher: prov.OutboundDispatcher(),
			didCreator: &mockdid.MockDIDCreator{Doc: getMockDID()}, signer: &mockSigner{}}
		newDidDoc, err := ctx.didCreator.CreateDID()
		require.NoError(t, err)
		request := &Request{
			Type:  RequestMsgType,
			ID:    randomString(),
			Label: "Bob",
			Connection: &Connection{
				DID:    newDidDoc.ID,
				DIDDoc: newDidDoc,
			},
		}
		_, err = ctx.handleInboundRequest(request)
		require.NoError(t, err)
	})
	t.Run("unsuccessful new response from request", func(t *testing.T) {
		prov := protocol.MockProvider{}
		ctx := context{outboundDispatcher: prov.OutboundDispatcher(),
			didCreator: &mockdid.MockDIDCreator{Failure: fmt.Errorf("create DID error")}}
		request := &Request{}
		_, err := ctx.handleInboundRequest(request)
		require.Error(t, err)
		require.Equal(t, "create DID error", err.Error())
	})
}

func TestGetPublicKey(t *testing.T) {
	t.Run("successfully getting public key", func(t *testing.T) {
		prov := protocol.MockProvider{}
		ctx := context{outboundDispatcher: prov.OutboundDispatcher(), didCreator: &mockdid.MockDIDCreator{Doc: getMockDID()}}
		newDidDoc, err := ctx.didCreator.CreateDID()
		require.NoError(t, err)
		pubkey, err := getPublicKeys(newDidDoc, supportedPublicKeyType)
		require.NoError(t, err)
		require.NotNil(t, pubkey)
		require.Len(t, pubkey, 1)
	})
	t.Run("failed to get public key", func(t *testing.T) {
		prov := protocol.MockProvider{}
		ctx := context{outboundDispatcher: prov.OutboundDispatcher(), didCreator: &mockdid.MockDIDCreator{Doc: getMockDID()}}
		newDidDoc, err := ctx.didCreator.CreateDID()
		require.NoError(t, err)
		pubkey, err := getPublicKeys(newDidDoc, "invalid key")
		require.Error(t, err)
		require.Contains(t, err.Error(), "public key not supported")
		require.Nil(t, pubkey)
	})
}

func TestGetDestinationFromDID(t *testing.T) {
	t.Run("successfully getting destination from public DID", func(t *testing.T) {
		doc := createDIDDoc()
		ctx := context{didResolver: &mockdidresolver.MockResolver{Doc: doc}}
		destination, err := ctx.getDestinationFromDID(doc.ID)
		require.NoError(t, err)
		require.NotNil(t, destination)
	})
	t.Run("test public key not found", func(t *testing.T) {
		doc := createDIDDoc()
		doc.PublicKey = nil
		ctx := context{didResolver: &mockdidresolver.MockResolver{Doc: doc}}
		destination, err := ctx.getDestinationFromDID(doc.ID)
		require.Error(t, err)
		require.Nil(t, destination)
		require.Contains(t, err.Error(), "public key not supported")
	})
	t.Run("test service not found", func(t *testing.T) {
		doc := createDIDDoc()
		doc.Service = nil
		ctx := context{didResolver: &mockdidresolver.MockResolver{Doc: doc}}
		destination, err := ctx.getDestinationFromDID(doc.ID)
		require.Error(t, err)
		require.Nil(t, destination)
		require.Contains(t, err.Error(), "service not found in DID document")
	})
	t.Run("test did document not found", func(t *testing.T) {
		doc := createDIDDoc()
		ctx := context{didResolver: &mockdidresolver.MockResolver{Err: errors.New("resolver error")}}
		destination, err := ctx.getDestinationFromDID(doc.ID)
		require.Error(t, err)
		require.Nil(t, destination)
		require.Contains(t, err.Error(), "resolver error")
	})
}

type mockSigner struct {
	Err error
}

func (s *mockSigner) SignMessage(message []byte, fromVerKey string) ([]byte, error) {
	return nil, s.Err
}

func createDIDDoc() *diddoc.Doc {
	const didFormat = "did:%s:%s"
	const didPKID = "%s#keys-%d"
	const didServiceID = "%s#endpoint-%d"
	const method = "test"

	pub := generateKeyPair()

	id := fmt.Sprintf(didFormat, method, pub[:16])
	pubKey := diddoc.PublicKey{
		ID:         fmt.Sprintf(didPKID, id, 1),
		Type:       "Ed25519VerificationKey2018",
		Controller: id,
		Value:      []byte(pub),
	}

	services := []diddoc.Service{
		{
			ID:              fmt.Sprintf(didServiceID, id, 1),
			Type:            "did-communication",
			ServiceEndpoint: "http://localhost:58416",
		},
	}

	createdTime := time.Now()

	didDoc := &diddoc.Doc{
		Context:   []string{diddoc.Context},
		ID:        id,
		PublicKey: []diddoc.PublicKey{pubKey},
		Service:   services,
		Created:   &createdTime,
		Updated:   &createdTime,
	}

	return didDoc
}

func generateKeyPair() string {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	return base58.Encode(pubKey[:])
}
