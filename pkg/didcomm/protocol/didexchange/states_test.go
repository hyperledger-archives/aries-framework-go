/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	mockdid "github.com/hyperledger/aries-framework-go/pkg/internal/mock/common/did"
	mockdispatcher "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol"
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

func TestStateFromMsgType(t *testing.T) {
	t.Run("invited", func(t *testing.T) {
		expected := &invited{}
		actual, err := stateFromMsgType(ConnectionInvite)
		require.NoError(t, err)
		require.Equal(t, expected.Name(), actual.Name())
	})
	t.Run("requested", func(t *testing.T) {
		expected := &requested{}
		actual, err := stateFromMsgType(ConnectionRequest)
		require.NoError(t, err)
		require.Equal(t, expected.Name(), actual.Name())
	})
	t.Run("responded", func(t *testing.T) {
		expected := &responded{}
		actual, err := stateFromMsgType(ConnectionResponse)
		require.NoError(t, err)
		require.Equal(t, expected.Name(), actual.Name())
	})
	t.Run("completed", func(t *testing.T) {
		expected := &completed{}
		actual, err := stateFromMsgType(ConnectionAck)
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
	followup, _, err := (&noOp{}).Execute(&service.DIDCommMsg{}, "", context{})
	require.Error(t, err)
	require.Nil(t, followup)
}

// null.Execute() is a no-op
func TestNullState_Execute(t *testing.T) {
	followup, _, err := (&null{}).Execute(&service.DIDCommMsg{}, "", context{})
	require.NoError(t, err)
	require.IsType(t, &noOp{}, followup)
}

func TestInvitedState_Execute(t *testing.T) {
	t.Run("rejects msgs other than invitations", func(t *testing.T) {
		others := []string{ConnectionRequest, ConnectionResponse, ConnectionAck}
		for _, o := range others {
			_, _, err := (&invited{}).Execute(&service.DIDCommMsg{Type: o}, "", context{})
			require.Error(t, err)
		}
	})
	t.Run("rejects outbound invitations", func(t *testing.T) {
		_, _, err := (&invited{}).Execute(&service.DIDCommMsg{Type: ConnectionInvite, Outbound: true}, "", context{})
		require.Error(t, err)
	})
	t.Run("followup to 'requested' on inbound invitations", func(t *testing.T) {
		followup, _, err := (&invited{}).Execute(
			&service.DIDCommMsg{Type: ConnectionInvite, Outbound: false}, "", context{})
		require.NoError(t, err)
		require.Equal(t, (&requested{}).Name(), followup.Name())
	})
}

func TestRequestedState_Execute(t *testing.T) {
	prov := protocol.MockProvider{}
	ctx := context{outboundDispatcher: prov.OutboundDispatcher(), didCreator: &mockdid.MockDIDCreator{Doc: getMockDID()}}
	newDidDoc, err := ctx.didCreator.CreateDID()
	require.NoError(t, err)
	t.Run("rejects msgs other than invitations or requests", func(t *testing.T) {
		others := []string{ConnectionResponse, ConnectionAck}
		for _, o := range others {
			_, _, e := (&requested{}).Execute(&service.DIDCommMsg{Type: o}, "", context{})
			require.Error(t, e)
		}
	})
	t.Run("rejects outbound invitations", func(t *testing.T) {
		_, _, e := (&requested{}).Execute(&service.DIDCommMsg{Type: ConnectionInvite, Outbound: true}, "", context{})
		require.Error(t, e)
	})
	// Alice receives an invitation from Bob
	invitationPayloadBytes, err := json.Marshal(
		&Invitation{
			Type:            ConnectionInvite,
			ID:              randomString(),
			Label:           "Bob",
			DID:             "did:example:bob",
			RecipientKeys:   []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
			ServiceEndpoint: "https://localhost:8090",
			RoutingKeys:     []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
		},
	)
	require.NoError(t, err)
	t.Run("no followup to inbound invitations", func(t *testing.T) {
		msg := service.DIDCommMsg{Type: ConnectionInvite, Payload: invitationPayloadBytes, Outbound: false}
		thid, er := threadID(&msg)
		require.NoError(t, er)
		_, _, e := (&requested{}).Execute(
			&service.DIDCommMsg{Type: ConnectionInvite, Payload: invitationPayloadBytes, Outbound: false}, thid, ctx)
		require.NoError(t, e)
	})
	// Bob sends an exchange request to Alice
	requestPayloadBytes, err := json.Marshal(
		&Request{
			Type:  ConnectionRequest,
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
	// OutboundDestination needs to be present
	t.Run("no followup for outbound requests", func(t *testing.T) {
		followup, _, err := (&requested{}).
			Execute(&service.DIDCommMsg{
				Type: ConnectionRequest, Payload: requestPayloadBytes, Outbound: true, OutboundDestination: dest}, "", ctx)
		require.NoError(t, err)
		require.IsType(t, &noOp{}, followup)
	})
	t.Run("err in sendind outbound requests", func(t *testing.T) {
		ctx2 := context{outboundDispatcher: prov.OutboundDispatcher(),
			didCreator: &mockdid.MockDIDCreator{Doc: getMockDIDPublicKey()}}
		newDidDoc, err := ctx2.didCreator.CreateDID()
		require.NoError(t, err)
		requestPayloadBytes, err := json.Marshal(
			&Request{
				Type:  ConnectionRequest,
				ID:    randomString(),
				Label: "Bob",
				Connection: &Connection{
					DID:    newDidDoc.ID,
					DIDDoc: newDidDoc,
				},
			},
		)
		require.NoError(t, err)
		followup, _, err := (&requested{}).
			Execute(&service.DIDCommMsg{
				Type: ConnectionRequest, Payload: requestPayloadBytes, Outbound: true, OutboundDestination: dest}, "", ctx2)
		require.Error(t, err)
		require.Nil(t, followup)
	})
	t.Run("followup to 'responded' on inbound requests", func(t *testing.T) {
		followup, _, err := (&requested{}).
			Execute(&service.DIDCommMsg{Type: ConnectionRequest, Outbound: false}, "", context{})
		require.NoError(t, err)
		require.Equal(t, (&responded{}).Name(), followup.Name())
	})
	t.Run("followup to 'responded' on inbound requests", func(t *testing.T) {
		followup, _, err := (&requested{}).
			Execute(&service.DIDCommMsg{Type: ConnectionRequest, Payload: nil, Outbound: true}, "", context{})
		require.Error(t, err)
		require.Nil(t, followup)
	})
	t.Run("inbound request error", func(t *testing.T) {
		followup, _, err := (&requested{}).
			Execute(&service.DIDCommMsg{Type: ConnectionInvite, Payload: nil, Outbound: false}, "", context{})
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
			didCreator: &mockdid.MockDIDCreator{Doc: getMockDID()}}
		followup, action, err := (&requested{}).
			Execute(&service.DIDCommMsg{Type: ConnectionInvite, Payload: invitationPayloadBytes, Outbound: false}, "", ctx2)
		require.NoError(t, err)
		require.NotNil(t, followup)
		require.Error(t, action())
	})
	t.Run("handle inbound invitation public key error", func(t *testing.T) {
		ctx2 := context{outboundDispatcher: prov.OutboundDispatcher(),
			didCreator: &mockdid.MockDIDCreator{Doc: getMockDIDPublicKey()}}
		followup, _, err := (&requested{}).
			Execute(&service.DIDCommMsg{Type: ConnectionInvite, Payload: invitationPayloadBytes, Outbound: false}, "", ctx2)
		require.Error(t, err)
		require.Nil(t, followup)
	})
}

func TestRespondedState_Execute(t *testing.T) {
	prov := protocol.MockProvider{}
	ctx := context{outboundDispatcher: prov.OutboundDispatcher(), didCreator: &mockdid.MockDIDCreator{Doc: getMockDID()}}
	newDidDoc, err := ctx.didCreator.CreateDID()
	require.NoError(t, err)

	outboundDestination := &service.Destination{RecipientKeys: []string{"test", "test2"}, ServiceEndpoint: "xyz"}
	t.Run("rejects msgs other than requests and responses", func(t *testing.T) {
		others := []string{ConnectionInvite, ConnectionAck}
		for _, o := range others {
			_, _, e := (&responded{}).Execute(&service.DIDCommMsg{Type: o}, "", context{})
			require.Error(t, e)
		}
	})
	t.Run("rejects outbound requests", func(t *testing.T) {
		_, _, e := (&responded{}).Execute(&service.DIDCommMsg{Type: ConnectionRequest, Outbound: true}, "", context{})
		require.Error(t, e)
	})
	// Prepare did-exchange inbound request
	requestPayloadBytes, err := json.Marshal(
		&Request{
			Type:  ConnectionRequest,
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
		followup, _, e := (&responded{}).
			Execute(&service.DIDCommMsg{Type: ConnectionRequest, Outbound: false, Payload: requestPayloadBytes}, "", ctx)
		require.NoError(t, e)
		require.IsType(t, &noOp{}, followup)
	})
	t.Run("followup to 'completed' on inbound responses", func(t *testing.T) {
		followup, _, e := (&responded{}).Execute(&service.DIDCommMsg{Type: ConnectionResponse, Outbound: false}, "", ctx)
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
		Type:                ConnectionRequest,
		ID:                  randomString(),
		ConnectionSignature: connectionSignature,
	}
	// Bob sends an exchange request to Alice
	responsePayloadBytes, err := json.Marshal(response)
	require.NoError(t, err)
	// OutboundDestination needs to be present
	t.Run("no followup for outbound responses", func(t *testing.T) {
		m := service.DIDCommMsg{Type: ConnectionResponse,
			Outbound: true, Payload: responsePayloadBytes, OutboundDestination: outboundDestination}
		followup, _, e := (&responded{}).Execute(&m, "", ctx)
		require.NoError(t, e)
		require.IsType(t, &noOp{}, followup)
	})

	t.Run("error for outbound responses", func(t *testing.T) {
		ctx2 := context{outboundDispatcher: prov.OutboundDispatcher(),
			didCreator: &mockdid.MockDIDCreator{Doc: getMockDIDPublicKey()}}
		newDidDoc, err = ctx2.didCreator.CreateDID()
		require.NoError(t, err)
		connection := &Connection{
			DID:    newDidDoc.ID,
			DIDDoc: newDidDoc,
		}
		connectionSignature, err = prepareConnectionSignature(connection)
		require.NoError(t, err)

		response := &Response{
			Type:                ConnectionRequest,
			ID:                  randomString(),
			ConnectionSignature: connectionSignature,
		}
		// Bob sends an exchange request to Alice
		responsePayloadBytes, err = json.Marshal(response)
		require.NoError(t, err)
		m := service.DIDCommMsg{Type: ConnectionResponse,
			Outbound: true, Payload: responsePayloadBytes, OutboundDestination: outboundDestination}
		followup, _, e := (&responded{}).Execute(&m, "", ctx2)
		require.Error(t, e)
		require.Nil(t, followup)
	})

	t.Run("no followup for outbound responses error", func(t *testing.T) {
		followup, _, e := (&responded{}).
			Execute(&service.DIDCommMsg{Type: ConnectionResponse, Payload: nil, Outbound: true}, "", context{})
		require.Error(t, e)
		require.Nil(t, followup)
	})
	t.Run("inbound request error", func(t *testing.T) {
		followup, _, e := (&responded{}).
			Execute(&service.DIDCommMsg{Type: ConnectionRequest, Payload: nil, Outbound: false}, "", context{})
		require.Error(t, e)
		require.Nil(t, followup)
	})
	t.Run("handle inbound request  error", func(t *testing.T) {
		ctx2 := context{outboundDispatcher: &mockdispatcher.MockOutbound{SendErr: fmt.Errorf("error")},
			didCreator: &mockdid.MockDIDCreator{Doc: getMockDID()}}
		followup, action, e := (&responded{}).
			Execute(&service.DIDCommMsg{Type: ConnectionRequest, Payload: requestPayloadBytes,
				Outbound: false, OutboundDestination: outboundDestination}, "", ctx2)
		require.NoError(t, e)
		require.NotNil(t, followup)
		require.Error(t, action())
	})
	t.Run("outbound responses unmarshall connection error ", func(t *testing.T) {
		require.NoError(t, err)
		response := &Response{
			Type:                ConnectionRequest,
			ID:                  randomString(),
			ConnectionSignature: &ConnectionSignature{},
		}
		responsePayloadBytes, err := json.Marshal(response)
		require.NoError(t, err)
		followup, _, err := (&responded{}).Execute(&service.DIDCommMsg{Type: ConnectionResponse, Outbound: true,
			Payload: responsePayloadBytes, OutboundDestination: outboundDestination}, "", ctx)
		require.Error(t, err)
		require.Nil(t, followup)
	})
	t.Run("handle inbound request public key error", func(t *testing.T) {
		ctx2 := context{outboundDispatcher: prov.OutboundDispatcher(),
			didCreator: &mockdid.MockDIDCreator{Doc: getMockDIDPublicKey()}}
		followup, _, err := (&responded{}).
			Execute(&service.DIDCommMsg{Type: ConnectionRequest, Payload: requestPayloadBytes, Outbound: false}, "", ctx2)
		require.Error(t, err)
		require.Nil(t, followup)
	})
}

// completed is an end state
func TestCompletedState_Execute(t *testing.T) {
	prov := protocol.MockProvider{}
	ctx := context{outboundDispatcher: prov.OutboundDispatcher(), didCreator: &mockdid.MockDIDCreator{Doc: getMockDID()}}
	newDidDoc, err := ctx.didCreator.CreateDID()
	require.NoError(t, err)
	outboundDestination := &service.Destination{RecipientKeys: []string{"test", "test2"}, ServiceEndpoint: "xyz"}
	t.Run("rejects msgs other than responses and acks", func(t *testing.T) {
		others := []string{ConnectionInvite, ConnectionRequest}
		for _, o := range others {
			_, _, err = (&completed{}).Execute(&service.DIDCommMsg{Type: o}, "", context{})
			require.Error(t, err)
		}
	})
	ackPayloadBytes, err := json.Marshal(&model.Ack{
		Type:   ConnectionAck,
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
		Type: ConnectionRequest,
		ID:   randomString(),
		Thread: &decorator.Thread{
			ID: uuid.New().String(),
		},
		ConnectionSignature: connectionSignature,
	}
	responsePayloadBytes, err := json.Marshal(response)

	t.Run("rejects outbound responses", func(t *testing.T) {
		_, _, err = (&completed{}).Execute(&service.DIDCommMsg{Type: ConnectionResponse, Outbound: true}, "", context{})
		require.Error(t, err)
	})
	t.Run("no followup for inbound responses", func(t *testing.T) {
		followup, _, e := (&completed{}).Execute(&service.DIDCommMsg{Type: ConnectionResponse, Outbound: false,
			Payload: responsePayloadBytes, OutboundDestination: outboundDestination}, "", ctx)
		require.NoError(t, e)
		require.IsType(t, &noOp{}, followup)
	})
	t.Run("inbound responses unmarshall error ", func(t *testing.T) {
		response := &Response{
			Type: ConnectionRequest,
			ID:   randomString(),
			Thread: &decorator.Thread{
				ID: "responseID",
			},
			ConnectionSignature: &ConnectionSignature{},
		}
		respPayloadBytes, err := json.Marshal(response)
		require.NoError(t, err)
		followup, _, err := (&completed{}).Execute(&service.DIDCommMsg{Type: ConnectionResponse, Outbound: false,
			Payload: respPayloadBytes, OutboundDestination: outboundDestination}, "", ctx)
		require.Error(t, err)
		require.Nil(t, followup)
	})
	t.Run("no followup for inbound responses error", func(t *testing.T) {
		followup, _, err := (&completed{}).Execute(&service.DIDCommMsg{Type: ConnectionResponse, Outbound: false},
			"", context{})
		require.Error(t, err)
		require.Nil(t, followup)
	})
	t.Run("no followup for inbound acks", func(t *testing.T) {
		followup, _, err := (&completed{}).Execute(&service.DIDCommMsg{Type: ConnectionAck, Outbound: false}, "", context{})
		require.NoError(t, err)
		require.IsType(t, &noOp{}, followup)
	})

	t.Run("no followup for outbound acks error", func(t *testing.T) {
		followup, _, err := (&completed{}).Execute(&service.DIDCommMsg{Type: ConnectionAck, Outbound: true,
			Payload: ackPayloadBytes, OutboundDestination: outboundDestination}, "", ctx)
		require.NoError(t, err)
		require.IsType(t, &noOp{}, followup)
	})
	t.Run("no followup for outbound acks outbound destination error", func(t *testing.T) {
		followup, _, err := (&completed{}).Execute(&service.DIDCommMsg{Type: ConnectionAck, Outbound: true,
			Payload: ackPayloadBytes}, "", ctx)
		require.Error(t, err)
		require.Nil(t, followup)
	})
	t.Run("no followup for outbound acks error", func(t *testing.T) {
		followup, _, err := (&completed{}).Execute(&service.DIDCommMsg{Type: ConnectionAck, Outbound: true,
			OutboundDestination: outboundDestination}, "", ctx)
		require.Error(t, err)
		require.Nil(t, followup)
	})
	t.Run("handle inbound response  error", func(t *testing.T) {
		ctx2 := context{outboundDispatcher: &mockdispatcher.MockOutbound{SendErr: fmt.Errorf("error")},
			didCreator: &mockdid.MockDIDCreator{Doc: getMockDID()}}
		followup, action, err := (&completed{}).
			Execute(&service.DIDCommMsg{Type: ConnectionResponse, Payload: responsePayloadBytes,
				Outbound: false, OutboundDestination: outboundDestination}, "", ctx2)
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
			Type:            ConnectionInvite,
			ID:              randomString(),
			Label:           "Bob",
			DID:             "did:example:bob",
			RecipientKeys:   []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
			ServiceEndpoint: "https://localhost:8090",
			RoutingKeys:     []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
		}
		invitationBytes, err := json.Marshal(invitation)
		require.NoError(t, err)
		thid, err := threadID(&service.DIDCommMsg{Type: ConnectionInvite, Payload: invitationBytes, Outbound: false})
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
		thid, err := threadID(&service.DIDCommMsg{Type: ConnectionInvite, Payload: invitationBytes, Outbound: false})
		require.NoError(t, err)
		_, err = ctx.handleInboundInvitation(invitation, thid)
		require.Error(t, err)
		require.Equal(t, "create DID error", err.Error())
	})
}

func TestNewResponseFromRequest(t *testing.T) {
	t.Run("successful new response from request", func(t *testing.T) {
		prov := protocol.MockProvider{}
		ctx := context{outboundDispatcher: prov.OutboundDispatcher(), didCreator: &mockdid.MockDIDCreator{Doc: getMockDID()}}
		newDidDoc, err := ctx.didCreator.CreateDID()
		require.NoError(t, err)
		request := &Request{
			Type:  ConnectionRequest,
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
		require.Nil(t, pubkey)
	})
}
