/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
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
	followup, err := (&noOp{}).Execute(dispatcher.DIDCommMsg{}, context{})
	require.Error(t, err)
	require.Nil(t, followup)
}

// null.Execute() is a no-op
func TestNullState_Execute(t *testing.T) {
	followup, err := (&null{}).Execute(dispatcher.DIDCommMsg{}, context{})
	require.NoError(t, err)
	require.IsType(t, &noOp{}, followup)
}

func TestInvitedState_Execute(t *testing.T) {
	t.Run("rejects msgs other than invitations", func(t *testing.T) {
		others := []string{ConnectionRequest, ConnectionResponse, ConnectionAck}
		for _, o := range others {
			_, err := (&invited{}).Execute(dispatcher.DIDCommMsg{Type: o}, context{})
			require.Error(t, err)
		}
	})
	t.Run("rejects outbound invitations", func(t *testing.T) {
		_, err := (&invited{}).Execute(dispatcher.DIDCommMsg{Type: ConnectionInvite, Outbound: true}, context{})
		require.Error(t, err)
	})
	t.Run("followup to 'requested' on inbound invitations", func(t *testing.T) {
		followup, err := (&invited{}).Execute(dispatcher.DIDCommMsg{Type: ConnectionInvite, Outbound: false}, context{})
		require.NoError(t, err)
		require.Equal(t, (&requested{}).Name(), followup.Name())
	})
}

func TestRequestedState_Execute(t *testing.T) {
	prov := mockProvider{}
	ctx:= context{outboundDispatcher:prov.OutboundDispatcher(), didWallet:prov.DIDWallet()}
	newDidDoc, err := ctx.didWallet.CreateDID()
	require.NoError(t, err)
	t.Run("rejects msgs other than invitations or requests", func(t *testing.T) {
		others := []string{ConnectionResponse, ConnectionAck}
		for _, o := range others {
			_, err := (&requested{}).Execute(dispatcher.DIDCommMsg{Type: o}, context{})
			require.Error(t, err)
		}
	})
	t.Run("rejects outbound invitations", func(t *testing.T) {
		_, err := (&requested{}).Execute(dispatcher.DIDCommMsg{Type: ConnectionInvite, Outbound: true}, context{})
		require.Error(t, err)
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
		_, err := (&requested{}).Execute(dispatcher.DIDCommMsg{Type: ConnectionInvite, Payload: invitationPayloadBytes, Outbound: false}, ctx)
		require.NoError(t, err)
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
	dest := &dispatcher.Destination{RecipientKeys:[]string{"test", "test2"}, ServiceEndpoint:"xyz",}
	require.NoError(t, err)
	//OutboundDestination needs to be present
	t.Run("no followup for outbound requests", func(t *testing.T) {
		followup, err := (&requested{}).Execute(dispatcher.DIDCommMsg{Type: ConnectionRequest, Payload: requestPayloadBytes, Outbound: true, OutboundDestination:dest},  ctx)
		require.NoError(t, err)
		require.IsType(t, &noOp{}, followup)
	})
	t.Run("followup to 'responded' on inbound requests", func(t *testing.T) {
		followup, err := (&requested{}).Execute(dispatcher.DIDCommMsg{Type: ConnectionRequest, Outbound: false}, context{})
		require.NoError(t, err)
		require.Equal(t, (&responded{}).Name(), followup.Name())
	})
	t.Run("followup to 'responded' on inbound requests", func(t *testing.T) {
		followup, err := (&requested{}).Execute(dispatcher.DIDCommMsg{Type: ConnectionRequest,Payload: nil, Outbound: true}, context{})
		require.Error(t, err)
		require.Nil(t,followup)
	})
	t.Run("inbound request error", func(t *testing.T) {
		followup, err := (&requested{}).Execute(dispatcher.DIDCommMsg{Type: ConnectionInvite, Payload: nil, Outbound: false}, context{})
		require.Error(t, err)
		require.Nil(t,followup )
	})
}

func TestRespondedState_Execute(t *testing.T) {
	prov := mockProvider{}
	ctx:= context{outboundDispatcher:prov.OutboundDispatcher(), didWallet:prov.DIDWallet()}
	newDidDoc, err := ctx.didWallet.CreateDID()
	require.NoError(t, err)

	dest := &dispatcher.Destination{RecipientKeys:[]string{"test", "test2"}, ServiceEndpoint:"xyz",}
	t.Run("rejects msgs other than requests and responses", func(t *testing.T) {
		others := []string{ConnectionInvite, ConnectionAck}
		for _, o := range others {
			_, err := (&responded{}).Execute(dispatcher.DIDCommMsg{Type: o},context{})
			require.Error(t, err)
		}
	})
	t.Run("rejects outbound requests", func(t *testing.T) {
		_, err := (&responded{}).Execute(dispatcher.DIDCommMsg{Type: ConnectionRequest, Outbound: true}, context{})
		require.Error(t, err)
	})
	//Prepare did-exchange inbound request
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
		followup, err := (&responded{}).Execute(dispatcher.DIDCommMsg{Type: ConnectionRequest, Outbound: false, Payload:requestPayloadBytes}, ctx)
		require.NoError(t, err)
		require.IsType(t, &noOp{}, followup)
	})
	t.Run("followup to 'completed' on inbound responses", func(t *testing.T) {
		followup, err := (&responded{}).Execute(dispatcher.DIDCommMsg{Type: ConnectionResponse, Outbound: false}, ctx)
		require.NoError(t, err)
		require.Equal(t, (&completed{}).Name(), followup.Name())
	})
	//Prepare did-exchange outbound response
	connection := &Connection{
		DID:newDidDoc.ID,
		DIDDoc:newDidDoc,
	}
	connectionSignature, err  := prepareConnectionSignature(connection)
	require.NoError(t, err)

	response := &Response{
		Type:  ConnectionRequest,
		ID:    randomString(),
		ConnectionSignature: connectionSignature,
	}
	// Bob sends an exchange request to Alice
	responsePayloadBytes, err := json.Marshal(response)
	require.NoError(t, err)
	//OutboundDestination needs to be present
	t.Run("no followup for outbound responses", func(t *testing.T) {
		followup, err := (&responded{}).Execute(dispatcher.DIDCommMsg{Type: ConnectionResponse, Outbound: true, Payload: responsePayloadBytes, OutboundDestination:dest}, ctx)
		require.NoError(t, err)
		require.IsType(t, &noOp{}, followup)
	})

	t.Run("no followup for outbound responses error", func(t *testing.T) {
		followup, err := (&responded{}).Execute(dispatcher.DIDCommMsg{Type: ConnectionResponse, Payload: nil, Outbound: true}, context{})
		require.Error(t, err)
		require.Nil(t,followup )
	})
	t.Run("inbound request error", func(t *testing.T) {
		followup, err := (&responded{}).Execute(dispatcher.DIDCommMsg{Type: ConnectionRequest, Payload: nil, Outbound: false}, context{})
		require.Error(t, err)
		require.Nil(t,followup )
	})
}

// completed is an end state
func TestCompletedState_Execute(t *testing.T) {
	t.Run("rejects msgs other than responses and acks", func(t *testing.T) {
		others := []string{ConnectionInvite, ConnectionRequest}
		for _, o := range others {
			_, err := (&completed{}).Execute(dispatcher.DIDCommMsg{Type: o}, context{})
			require.Error(t, err)
		}
	})
	t.Run("rejects outbound responses", func(t *testing.T) {
		_, err := (&completed{}).Execute(dispatcher.DIDCommMsg{Type: ConnectionResponse, Outbound: true}, context{})
		require.Error(t, err)
	})
	t.Run("no followup for inbound responses", func(t *testing.T) {
		followup, err := (&completed{}).Execute(dispatcher.DIDCommMsg{Type: ConnectionResponse, Outbound: false}, context{})
		require.NoError(t, err)
		require.IsType(t, &noOp{}, followup)
	})
	t.Run("no followup for inbound acks", func(t *testing.T) {
		followup, err := (&completed{}).Execute(dispatcher.DIDCommMsg{Type: ConnectionAck, Outbound: false}, context{})
		require.NoError(t, err)
		require.IsType(t, &noOp{}, followup)
	})
	t.Run("no followup for outbound acks", func(t *testing.T) {
		followup, err := (&completed{}).Execute(dispatcher.DIDCommMsg{Type: ConnectionAck, Outbound: true}, context{})
		require.NoError(t, err)
		require.IsType(t, &noOp{}, followup)
	})
}

func TestCreateAndSendRequest(t *testing.T) {
	prov := mockProvider{}
	ctx:= context{outboundDispatcher:prov.OutboundDispatcher(), didWallet:prov.DIDWallet()}
	newDidDoc, err := ctx.didWallet.CreateDID()
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

	outboundDestination := &dispatcher.Destination{RecipientKeys:[]string{"test", "test2"}, ServiceEndpoint:"xyz",}
	t.Run("no followup to inbound invitations", func(t *testing.T) {
		requestPayloadBytes, err := json.Marshal(request)
		require.NoError(t, err)
		req, dest, err := ctx.createOutboundRequest(dispatcher.DIDCommMsg{Type: ConnectionRequest, Payload: requestPayloadBytes, Outbound: false, OutboundDestination:outboundDestination})
		require.NotNil(t, req)
		require.NotNil(t, dest)
		require.NoError(t, err)
		err = ctx.sendOutbound(req, dest)
		require.NoError(t, err)
	})

	t.Run("inbound invitations payload error", func(t *testing.T) {
		req, dest, err := ctx.createOutboundRequest(dispatcher.DIDCommMsg{Type: ConnectionRequest, Payload: nil, Outbound: false, OutboundDestination:outboundDestination})
		require.Nil(t, req)
		require.Nil(t, dest)
		require.Error(t, err)
	})

	t.Run("inbound invitations destination cannot be empty", func(t *testing.T) {
		req, dest, err := ctx.createOutboundRequest(dispatcher.DIDCommMsg{Type: ConnectionRequest, Payload: nil, Outbound: false})
		require.Nil(t, req)
		require.Nil(t, dest)
		require.Error(t, err)
	})


	t.Run("no followup for outbound responses", func(t *testing.T) {
		err := ctx.sendExchangeRequest(request,outboundDestination)
		require.NoError(t, err)
	})
}

func TestCreateAndSendResponse(t *testing.T) {
	prov := mockProvider{}
	ctx:= context{outboundDispatcher:prov.OutboundDispatcher(), didWallet:prov.DIDWallet()}
	newDidDoc, err := ctx.didWallet.CreateDID()
	require.NoError(t, err)

	connection := &Connection{
		DID:newDidDoc.ID,
		DIDDoc:newDidDoc,
	}
	connectionSignature, err  := prepareConnectionSignature(connection)
	require.NoError(t, err)

	response := &Response{
		Type:  ConnectionRequest,
		ID:    randomString(),
		ConnectionSignature: connectionSignature,
	}
	// Bob sends an exchange request to Alice
	responsePayloadBytes, err := json.Marshal(response)
	require.NoError(t, err)

	t.Run("no followup for outbound responses", func(t *testing.T) {
		resp, dest, err := ctx.createOutboundResponse(dispatcher.DIDCommMsg{Type: ConnectionResponse, Payload: responsePayloadBytes, Outbound: true})
		require.Error(t, err)
		require.Nil(t, resp)
		require.Nil(t, dest)
		require.Equal(t, err.Error(), "OutboundDestination cannot be empty for outbound Response")
	})
	dest := &dispatcher.Destination{RecipientKeys:[]string{"test", "test2"}, ServiceEndpoint:"xyz",}
	t.Run("no followup for outbound responses", func(t *testing.T) {
		resp, dest, err := ctx.createOutboundResponse(dispatcher.DIDCommMsg{Type: ConnectionResponse, Payload: responsePayloadBytes, Outbound: true,OutboundDestination:dest})
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NotNil(t, dest)
	})
	t.Run("no followup for outbound responses error", func(t *testing.T) {
		resp, dest, err := ctx.createOutboundResponse(dispatcher.DIDCommMsg{Type: ConnectionResponse, Payload: nil, Outbound: true,OutboundDestination:dest})
		require.Error(t, err)
		require.Nil(t, resp)
		require.Nil(t, dest)
	})

	t.Run("no followup for outbound responses", func(t *testing.T) {
		err := ctx.sendExchangeResponse(response, dest)
		require.NoError(t, err)
	})

}

func TestPrepareConnectionSignature(t *testing.T){
	t.Run("prepare connection signature", func(t *testing.T) {
		prov := mockProvider{}
		ctx:= context{outboundDispatcher:prov.OutboundDispatcher(), didWallet:prov.DIDWallet()}
		newDidDoc, err := ctx.didWallet.CreateDID()
		connection := &Connection{
			DID:newDidDoc.ID,
			DIDDoc:newDidDoc,
		}
		connectionSignature, err  := prepareConnectionSignature(connection)
		require.NoError(t, err)
		require.NotNil(t, connectionSignature)
		require.Equal(t, connectionSignature.Type, "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/signature/1.0/ed25519Sha512_single")
	})
}


func TestPrepareDestination(t *testing.T){
		prov := mockProvider{}
		ctx := context{outboundDispatcher: prov.OutboundDispatcher(), didWallet: prov.DIDWallet()}
		newDidDoc, err := ctx.didWallet.CreateDID()
		require.NoError(t, err)
		dest := prepareDestination(newDidDoc)
		require.NotNil(t, dest)
		require.Equal(t, dest.ServiceEndpoint, "https://localhost:8090")
		//2 Public keys inside the didDoc
		require.Len(t, dest.RecipientKeys, 2)
}

func TestNewRequestFromInvitation(t *testing.T){
		prov := mockProvider{}
		ctx := context{outboundDispatcher: prov.OutboundDispatcher(), didWallet: prov.DIDWallet()}
		invitation := &Invitation{
			Type:            ConnectionInvite,
			ID:              randomString(),
			Label:           "Bob",
			DID:             "did:example:bob",
			RecipientKeys:   []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
			ServiceEndpoint: "https://localhost:8090",
			RoutingKeys:     []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
		}
		req, dest, err := ctx.newRequestFromInvitation(invitation)
		require.NotNil(t, req)
		require.NotNil(t, dest)
		require.NoError(t, err)
}

func TestNewResponseFromRequest(t *testing.T){
	prov := mockProvider{}
	ctx:= context{outboundDispatcher:prov.OutboundDispatcher(), didWallet:prov.DIDWallet()}
	newDidDoc, err := ctx.didWallet.CreateDID()
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
	resp, dest, err := ctx.newResponseFromRequest(request )
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, dest)
}
