/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
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
		actual, err := stateFromMsgType(connectionInvite)
		require.NoError(t, err)
		require.Equal(t, expected.Name(), actual.Name())
	})
	t.Run("requested", func(t *testing.T) {
		expected := &requested{}
		actual, err := stateFromMsgType(connectionRequest)
		require.NoError(t, err)
		require.Equal(t, expected.Name(), actual.Name())
	})
	t.Run("responded", func(t *testing.T) {
		expected := &responded{}
		actual, err := stateFromMsgType(connectionResponse)
		require.NoError(t, err)
		require.Equal(t, expected.Name(), actual.Name())
	})
	t.Run("completed", func(t *testing.T) {
		expected := &completed{}
		actual, err := stateFromMsgType(connectionAck)
		require.NoError(t, err)
		require.Equal(t, expected.Name(), actual.Name())
	})
}

func TestStateFromName(t *testing.T) {
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

}

// noOp.Execute() returns nil, error
func TestNoOpState_Execute(t *testing.T) {
	followup, err := (&noOp{}).Execute(dispatcher.DIDCommMsg{})
	require.Error(t, err)
	require.Nil(t, followup)
}

// null.Execute() is a no-op
func TestNullState_Execute(t *testing.T) {
	followup, err := (&null{}).Execute(dispatcher.DIDCommMsg{})
	require.NoError(t, err)
	require.IsType(t, &noOp{}, followup)
}

func TestInvitedState_Execute(t *testing.T) {
	t.Run("rejects msgs other than invitations", func(t *testing.T) {
		others := []string{connectionRequest, connectionResponse, connectionAck}
		for _, o := range others {
			_, err := (&invited{}).Execute(dispatcher.DIDCommMsg{Type: o})
			require.Error(t, err)
		}
	})
	t.Run("rejects outbound invitations", func(t *testing.T) {
		_, err := (&invited{}).Execute(dispatcher.DIDCommMsg{Type: connectionInvite, Outbound: true})
		require.Error(t, err)
	})
	t.Run("followup to 'requested' on inbound invitations", func(t *testing.T) {
		followup, err := (&invited{}).Execute(dispatcher.DIDCommMsg{Type: connectionInvite, Outbound: false})
		require.NoError(t, err)
		require.Equal(t, (&requested{}).Name(), followup.Name())
	})
}

func TestRequestedState_Execute(t *testing.T) {
	t.Run("rejects msgs other than invitations or requests", func(t *testing.T) {
		others := []string{connectionResponse, connectionAck}
		for _, o := range others {
			_, err := (&requested{}).Execute(dispatcher.DIDCommMsg{Type: o})
			require.Error(t, err)
		}
	})
	t.Run("rejects outbound invitations", func(t *testing.T) {
		_, err := (&requested{}).Execute(dispatcher.DIDCommMsg{Type: connectionInvite, Outbound: true})
		require.Error(t, err)
	})
	t.Run("no followup to inbound invitations", func(t *testing.T) {
		followup, err := (&requested{}).Execute(dispatcher.DIDCommMsg{Type: connectionInvite, Outbound: false})
		require.NoError(t, err)
		require.IsType(t, &noOp{}, followup)
	})
	t.Run("no followup to outbound requests", func(t *testing.T) {
		followup, err := (&requested{}).Execute(dispatcher.DIDCommMsg{Type: connectionRequest, Outbound: true})
		require.NoError(t, err)
		require.IsType(t, &noOp{}, followup)
	})
	t.Run("followup to 'responded' on inbound requests", func(t *testing.T) {
		followup, err := (&requested{}).Execute(dispatcher.DIDCommMsg{Type: connectionRequest, Outbound: false})
		require.NoError(t, err)
		require.Equal(t, (&responded{}).Name(), followup.Name())
	})
}

func TestRespondedState_Execute(t *testing.T) {
	t.Run("rejects msgs other than requests and responses", func(t *testing.T) {
		others := []string{connectionInvite, connectionAck}
		for _, o := range others {
			_, err := (&responded{}).Execute(dispatcher.DIDCommMsg{Type: o})
			require.Error(t, err)
		}
	})
	t.Run("rejects outbound requests", func(t *testing.T) {
		_, err := (&responded{}).Execute(dispatcher.DIDCommMsg{Type: connectionRequest, Outbound: true})
		require.Error(t, err)
	})
	t.Run("no followup for inbound requests", func(t *testing.T) {
		followup, err := (&responded{}).Execute(dispatcher.DIDCommMsg{Type: connectionRequest, Outbound: false})
		require.NoError(t, err)
		require.IsType(t, &noOp{}, followup)
	})
	t.Run("followup to 'completed' on inbound responses", func(t *testing.T) {
		followup, err := (&responded{}).Execute(dispatcher.DIDCommMsg{Type: connectionResponse, Outbound: false})
		require.NoError(t, err)
		require.Equal(t, (&completed{}).Name(), followup.Name())
	})
	t.Run("no followup for outbound responses", func(t *testing.T) {
		followup, err := (&responded{}).Execute(dispatcher.DIDCommMsg{Type: connectionResponse, Outbound: true})
		require.NoError(t, err)
		require.IsType(t, &noOp{}, followup)
	})
}

// completed is an end state
func TestCompletedState_Execute(t *testing.T) {
	t.Run("rejects msgs other than responses and acks", func(t *testing.T) {
		others := []string{connectionInvite, connectionRequest}
		for _, o := range others {
			_, err := (&completed{}).Execute(dispatcher.DIDCommMsg{Type: o})
			require.Error(t, err)
		}
	})
	t.Run("rejects outbound responses", func(t *testing.T) {
		_, err := (&completed{}).Execute(dispatcher.DIDCommMsg{Type: connectionResponse, Outbound: true})
		require.Error(t, err)
	})
	t.Run("no followup for inbound responses", func(t *testing.T) {
		followup, err := (&completed{}).Execute(dispatcher.DIDCommMsg{Type: connectionResponse, Outbound: false})
		require.NoError(t, err)
		require.IsType(t, &noOp{}, followup)
	})
	t.Run("no followup for inbound acks", func(t *testing.T) {
		followup, err := (&completed{}).Execute(dispatcher.DIDCommMsg{Type: connectionAck, Outbound: false})
		require.NoError(t, err)
		require.IsType(t, &noOp{}, followup)
	})
	t.Run("no followup for outbound acks", func(t *testing.T) {
		followup, err := (&completed{}).Execute(dispatcher.DIDCommMsg{Type: connectionAck, Outbound: true})
		require.NoError(t, err)
		require.IsType(t, &noOp{}, followup)
	})
}
