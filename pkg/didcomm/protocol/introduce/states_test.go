/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
)

func notTransition(t *testing.T, st state) {
	var allState = [...]state{
		&noOp{}, &start{}, &done{},
		&arranging{}, &delivering{},
		&confirming{}, &abandoning{},
		&deciding{}, &waiting{},
	}
	for _, s := range allState {
		require.False(t, st.CanTransitionTo(s))
	}
}

func TestNoopState(t *testing.T) {
	noop := &noOp{}
	require.Equal(t, stateNameNoop, noop.Name())
	notTransition(t, noop)
}

func TestNoOpState_ExecuteInbound(t *testing.T) {
	followup, err := (&noOp{}).ExecuteInbound(&service.DIDCommMsg{})
	require.Error(t, err)
	require.Nil(t, followup)
}

func TestNoOpState_ExecuteOutbound(t *testing.T) {
	followup, err := (&noOp{}).ExecuteOutbound(&service.DIDCommMsg{}, &service.Destination{})
	require.Error(t, err)
	require.Nil(t, followup)
}

// start state can transition to ...
func TestStartState(t *testing.T) {
	st := &start{}
	require.Equal(t, stateNameStart, st.Name())

	require.True(t, st.CanTransitionTo(&arranging{}))
	require.True(t, st.CanTransitionTo(&deciding{}))
	require.True(t, st.CanTransitionTo(&delivering{}))

	require.False(t, st.CanTransitionTo(&noOp{}))
	require.False(t, st.CanTransitionTo(&start{}))
	require.False(t, st.CanTransitionTo(&done{}))
	require.False(t, st.CanTransitionTo(&confirming{}))
	require.False(t, st.CanTransitionTo(&abandoning{}))
	require.False(t, st.CanTransitionTo(&waiting{}))
}

func TestStartState_ExecuteInbound(t *testing.T) {
	followup, err := (&start{}).ExecuteInbound(&service.DIDCommMsg{})
	require.Error(t, err)
	require.Nil(t, followup)
}

func TestStartState_ExecuteOutbound(t *testing.T) {
	followup, err := (&start{}).ExecuteOutbound(&service.DIDCommMsg{}, &service.Destination{})
	require.Error(t, err)
	require.Nil(t, followup)
}

// done state can transition to ...
func TestDoneState(t *testing.T) {
	done := &done{}
	require.Equal(t, stateNameDone, done.Name())
	notTransition(t, done)
}

func TestDoneState_ExecuteInbound(t *testing.T) {
	followup, err := (&done{}).ExecuteInbound(&service.DIDCommMsg{})
	require.Error(t, err)
	require.Nil(t, followup)
}

func TestDoneState_ExecuteOutbound(t *testing.T) {
	followup, err := (&done{}).ExecuteOutbound(&service.DIDCommMsg{}, &service.Destination{})
	require.Error(t, err)
	require.Nil(t, followup)
}

// arranging state can transition to ...
func TestArrangingState(t *testing.T) {
	st := &arranging{}
	require.Equal(t, stateNameArranging, st.Name())

	require.True(t, st.CanTransitionTo(&arranging{}))
	require.True(t, st.CanTransitionTo(&abandoning{}))
	require.True(t, st.CanTransitionTo(&done{}))

	require.False(t, st.CanTransitionTo(&noOp{}))
	require.False(t, st.CanTransitionTo(&start{}))
	require.False(t, st.CanTransitionTo(&delivering{}))
	require.False(t, st.CanTransitionTo(&confirming{}))
	require.False(t, st.CanTransitionTo(&deciding{}))
	require.False(t, st.CanTransitionTo(&waiting{}))
}

func TestArrangingState_ExecuteInbound(t *testing.T) {
	followup, err := (&arranging{}).ExecuteInbound(&service.DIDCommMsg{})
	require.Error(t, err)
	require.Nil(t, followup)
}

func TestArrangingState_ExecuteOutbound(t *testing.T) {
	followup, err := (&arranging{}).ExecuteOutbound(&service.DIDCommMsg{}, &service.Destination{})
	require.Error(t, err)
	require.Nil(t, followup)
}

// delivering state can transition to ...
func TestDeliveringState(t *testing.T) {
	st := &delivering{}
	require.Equal(t, stateNameDelivering, st.Name())

	require.True(t, st.CanTransitionTo(&confirming{}))
	require.True(t, st.CanTransitionTo(&abandoning{}))
	require.True(t, st.CanTransitionTo(&done{}))

	require.False(t, st.CanTransitionTo(&noOp{}))
	require.False(t, st.CanTransitionTo(&start{}))
	require.False(t, st.CanTransitionTo(&delivering{}))
	require.False(t, st.CanTransitionTo(&arranging{}))
	require.False(t, st.CanTransitionTo(&deciding{}))
	require.False(t, st.CanTransitionTo(&waiting{}))
}

func TestDeliveringState_ExecuteInbound(t *testing.T) {
	followup, err := (&delivering{}).ExecuteInbound(&service.DIDCommMsg{})
	require.Error(t, err)
	require.Nil(t, followup)
}

func TestDeliveringState_ExecuteOutbound(t *testing.T) {
	followup, err := (&delivering{}).ExecuteOutbound(&service.DIDCommMsg{}, &service.Destination{})
	require.Error(t, err)
	require.Nil(t, followup)
}

// confirming state can transition to ...
func TestConfirmingState(t *testing.T) {
	st := &confirming{}
	require.Equal(t, stateNameConfirming, st.Name())

	require.True(t, st.CanTransitionTo(&abandoning{}))
	require.True(t, st.CanTransitionTo(&done{}))

	require.False(t, st.CanTransitionTo(&noOp{}))
	require.False(t, st.CanTransitionTo(&start{}))
	require.False(t, st.CanTransitionTo(&delivering{}))
	require.False(t, st.CanTransitionTo(&arranging{}))
	require.False(t, st.CanTransitionTo(&confirming{}))
	require.False(t, st.CanTransitionTo(&deciding{}))
	require.False(t, st.CanTransitionTo(&waiting{}))
}

func TestConfirmingState_ExecuteInbound(t *testing.T) {
	followup, err := (&confirming{}).ExecuteInbound(&service.DIDCommMsg{})
	require.Error(t, err)
	require.Nil(t, followup)
}

func TestConfirmingState_ExecuteOutbound(t *testing.T) {
	followup, err := (&confirming{}).ExecuteOutbound(&service.DIDCommMsg{}, &service.Destination{})
	require.Error(t, err)
	require.Nil(t, followup)
}

// abandoning state can transition to ...
func TestAbandoningState(t *testing.T) {
	st := &abandoning{}
	require.Equal(t, stateNameAbandoning, st.Name())

	require.True(t, st.CanTransitionTo(&done{}))

	require.False(t, st.CanTransitionTo(&noOp{}))
	require.False(t, st.CanTransitionTo(&start{}))
	require.False(t, st.CanTransitionTo(&delivering{}))
	require.False(t, st.CanTransitionTo(&arranging{}))
	require.False(t, st.CanTransitionTo(&confirming{}))
	require.False(t, st.CanTransitionTo(&deciding{}))
	require.False(t, st.CanTransitionTo(&abandoning{}))
	require.False(t, st.CanTransitionTo(&waiting{}))
}

func TestAbandoningState_ExecuteInbound(t *testing.T) {
	followup, err := (&abandoning{}).ExecuteInbound(&service.DIDCommMsg{})
	require.Error(t, err)
	require.Nil(t, followup)
}

func TestAbandoningState_ExecuteOutbound(t *testing.T) {
	followup, err := (&abandoning{}).ExecuteOutbound(&service.DIDCommMsg{}, &service.Destination{})
	require.Error(t, err)
	require.Nil(t, followup)
}

// deciding state can transition to ...
func TestDecidingState(t *testing.T) {
	st := &deciding{}
	require.Equal(t, stateNameDeciding, st.Name())

	require.True(t, st.CanTransitionTo(&waiting{}))
	require.True(t, st.CanTransitionTo(&done{}))

	require.False(t, st.CanTransitionTo(&noOp{}))
	require.False(t, st.CanTransitionTo(&start{}))
	require.False(t, st.CanTransitionTo(&delivering{}))
	require.False(t, st.CanTransitionTo(&arranging{}))
	require.False(t, st.CanTransitionTo(&confirming{}))
	require.False(t, st.CanTransitionTo(&deciding{}))
	require.False(t, st.CanTransitionTo(&abandoning{}))
}

func TestDecidingState_ExecuteInbound(t *testing.T) {
	followup, err := (&deciding{}).ExecuteInbound(&service.DIDCommMsg{})
	require.Error(t, err)
	require.Nil(t, followup)
}

func TestDecidingState_ExecuteOutbound(t *testing.T) {
	followup, err := (&deciding{}).ExecuteOutbound(&service.DIDCommMsg{}, &service.Destination{})
	require.Error(t, err)
	require.Nil(t, followup)
}

// waiting state can transition to ...
func TestWaitingState(t *testing.T) {
	st := &waiting{}
	require.Equal(t, stateNameWaiting, st.Name())

	require.True(t, st.CanTransitionTo(&done{}))

	require.False(t, st.CanTransitionTo(&noOp{}))
	require.False(t, st.CanTransitionTo(&start{}))
	require.False(t, st.CanTransitionTo(&delivering{}))
	require.False(t, st.CanTransitionTo(&arranging{}))
	require.False(t, st.CanTransitionTo(&confirming{}))
	require.False(t, st.CanTransitionTo(&deciding{}))
	require.False(t, st.CanTransitionTo(&abandoning{}))
	require.False(t, st.CanTransitionTo(&waiting{}))
}

func TestWaitingState_ExecuteInbound(t *testing.T) {
	followup, err := (&waiting{}).ExecuteInbound(&service.DIDCommMsg{})
	require.Error(t, err)
	require.Nil(t, followup)
}

func TestWaitingState_ExecuteOutbound(t *testing.T) {
	followup, err := (&waiting{}).ExecuteOutbound(&service.DIDCommMsg{}, &service.Destination{})
	require.Error(t, err)
	require.Nil(t, followup)
}
