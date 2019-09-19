/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
)

// nolint:gochecknoglobals
var allState = [...]state{
	&noOp{}, &start{}, &done{},
	&arranging{}, &delivering{},
	&confirming{}, &abandoning{},
	&deciding{}, &waiting{},
}

func TestNoopState(t *testing.T) {
	noop := &noOp{}
	require.Equal(t, stateNameNoop, noop.Name())
	t.Run("must not transition to any state", func(t *testing.T) {
		for _, s := range allState {
			require.False(t, noop.CanTransitionTo(s))
		}
	})
}

// noOp.Execute() returns nil, error
func TestNoOpState_Execute(t *testing.T) {
	followup, err := (&noOp{}).Execute(dispatcher.DIDCommMsg{})
	require.Error(t, err)
	require.Nil(t, followup)
}

// start state can transition to ...
func TestStartState(t *testing.T) {
	st := &start{}
	require.Equal(t, stateNameStart, st.Name())

	require.True(t, st.CanTransitionTo(&arranging{}))
	require.True(t, st.CanTransitionTo(&deciding{}))
	require.True(t, st.CanTransitionTo(&done{}))

	require.False(t, st.CanTransitionTo(&noOp{}))
	require.False(t, st.CanTransitionTo(&start{}))
	require.False(t, st.CanTransitionTo(&delivering{}))
	require.False(t, st.CanTransitionTo(&confirming{}))
	require.False(t, st.CanTransitionTo(&abandoning{}))
	require.False(t, st.CanTransitionTo(&waiting{}))
}

func TestStartState_Execute(t *testing.T) {
	followup, err := (&start{}).Execute(dispatcher.DIDCommMsg{})
	require.Error(t, err)
	require.Nil(t, followup)
}

// done state can transition to ...
func TestDoneState(t *testing.T) {
	done := &done{}
	require.Equal(t, stateNameDone, done.Name())
	t.Run("must not transition to any state", func(t *testing.T) {
		for _, s := range allState {
			require.False(t, done.CanTransitionTo(s))
		}
	})
}

func TestDoneState_Execute(t *testing.T) {
	followup, err := (&done{}).Execute(dispatcher.DIDCommMsg{})
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

func TestArrangingState_Execute(t *testing.T) {
	followup, err := (&arranging{}).Execute(dispatcher.DIDCommMsg{})
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

func TestDeliveringState_Execute(t *testing.T) {
	followup, err := (&delivering{}).Execute(dispatcher.DIDCommMsg{})
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

func TestConfirmingState_Execute(t *testing.T) {
	followup, err := (&confirming{}).Execute(dispatcher.DIDCommMsg{})
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

func TestAbandoningState_Execute(t *testing.T) {
	followup, err := (&abandoning{}).Execute(dispatcher.DIDCommMsg{})
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

func TestDecidingState_Execute(t *testing.T) {
	followup, err := (&deciding{}).Execute(dispatcher.DIDCommMsg{})
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

func TestWaitingState_Execute(t *testing.T) {
	followup, err := (&waiting{}).Execute(dispatcher.DIDCommMsg{})
	require.Error(t, err)
	require.Nil(t, followup)
}
