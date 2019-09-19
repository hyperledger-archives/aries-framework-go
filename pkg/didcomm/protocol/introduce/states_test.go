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
	start := &start{}
	require.Equal(t, stateNameStart, start.Name())
	t.Run("must not transition to any state", func(t *testing.T) {
		for _, s := range allState {
			require.False(t, start.CanTransitionTo(s))
		}
	})
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
	arranging := &arranging{}
	require.Equal(t, stateNameArranging, arranging.Name())
	t.Run("must not transition to any state", func(t *testing.T) {
		for _, s := range allState {
			require.False(t, arranging.CanTransitionTo(s))
		}
	})
}

func TestArrangingState_Execute(t *testing.T) {
	followup, err := (&arranging{}).Execute(dispatcher.DIDCommMsg{})
	require.Error(t, err)
	require.Nil(t, followup)
}

// delivering state can transition to ...
func TestDeliveringState(t *testing.T) {
	delivering := &delivering{}
	require.Equal(t, stateNameDelivering, delivering.Name())
	t.Run("must not transition to any state", func(t *testing.T) {
		for _, s := range allState {
			require.False(t, delivering.CanTransitionTo(s))
		}
	})
}

func TestDeliveringState_Execute(t *testing.T) {
	followup, err := (&delivering{}).Execute(dispatcher.DIDCommMsg{})
	require.Error(t, err)
	require.Nil(t, followup)
}

// confirming state can transition to ...
func TestConfirmingState(t *testing.T) {
	confirming := &confirming{}
	require.Equal(t, stateNameConfirming, confirming.Name())
	t.Run("must not transition to any state", func(t *testing.T) {
		for _, s := range allState {
			require.False(t, confirming.CanTransitionTo(s))
		}
	})
}

func TestConfirmingState_Execute(t *testing.T) {
	followup, err := (&confirming{}).Execute(dispatcher.DIDCommMsg{})
	require.Error(t, err)
	require.Nil(t, followup)
}

// abandoning state can transition to ...
func TestAbandoningState(t *testing.T) {
	abandoning := &abandoning{}
	require.Equal(t, stateNameAbandoning, abandoning.Name())
	t.Run("must not transition to any state", func(t *testing.T) {
		for _, s := range allState {
			require.False(t, abandoning.CanTransitionTo(s))
		}
	})
}

func TestAbandoningState_Execute(t *testing.T) {
	followup, err := (&abandoning{}).Execute(dispatcher.DIDCommMsg{})
	require.Error(t, err)
	require.Nil(t, followup)
}

// deciding state can transition to ...
func TestDecidingState(t *testing.T) {
	deciding := &deciding{}
	require.Equal(t, stateNameDeciding, deciding.Name())
	t.Run("must not transition to any state", func(t *testing.T) {
		for _, s := range allState {
			require.False(t, deciding.CanTransitionTo(s))
		}
	})
}

func TestDecidingState_Execute(t *testing.T) {
	followup, err := (&deciding{}).Execute(dispatcher.DIDCommMsg{})
	require.Error(t, err)
	require.Nil(t, followup)
}

// waiting state can transition to ...
func TestWaitingState(t *testing.T) {
	waiting := &waiting{}
	require.Equal(t, stateNameWaiting, waiting.Name())
	t.Run("must not transition to any state", func(t *testing.T) {
		for _, s := range allState {
			require.False(t, waiting.CanTransitionTo(s))
		}
	})
}

func TestWaitingState_Execute(t *testing.T) {
	followup, err := (&waiting{}).Execute(dispatcher.DIDCommMsg{})
	require.Error(t, err)
	require.Nil(t, followup)
}
