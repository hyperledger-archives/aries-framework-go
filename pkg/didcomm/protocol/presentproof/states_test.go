/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStart_CanTransitionTo(t *testing.T) {
	st := &start{}
	require.Equal(t, stateNameStart, st.Name())
	// common states
	require.False(t, st.CanTransitionTo(&start{}))
	require.False(t, st.CanTransitionTo(&abandoning{}))
	require.False(t, st.CanTransitionTo(&done{}))
	require.False(t, st.CanTransitionTo(&noOp{}))
	// states for Verifier
	require.True(t, st.CanTransitionTo(&requestSent{}))
	require.False(t, st.CanTransitionTo(&presentationReceived{}))
	require.True(t, st.CanTransitionTo(&proposePresentationReceived{}))
	// states for Prover
	require.True(t, st.CanTransitionTo(&requestReceived{}))
	require.False(t, st.CanTransitionTo(&presentationSent{}))
	require.True(t, st.CanTransitionTo(&proposePresentationSent{}))
}

func TestStart_ExecuteInbound(t *testing.T) {
	followup, action, err := (&start{}).ExecuteInbound(&metaData{})
	require.Contains(t, fmt.Sprintf("%v", err), "is not implemented yet")
	require.Nil(t, followup)
	require.Nil(t, action)
}

func TestStart_ExecuteOutbound(t *testing.T) {
	followup, action, err := (&start{}).ExecuteOutbound(&metaData{})
	require.Contains(t, fmt.Sprintf("%v", err), "is not implemented yet")
	require.Nil(t, followup)
	require.Nil(t, action)
}

func TestAbandoning_CanTransitionTo(t *testing.T) {
	st := &abandoning{}
	require.Equal(t, stateNameAbandoning, st.Name())
	// common states
	require.False(t, st.CanTransitionTo(&start{}))
	require.False(t, st.CanTransitionTo(&abandoning{}))
	require.True(t, st.CanTransitionTo(&done{}))
	require.False(t, st.CanTransitionTo(&noOp{}))
	// states for Verifier
	require.False(t, st.CanTransitionTo(&requestSent{}))
	require.False(t, st.CanTransitionTo(&presentationReceived{}))
	require.False(t, st.CanTransitionTo(&proposePresentationReceived{}))
	// states for Prover
	require.False(t, st.CanTransitionTo(&requestReceived{}))
	require.False(t, st.CanTransitionTo(&presentationSent{}))
	require.False(t, st.CanTransitionTo(&proposePresentationSent{}))
}

func TestAbandoning_ExecuteInbound(t *testing.T) {
	followup, action, err := (&abandoning{}).ExecuteInbound(&metaData{})
	require.Contains(t, fmt.Sprintf("%v", err), "is not implemented yet")
	require.Nil(t, followup)
	require.Nil(t, action)
}

func TestAbandoning_ExecuteOutbound(t *testing.T) {
	followup, action, err := (&abandoning{}).ExecuteOutbound(&metaData{})
	require.Contains(t, fmt.Sprintf("%v", err), "is not implemented yet")
	require.Nil(t, followup)
	require.Nil(t, action)
}

func TestDone_CanTransitionTo(t *testing.T) {
	st := &done{}
	require.Equal(t, stateNameDone, st.Name())
	notTransition(t, st)
}

func TestDone_ExecuteInbound(t *testing.T) {
	followup, action, err := (&done{}).ExecuteInbound(&metaData{})
	require.NoError(t, err)
	require.Equal(t, &noOp{}, followup)
	require.NoError(t, action(nil))
}

func TestDone_ExecuteOutbound(t *testing.T) {
	followup, action, err := (&done{}).ExecuteOutbound(&metaData{})
	require.Contains(t, fmt.Sprintf("%v", err), "is not implemented yet")
	require.Nil(t, followup)
	require.Nil(t, action)
}

func TestNoOp_CanTransitionTo(t *testing.T) {
	st := &noOp{}
	require.Equal(t, stateNameNoop, st.Name())
	notTransition(t, st)
}

func TestNoOp_ExecuteInbound(t *testing.T) {
	followup, action, err := (&noOp{}).ExecuteInbound(&metaData{})
	require.Contains(t, fmt.Sprintf("%v", err), "cannot execute no-op")
	require.Nil(t, followup)
	require.Nil(t, action)
}

func TestNoOp_ExecuteOutbound(t *testing.T) {
	followup, action, err := (&noOp{}).ExecuteOutbound(&metaData{})
	require.Contains(t, fmt.Sprintf("%v", err), "cannot execute no-op")
	require.Nil(t, followup)
	require.Nil(t, action)
}

func TestRequestReceived_CanTransitionTo(t *testing.T) {
	st := &requestReceived{}
	require.Equal(t, stateNameRequestReceived, st.Name())
	// common states
	require.False(t, st.CanTransitionTo(&start{}))
	require.True(t, st.CanTransitionTo(&abandoning{}))
	require.False(t, st.CanTransitionTo(&done{}))
	require.False(t, st.CanTransitionTo(&noOp{}))
	// states for Verifier
	require.False(t, st.CanTransitionTo(&requestSent{}))
	require.False(t, st.CanTransitionTo(&presentationReceived{}))
	require.False(t, st.CanTransitionTo(&proposePresentationReceived{}))
	// states for Prover
	require.False(t, st.CanTransitionTo(&requestReceived{}))
	require.True(t, st.CanTransitionTo(&presentationSent{}))
	require.True(t, st.CanTransitionTo(&proposePresentationSent{}))
}

func TestRequestReceived_ExecuteInbound(t *testing.T) {
	followup, action, err := (&requestReceived{}).ExecuteInbound(&metaData{})
	require.Contains(t, fmt.Sprintf("%v", err), "is not implemented yet")
	require.Nil(t, followup)
	require.Nil(t, action)
}

func TestRequestReceived_ExecuteOutbound(t *testing.T) {
	followup, action, err := (&requestReceived{}).ExecuteOutbound(&metaData{})
	require.Contains(t, fmt.Sprintf("%v", err), "is not implemented yet")
	require.Nil(t, followup)
	require.Nil(t, action)
}

func TestRequestSent_CanTransitionTo(t *testing.T) {
	st := &requestSent{}
	require.Equal(t, stateNameRequestSent, st.Name())
	// common states
	require.False(t, st.CanTransitionTo(&start{}))
	require.True(t, st.CanTransitionTo(&abandoning{}))
	require.False(t, st.CanTransitionTo(&done{}))
	require.False(t, st.CanTransitionTo(&noOp{}))
	// states for Verifier
	require.False(t, st.CanTransitionTo(&requestSent{}))
	require.True(t, st.CanTransitionTo(&presentationReceived{}))
	require.True(t, st.CanTransitionTo(&proposePresentationReceived{}))
	// states for Prover
	require.False(t, st.CanTransitionTo(&requestReceived{}))
	require.False(t, st.CanTransitionTo(&presentationSent{}))
	require.False(t, st.CanTransitionTo(&proposePresentationSent{}))
}

func TestRequestSent_ExecuteInbound(t *testing.T) {
	followup, action, err := (&requestSent{}).ExecuteInbound(&metaData{})
	require.Contains(t, fmt.Sprintf("%v", err), "is not implemented yet")
	require.Nil(t, followup)
	require.Nil(t, action)
}

func TestRequestSent_ExecuteOutbound(t *testing.T) {
	followup, action, err := (&requestSent{}).ExecuteOutbound(&metaData{})
	require.Contains(t, fmt.Sprintf("%v", err), "is not implemented yet")
	require.Nil(t, followup)
	require.Nil(t, action)
}

func TestPresentationSent_CanTransitionTo(t *testing.T) {
	st := &presentationSent{}
	require.Equal(t, stateNamePresentationSent, st.Name())
	// common states
	require.False(t, st.CanTransitionTo(&start{}))
	require.True(t, st.CanTransitionTo(&abandoning{}))
	require.True(t, st.CanTransitionTo(&done{}))
	require.False(t, st.CanTransitionTo(&noOp{}))
	// states for Verifier
	require.False(t, st.CanTransitionTo(&requestSent{}))
	require.False(t, st.CanTransitionTo(&presentationReceived{}))
	require.False(t, st.CanTransitionTo(&proposePresentationReceived{}))
	// states for Prover
	require.False(t, st.CanTransitionTo(&requestReceived{}))
	require.False(t, st.CanTransitionTo(&presentationSent{}))
	require.False(t, st.CanTransitionTo(&proposePresentationSent{}))
}

func TestPresentationSent_ExecuteInbound(t *testing.T) {
	followup, action, err := (&presentationSent{}).ExecuteInbound(&metaData{})
	require.Contains(t, fmt.Sprintf("%v", err), "is not implemented yet")
	require.Nil(t, followup)
	require.Nil(t, action)
}

func TestPresentationSent_ExecuteOutbound(t *testing.T) {
	followup, action, err := (&presentationSent{}).ExecuteOutbound(&metaData{})
	require.Contains(t, fmt.Sprintf("%v", err), "is not implemented yet")
	require.Nil(t, followup)
	require.Nil(t, action)
}

func TestPresentationReceived_CanTransitionTo(t *testing.T) {
	st := &presentationReceived{}
	require.Equal(t, stateNamePresentationReceived, st.Name())
	// common states
	require.False(t, st.CanTransitionTo(&start{}))
	require.True(t, st.CanTransitionTo(&abandoning{}))
	require.True(t, st.CanTransitionTo(&done{}))
	require.False(t, st.CanTransitionTo(&noOp{}))
	// states for Verifier
	require.False(t, st.CanTransitionTo(&requestSent{}))
	require.False(t, st.CanTransitionTo(&presentationReceived{}))
	require.False(t, st.CanTransitionTo(&proposePresentationReceived{}))
	// states for Prover
	require.False(t, st.CanTransitionTo(&requestReceived{}))
	require.False(t, st.CanTransitionTo(&presentationSent{}))
	require.False(t, st.CanTransitionTo(&proposePresentationSent{}))
}

func TestPresentationReceived_ExecuteInbound(t *testing.T) {
	followup, action, err := (&presentationReceived{}).ExecuteInbound(&metaData{})
	require.Contains(t, fmt.Sprintf("%v", err), "is not implemented yet")
	require.Nil(t, followup)
	require.Nil(t, action)
}

func TestPresentationReceived_ExecuteOutbound(t *testing.T) {
	followup, action, err := (&presentationReceived{}).ExecuteOutbound(&metaData{})
	require.Contains(t, fmt.Sprintf("%v", err), "is not implemented yet")
	require.Nil(t, followup)
	require.Nil(t, action)
}

func TestProposePresentationSent_CanTransitionTo(t *testing.T) {
	st := &proposePresentationSent{}
	require.Equal(t, stateNameProposePresentationSent, st.Name())
	// common states
	require.False(t, st.CanTransitionTo(&start{}))
	require.True(t, st.CanTransitionTo(&abandoning{}))
	require.False(t, st.CanTransitionTo(&done{}))
	require.False(t, st.CanTransitionTo(&noOp{}))
	// states for Verifier
	require.False(t, st.CanTransitionTo(&requestSent{}))
	require.False(t, st.CanTransitionTo(&presentationReceived{}))
	require.False(t, st.CanTransitionTo(&proposePresentationReceived{}))
	// states for Prover
	require.True(t, st.CanTransitionTo(&requestReceived{}))
	require.False(t, st.CanTransitionTo(&presentationSent{}))
	require.False(t, st.CanTransitionTo(&proposePresentationSent{}))
}

func TestProposePresentationSent_ExecuteInbound(t *testing.T) {
	followup, action, err := (&proposePresentationSent{}).ExecuteInbound(&metaData{})
	require.Contains(t, fmt.Sprintf("%v", err), "is not implemented yet")
	require.Nil(t, followup)
	require.Nil(t, action)
}

func TestProposePresentationSent_ExecuteOutbound(t *testing.T) {
	followup, action, err := (&proposePresentationSent{}).ExecuteOutbound(&metaData{})
	require.Contains(t, fmt.Sprintf("%v", err), "is not implemented yet")
	require.Nil(t, followup)
	require.Nil(t, action)
}

func TestProposePresentationReceived_CanTransitionTo(t *testing.T) {
	st := &proposePresentationReceived{}
	require.Equal(t, stateNameProposePresentationReceived, st.Name())
	// common states
	require.False(t, st.CanTransitionTo(&start{}))
	require.True(t, st.CanTransitionTo(&abandoning{}))
	require.False(t, st.CanTransitionTo(&done{}))
	require.False(t, st.CanTransitionTo(&noOp{}))
	// states for Verifier
	require.True(t, st.CanTransitionTo(&requestSent{}))
	require.False(t, st.CanTransitionTo(&presentationReceived{}))
	require.False(t, st.CanTransitionTo(&proposePresentationReceived{}))
	// states for Prover
	require.False(t, st.CanTransitionTo(&requestReceived{}))
	require.False(t, st.CanTransitionTo(&presentationSent{}))
	require.False(t, st.CanTransitionTo(&proposePresentationSent{}))
}

func TestProposePresentationReceived_ExecuteInbound(t *testing.T) {
	followup, action, err := (&proposePresentationReceived{}).ExecuteInbound(&metaData{})
	require.Contains(t, fmt.Sprintf("%v", err), "is not implemented yet")
	require.Nil(t, followup)
	require.Nil(t, action)
}

func TestProposePresentationReceived_ExecuteOutbound(t *testing.T) {
	followup, action, err := (&proposePresentationReceived{}).ExecuteOutbound(&metaData{})
	require.Contains(t, fmt.Sprintf("%v", err), "is not implemented yet")
	require.Nil(t, followup)
	require.Nil(t, action)
}

func notTransition(t *testing.T, st state) {
	t.Helper()

	var allState = [...]state{
		// common states
		&start{}, &abandoning{}, &done{}, &noOp{},
		// states for Verifier
		&requestSent{}, &presentationReceived{}, &proposePresentationReceived{},
		// states for Prover
		&requestReceived{}, &presentationSent{}, &proposePresentationSent{},
	}

	for _, s := range allState {
		require.False(t, st.CanTransitionTo(s))
	}
}
