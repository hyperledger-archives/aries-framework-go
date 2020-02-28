/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func notTransition(t *testing.T, st state) {
	t.Helper()

	var allState = [...]state{
		// common states
		&start{}, &abandoning{}, &done{}, &noOp{},
		// states for Issuer
		&proposalReceived{}, &offerSent{}, &requestReceived{}, &credentialIssued{},
		// states for Holder
		&proposalSent{}, &offerReceived{}, &requestSent{}, &credentialReceived{},
	}

	for _, s := range allState {
		require.False(t, st.CanTransitionTo(s))
	}
}

func TestStart_CanTransitionTo(t *testing.T) {
	st := &start{}
	require.Equal(t, stateNameStart, st.Name())
	// common states
	require.False(t, st.CanTransitionTo(&start{}))
	require.False(t, st.CanTransitionTo(&abandoning{}))
	require.False(t, st.CanTransitionTo(&done{}))
	require.False(t, st.CanTransitionTo(&noOp{}))
	// states for Issuer
	require.True(t, st.CanTransitionTo(&proposalReceived{}))
	require.True(t, st.CanTransitionTo(&offerSent{}))
	require.True(t, st.CanTransitionTo(&requestReceived{}))
	require.False(t, st.CanTransitionTo(&credentialIssued{}))
	// states for Holder
	require.True(t, st.CanTransitionTo(&proposalSent{}))
	require.True(t, st.CanTransitionTo(&offerReceived{}))
	require.True(t, st.CanTransitionTo(&requestSent{}))
	require.False(t, st.CanTransitionTo(&credentialReceived{}))
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
	// states for Issuer
	require.False(t, st.CanTransitionTo(&proposalReceived{}))
	require.False(t, st.CanTransitionTo(&offerSent{}))
	require.False(t, st.CanTransitionTo(&requestReceived{}))
	require.False(t, st.CanTransitionTo(&credentialIssued{}))
	// states for Holder
	require.False(t, st.CanTransitionTo(&proposalSent{}))
	require.False(t, st.CanTransitionTo(&offerReceived{}))
	require.False(t, st.CanTransitionTo(&requestSent{}))
	require.False(t, st.CanTransitionTo(&credentialReceived{}))
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
	require.Contains(t, fmt.Sprintf("%v", err), "is not implemented yet")
	require.Nil(t, followup)
	require.Nil(t, action)
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

func TestProposalReceived_CanTransitionTo(t *testing.T) {
	st := &proposalReceived{}
	require.Equal(t, stateNameProposalReceived, st.Name())
	// common states
	require.False(t, st.CanTransitionTo(&start{}))
	require.True(t, st.CanTransitionTo(&abandoning{}))
	require.False(t, st.CanTransitionTo(&done{}))
	require.False(t, st.CanTransitionTo(&noOp{}))
	// states for Issuer
	require.False(t, st.CanTransitionTo(&proposalReceived{}))
	require.True(t, st.CanTransitionTo(&offerSent{}))
	require.False(t, st.CanTransitionTo(&requestReceived{}))
	require.False(t, st.CanTransitionTo(&credentialIssued{}))
	// states for Holder
	require.False(t, st.CanTransitionTo(&proposalSent{}))
	require.False(t, st.CanTransitionTo(&offerReceived{}))
	require.False(t, st.CanTransitionTo(&requestSent{}))
	require.False(t, st.CanTransitionTo(&credentialReceived{}))
}

func TestProposalReceived_ExecuteInbound(t *testing.T) {
	followup, action, err := (&proposalReceived{}).ExecuteInbound(&metaData{})
	require.Contains(t, fmt.Sprintf("%v", err), "is not implemented yet")
	require.Nil(t, followup)
	require.Nil(t, action)
}

func TestProposalReceived_ExecuteOutbound(t *testing.T) {
	followup, action, err := (&proposalReceived{}).ExecuteOutbound(&metaData{})
	require.Contains(t, fmt.Sprintf("%v", err), "is not implemented yet")
	require.Nil(t, followup)
	require.Nil(t, action)
}

func TestOfferSent_CanTransitionTo(t *testing.T) {
	st := &offerSent{}
	require.Equal(t, stateNameOfferSent, st.Name())
	// common states
	require.False(t, st.CanTransitionTo(&start{}))
	require.True(t, st.CanTransitionTo(&abandoning{}))
	require.False(t, st.CanTransitionTo(&done{}))
	require.False(t, st.CanTransitionTo(&noOp{}))
	// states for Issuer
	require.True(t, st.CanTransitionTo(&proposalReceived{}))
	require.False(t, st.CanTransitionTo(&offerSent{}))
	require.True(t, st.CanTransitionTo(&requestReceived{}))
	require.False(t, st.CanTransitionTo(&credentialIssued{}))
	// states for Holder
	require.False(t, st.CanTransitionTo(&proposalSent{}))
	require.False(t, st.CanTransitionTo(&offerReceived{}))
	require.False(t, st.CanTransitionTo(&requestSent{}))
	require.False(t, st.CanTransitionTo(&credentialReceived{}))
}

func TestOfferSent_ExecuteInbound(t *testing.T) {
	followup, action, err := (&offerSent{}).ExecuteInbound(&metaData{})
	require.Contains(t, fmt.Sprintf("%v", err), "is not implemented yet")
	require.Nil(t, followup)
	require.Nil(t, action)
}

func TestOfferSent_ExecuteOutbound(t *testing.T) {
	followup, action, err := (&offerSent{}).ExecuteOutbound(&metaData{})
	require.Contains(t, fmt.Sprintf("%v", err), "is not implemented yet")
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
	// states for Issuer
	require.False(t, st.CanTransitionTo(&proposalReceived{}))
	require.False(t, st.CanTransitionTo(&offerSent{}))
	require.False(t, st.CanTransitionTo(&requestReceived{}))
	require.True(t, st.CanTransitionTo(&credentialIssued{}))
	// states for Holder
	require.False(t, st.CanTransitionTo(&proposalSent{}))
	require.False(t, st.CanTransitionTo(&offerReceived{}))
	require.False(t, st.CanTransitionTo(&requestSent{}))
	require.False(t, st.CanTransitionTo(&credentialReceived{}))
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

func TestCredentialIssued_CanTransitionTo(t *testing.T) {
	st := &credentialIssued{}
	require.Equal(t, stateNameCredentialIssued, st.Name())
	// common states
	require.False(t, st.CanTransitionTo(&start{}))
	require.True(t, st.CanTransitionTo(&abandoning{}))
	require.True(t, st.CanTransitionTo(&done{}))
	require.False(t, st.CanTransitionTo(&noOp{}))
	// states for Issuer
	require.False(t, st.CanTransitionTo(&proposalReceived{}))
	require.False(t, st.CanTransitionTo(&offerSent{}))
	require.False(t, st.CanTransitionTo(&requestReceived{}))
	require.False(t, st.CanTransitionTo(&credentialIssued{}))
	// states for Holder
	require.False(t, st.CanTransitionTo(&proposalSent{}))
	require.False(t, st.CanTransitionTo(&offerReceived{}))
	require.False(t, st.CanTransitionTo(&requestSent{}))
	require.False(t, st.CanTransitionTo(&credentialReceived{}))
}

func TestCredentialIssued_ExecuteInbound(t *testing.T) {
	followup, action, err := (&credentialIssued{}).ExecuteInbound(&metaData{})
	require.Contains(t, fmt.Sprintf("%v", err), "is not implemented yet")
	require.Nil(t, followup)
	require.Nil(t, action)
}

func TestCredentialIssued_ExecuteOutbound(t *testing.T) {
	followup, action, err := (&credentialIssued{}).ExecuteOutbound(&metaData{})
	require.Contains(t, fmt.Sprintf("%v", err), "is not implemented yet")
	require.Nil(t, followup)
	require.Nil(t, action)
}

func TestProposalSent_CanTransitionTo(t *testing.T) {
	st := &proposalSent{}
	require.Equal(t, stateNameProposalSent, st.Name())
	// common states
	require.False(t, st.CanTransitionTo(&start{}))
	require.True(t, st.CanTransitionTo(&abandoning{}))
	require.False(t, st.CanTransitionTo(&done{}))
	require.False(t, st.CanTransitionTo(&noOp{}))
	// states for Issuer
	require.False(t, st.CanTransitionTo(&proposalReceived{}))
	require.False(t, st.CanTransitionTo(&offerSent{}))
	require.False(t, st.CanTransitionTo(&requestReceived{}))
	require.False(t, st.CanTransitionTo(&credentialIssued{}))
	// states for Holder
	require.False(t, st.CanTransitionTo(&proposalSent{}))
	require.True(t, st.CanTransitionTo(&offerReceived{}))
	require.False(t, st.CanTransitionTo(&requestSent{}))
	require.False(t, st.CanTransitionTo(&credentialReceived{}))
}

func TestProposalSent_ExecuteInbound(t *testing.T) {
	followup, action, err := (&proposalSent{}).ExecuteInbound(&metaData{})
	require.Contains(t, fmt.Sprintf("%v", err), "is not implemented yet")
	require.Nil(t, followup)
	require.Nil(t, action)
}

func TestProposalSent_ExecuteOutbound(t *testing.T) {
	followup, action, err := (&proposalSent{}).ExecuteOutbound(&metaData{})
	require.Contains(t, fmt.Sprintf("%v", err), "is not implemented yet")
	require.Nil(t, followup)
	require.Nil(t, action)
}

func TestOfferReceived_CanTransitionTo(t *testing.T) {
	st := &offerReceived{}
	require.Equal(t, stateNameOfferReceived, st.Name())
	// common states
	require.False(t, st.CanTransitionTo(&start{}))
	require.True(t, st.CanTransitionTo(&abandoning{}))
	require.False(t, st.CanTransitionTo(&done{}))
	require.False(t, st.CanTransitionTo(&noOp{}))
	// states for Issuer
	require.False(t, st.CanTransitionTo(&proposalReceived{}))
	require.False(t, st.CanTransitionTo(&offerSent{}))
	require.False(t, st.CanTransitionTo(&requestReceived{}))
	require.False(t, st.CanTransitionTo(&credentialIssued{}))
	// states for Holder
	require.True(t, st.CanTransitionTo(&proposalSent{}))
	require.False(t, st.CanTransitionTo(&offerReceived{}))
	require.True(t, st.CanTransitionTo(&requestSent{}))
	require.False(t, st.CanTransitionTo(&credentialReceived{}))
}

func TestOfferReceived_ExecuteInbound(t *testing.T) {
	followup, action, err := (&offerReceived{}).ExecuteInbound(&metaData{})
	require.Contains(t, fmt.Sprintf("%v", err), "is not implemented yet")
	require.Nil(t, followup)
	require.Nil(t, action)
}

func TestOfferReceived_ExecuteOutbound(t *testing.T) {
	followup, action, err := (&offerReceived{}).ExecuteOutbound(&metaData{})
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
	// states for Issuer
	require.False(t, st.CanTransitionTo(&proposalReceived{}))
	require.False(t, st.CanTransitionTo(&offerSent{}))
	require.False(t, st.CanTransitionTo(&requestReceived{}))
	require.False(t, st.CanTransitionTo(&credentialIssued{}))
	// states for Holder
	require.False(t, st.CanTransitionTo(&proposalSent{}))
	require.False(t, st.CanTransitionTo(&offerReceived{}))
	require.False(t, st.CanTransitionTo(&requestSent{}))
	require.True(t, st.CanTransitionTo(&credentialReceived{}))
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

func TestCredentialReceived_CanTransitionTo(t *testing.T) {
	st := &credentialReceived{}
	require.Equal(t, stateNameCredentialReceived, st.Name())
	// common states
	require.False(t, st.CanTransitionTo(&start{}))
	require.True(t, st.CanTransitionTo(&abandoning{}))
	require.True(t, st.CanTransitionTo(&done{}))
	require.False(t, st.CanTransitionTo(&noOp{}))
	// states for Issuer
	require.False(t, st.CanTransitionTo(&proposalReceived{}))
	require.False(t, st.CanTransitionTo(&offerSent{}))
	require.False(t, st.CanTransitionTo(&requestReceived{}))
	require.False(t, st.CanTransitionTo(&credentialIssued{}))
	// states for Holder
	require.False(t, st.CanTransitionTo(&proposalSent{}))
	require.False(t, st.CanTransitionTo(&offerReceived{}))
	require.False(t, st.CanTransitionTo(&requestSent{}))
	require.False(t, st.CanTransitionTo(&credentialReceived{}))
}

func TestCredentialReceived_ExecuteInbound(t *testing.T) {
	followup, action, err := (&credentialReceived{}).ExecuteInbound(&metaData{})
	require.Contains(t, fmt.Sprintf("%v", err), "is not implemented yet")
	require.Nil(t, followup)
	require.Nil(t, action)
}

func TestCredentialReceived_ExecuteOutbound(t *testing.T) {
	followup, action, err := (&credentialReceived{}).ExecuteOutbound(&metaData{})
	require.Contains(t, fmt.Sprintf("%v", err), "is not implemented yet")
	require.Nil(t, followup)
	require.Nil(t, action)
}
