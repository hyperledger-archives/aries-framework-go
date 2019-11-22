/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	dispatcherMocks "github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher/gomocks"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	mocks "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/introduce/gomocks"
)

func notTransition(t *testing.T, st state) {
	t.Helper()

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
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := internalContext{Outbound: dispatcherMocks.NewMockOutbound(ctrl)}
	followup, err := (&noOp{}).ExecuteInbound(ctx, &metaData{})
	require.Error(t, err)
	require.Nil(t, followup)
}

func TestNoOpState_ExecuteOutbound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := internalContext{Outbound: dispatcherMocks.NewMockOutbound(ctrl)}
	followup, err := (&noOp{}).ExecuteOutbound(ctx, &metaData{}, &service.Destination{})
	require.Error(t, err)
	require.Nil(t, followup)
}

// start state can transition to ...
func TestStartState(t *testing.T) {
	st := &start{}
	require.Equal(t, stateNameStart, st.Name())

	require.True(t, st.CanTransitionTo(&arranging{}))
	require.True(t, st.CanTransitionTo(&deciding{}))

	require.False(t, st.CanTransitionTo(&delivering{}))
	require.False(t, st.CanTransitionTo(&noOp{}))
	require.False(t, st.CanTransitionTo(&start{}))
	require.False(t, st.CanTransitionTo(&done{}))
	require.False(t, st.CanTransitionTo(&confirming{}))
	require.False(t, st.CanTransitionTo(&abandoning{}))
	require.False(t, st.CanTransitionTo(&waiting{}))
}

func TestStartState_ExecuteInbound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := internalContext{Outbound: dispatcherMocks.NewMockOutbound(ctrl)}
	followup, err := (&start{}).ExecuteInbound(ctx, &metaData{})
	require.NoError(t, err)
	require.Equal(t, &arranging{}, followup)
}

func TestStartState_ExecuteOutbound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := internalContext{Outbound: dispatcherMocks.NewMockOutbound(ctrl)}
	followup, err := (&start{}).ExecuteOutbound(ctx, &metaData{}, &service.Destination{})
	require.NoError(t, err)
	require.Equal(t, &noOp{}, followup)
}

// done state can transition to ...
func TestDoneState(t *testing.T) {
	done := &done{}
	require.Equal(t, stateNameDone, done.Name())
	notTransition(t, done)
}

func TestDoneState_ExecuteInbound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := internalContext{Outbound: dispatcherMocks.NewMockOutbound(ctrl)}
	followup, err := (&done{}).ExecuteInbound(ctx, &metaData{})
	require.NoError(t, err)
	require.Equal(t, &noOp{}, followup)
}

func TestDoneState_ExecuteOutbound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := internalContext{Outbound: dispatcherMocks.NewMockOutbound(ctrl)}
	followup, err := (&done{}).ExecuteOutbound(ctx, &metaData{}, &service.Destination{})
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
	require.True(t, st.CanTransitionTo(&delivering{}))

	require.False(t, st.CanTransitionTo(&noOp{}))
	require.False(t, st.CanTransitionTo(&start{}))
	require.False(t, st.CanTransitionTo(&confirming{}))
	require.False(t, st.CanTransitionTo(&deciding{}))
	require.False(t, st.CanTransitionTo(&waiting{}))
}

func TestArrangingState_ExecuteInbound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	dispatcher := dispatcherMocks.NewMockOutbound(ctrl)
	dispatcher.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

	ctx := internalContext{
		Outbound: dispatcher,
		SendInvitation: func(_ *didexchange.Invitation, _ *service.Destination) error {
			return nil
		},
	}

	dep := mocks.NewMockInvitationEnvelope(ctrl)
	dep.EXPECT().Destinations().Return([]*service.Destination{{}})

	followup, err := (&arranging{}).ExecuteInbound(ctx, &metaData{dependency: dep})
	require.NoError(t, err)
	require.Equal(t, &noOp{}, followup)
}

func TestArrangingState_ExecuteOutbound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	dispatcher := dispatcherMocks.NewMockOutbound(ctrl)
	dispatcher.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

	ctx := internalContext{Outbound: dispatcher}
	followup, err := (&arranging{}).ExecuteOutbound(ctx, &metaData{
		Msg: &service.DIDCommMsg{Payload: []byte(`{}`)},
	}, &service.Destination{})
	require.NoError(t, err)
	require.Equal(t, &noOp{}, followup)

	// JSON error
	errMsg := "json: cannot unmarshal array into Go value of type introduce.Proposal"
	followup, err = (&arranging{}).ExecuteOutbound(ctx, &metaData{
		Msg: &service.DIDCommMsg{Payload: []byte(`[]`)},
	}, &service.Destination{})
	require.EqualError(t, errors.Unwrap(err), errMsg)
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
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Happy path", func(t *testing.T) {
		ctx := internalContext{Outbound: dispatcherMocks.NewMockOutbound(ctrl)}
		ctx.SendInvitation = func(inv *didexchange.Invitation, dest *service.Destination) error {
			return nil
		}

		dep := mocks.NewMockInvitationEnvelope(ctrl)
		dep.EXPECT().Destinations().Return([]*service.Destination{{}}).Times(2)
		dep.EXPECT().Invitation().Return(nil)

		followup, err := (&delivering{}).ExecuteInbound(ctx, &metaData{dependency: dep})
		require.NoError(t, err)
		require.Equal(t, &done{}, followup)
	})

	t.Run("SendInvitation Error", func(t *testing.T) {
		const errMsg = "test err"

		ctx := internalContext{Outbound: dispatcherMocks.NewMockOutbound(ctrl)}
		ctx.SendInvitation = func(inv *didexchange.Invitation, dest *service.Destination) error {
			return errors.New(errMsg)
		}

		dep := mocks.NewMockInvitationEnvelope(ctrl)
		dep.EXPECT().Destinations().Return([]*service.Destination{{}}).Times(2)
		dep.EXPECT().Invitation().Return(nil)

		followup, err := (&delivering{}).ExecuteInbound(ctx, &metaData{dependency: dep})
		require.Nil(t, followup)
		require.EqualError(t, errors.Unwrap(err), errMsg)

		// SkipProposal
		dep.EXPECT().Destinations().Return([]*service.Destination{{}, {}}).Times(2)
		followup, err = (&delivering{}).ExecuteInbound(ctx, &metaData{dependency: dep})
		require.Nil(t, followup)
		require.EqualError(t, errors.Unwrap(err), errMsg)
	})

	t.Run("Error Send", func(t *testing.T) {
		const errMsg = "test err"

		outbound := dispatcherMocks.NewMockOutbound(ctrl)
		outbound.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New(errMsg))

		ctx := internalContext{Outbound: outbound}
		ctx.SendInvitation = func(inv *didexchange.Invitation, dest *service.Destination) error {
			return nil
		}

		dep := mocks.NewMockInvitationEnvelope(ctrl)
		dep.EXPECT().Destinations().Return([]*service.Destination{{}, {}}).Times(2)

		followup, err := (&delivering{}).ExecuteInbound(ctx, &metaData{dependency: dep})
		require.Nil(t, followup)
		require.EqualError(t, errors.Unwrap(err), errMsg)
	})
}

func TestDeliveringState_ExecuteOutbound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := internalContext{Outbound: dispatcherMocks.NewMockOutbound(ctrl)}
	followup, err := (&delivering{}).ExecuteOutbound(ctx, &metaData{}, &service.Destination{})
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
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := internalContext{Outbound: dispatcherMocks.NewMockOutbound(ctrl)}
	followup, err := (&confirming{}).ExecuteInbound(ctx, &metaData{})
	require.Error(t, err)
	require.Nil(t, followup)
}

func TestConfirmingState_ExecuteOutbound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := internalContext{Outbound: dispatcherMocks.NewMockOutbound(ctrl)}
	followup, err := (&confirming{}).ExecuteOutbound(ctx, &metaData{}, &service.Destination{})
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
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := internalContext{Outbound: dispatcherMocks.NewMockOutbound(ctrl)}
	followup, err := (&abandoning{}).ExecuteInbound(ctx, &metaData{})
	require.Error(t, err)
	require.Nil(t, followup)
}

func TestAbandoningState_ExecuteOutbound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := internalContext{Outbound: dispatcherMocks.NewMockOutbound(ctrl)}
	followup, err := (&abandoning{}).ExecuteOutbound(ctx, &metaData{}, &service.Destination{})
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
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	dispatcher := dispatcherMocks.NewMockOutbound(ctrl)
	dispatcher.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

	ctx := internalContext{Outbound: dispatcher}

	dep := mocks.NewMockInvitationEnvelope(ctrl)
	dep.EXPECT().Invitation().Return(nil)

	followup, err := (&deciding{}).ExecuteInbound(ctx, &metaData{dependency: dep})
	require.NoError(t, err)
	require.Equal(t, &waiting{}, followup)
}

func TestDecidingState_ExecuteOutbound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := internalContext{Outbound: dispatcherMocks.NewMockOutbound(ctrl)}
	followup, err := (&deciding{}).ExecuteOutbound(ctx, &metaData{}, &service.Destination{})
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
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := internalContext{Outbound: dispatcherMocks.NewMockOutbound(ctrl)}
	followup, err := (&waiting{}).ExecuteInbound(ctx, &metaData{})
	require.NoError(t, err)
	require.Equal(t, &noOp{}, followup)
}

func TestWaitingState_ExecuteOutbound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := internalContext{Outbound: dispatcherMocks.NewMockOutbound(ctrl)}
	followup, err := (&waiting{}).ExecuteOutbound(ctx, &metaData{}, &service.Destination{})
	require.Error(t, err)
	require.Nil(t, followup)
}
