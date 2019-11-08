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
		&deciding{}, &waiting{}, &requesting{},
	}

	for _, s := range allState {
		require.False(t, st.CanTransitionTo(s))
	}
}

func TestNoOp_CanTransitionTo(t *testing.T) {
	noop := &noOp{}
	require.Equal(t, stateNameNoop, noop.Name())
	notTransition(t, noop)
}

func TestNoOp_ExecuteInbound(t *testing.T) {
	followup, err := (&noOp{}).ExecuteInbound(internalContext{}, &metaData{})
	require.Error(t, err)
	require.Nil(t, followup)
}

func TestNoOp_ExecuteOutbound(t *testing.T) {
	followup, err := (&noOp{}).ExecuteOutbound(internalContext{}, &metaData{}, &service.Destination{})
	require.Error(t, err)
	require.Nil(t, followup)
}

func TestStart_CanTransitionTo(t *testing.T) {
	st := &start{}
	require.Equal(t, stateNameStart, st.Name())

	require.True(t, st.CanTransitionTo(&arranging{}))
	require.True(t, st.CanTransitionTo(&deciding{}))
	require.True(t, st.CanTransitionTo(&requesting{}))

	require.False(t, st.CanTransitionTo(&delivering{}))
	require.False(t, st.CanTransitionTo(&noOp{}))
	require.False(t, st.CanTransitionTo(&start{}))
	require.False(t, st.CanTransitionTo(&done{}))
	require.False(t, st.CanTransitionTo(&confirming{}))
	require.False(t, st.CanTransitionTo(&abandoning{}))
	require.False(t, st.CanTransitionTo(&waiting{}))
}

func TestStart_ExecuteInbound(t *testing.T) {
	followup, err := (&start{}).ExecuteInbound(internalContext{}, &metaData{})
	require.NoError(t, err)
	require.Equal(t, &arranging{}, followup)
}

func TestStart_ExecuteOutbound(t *testing.T) {
	followup, err := (&start{}).ExecuteOutbound(internalContext{}, &metaData{}, &service.Destination{})
	require.NoError(t, err)
	require.Equal(t, &noOp{}, followup)
}

func TestDone_CanTransitionTo(t *testing.T) {
	st := &done{}
	require.Equal(t, stateNameDone, st.Name())
	notTransition(t, st)
}

func TestDone_ExecuteInbound(t *testing.T) {
	followup, err := (&done{}).ExecuteInbound(internalContext{}, &metaData{})
	require.NoError(t, err)
	require.Equal(t, &noOp{}, followup)
}

func TestDone_ExecuteOutbound(t *testing.T) {
	followup, err := (&done{}).ExecuteOutbound(internalContext{}, &metaData{}, &service.Destination{})
	require.Error(t, err)
	require.Nil(t, followup)
}

func TestArranging_CanTransitionTo(t *testing.T) {
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
	require.False(t, st.CanTransitionTo(&requesting{}))
}

func TestArranging_ExecuteInbound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	dispatcher := dispatcherMocks.NewMockOutbound(ctrl)
	dispatcher.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

	dep := mocks.NewMockInvitationEnvelope(ctrl)
	dep.EXPECT().Destinations().Return([]*service.Destination{{}})

	followup, err := (&arranging{}).ExecuteInbound(internalContext{Outbound: dispatcher}, &metaData{dependency: dep})
	require.NoError(t, err)
	require.Equal(t, &noOp{}, followup)
}

func TestArranging_ExecuteOutbound(t *testing.T) {
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

func TestDelivering_CanTransitionTo(t *testing.T) {
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
	require.False(t, st.CanTransitionTo(&requesting{}))
}

func TestDelivering_ExecuteInbound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Happy path", func(t *testing.T) {
		ctx := internalContext{Outbound: dispatcherMocks.NewMockOutbound(ctrl)}
		ctx.SendInvitation = func(inv *didexchange.Invitation, dest *service.Destination) error {
			return nil
		}

		dep := mocks.NewMockInvitationEnvelope(ctrl)
		dep.EXPECT().Destinations().Return([]*service.Destination{{}}).Times(1)
		dep.EXPECT().Invitation().Return(&didexchange.Invitation{}).Times(2)

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
		dep.EXPECT().Invitation().Return(nil).Times(1)

		followup, err := (&delivering{}).ExecuteInbound(ctx, &metaData{dependency: dep})
		require.Nil(t, followup)
		require.EqualError(t, err, "send inbound invitation: "+errMsg)

		// SkipProposal
		dep.EXPECT().Invitation().Return(&didexchange.Invitation{}).Times(2)
		followup, err = (&delivering{}).ExecuteInbound(ctx, &metaData{dependency: dep})
		require.Nil(t, followup)
		require.EqualError(t, err, "send inbound invitation (skip): "+errMsg)
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
		dep.EXPECT().Destinations().Return([]*service.Destination{{}, {}}).Times(1)
		dep.EXPECT().Invitation().Return(nil).Times(1)

		followup, err := (&delivering{}).ExecuteInbound(ctx, &metaData{dependency: dep})
		require.Nil(t, followup)
		require.EqualError(t, errors.Unwrap(err), errMsg)
	})
}

func TestDelivering_ExecuteOutbound(t *testing.T) {
	followup, err := (&delivering{}).ExecuteOutbound(internalContext{}, &metaData{}, &service.Destination{})
	require.Error(t, err)
	require.Nil(t, followup)
}

func TestConfirming_CanTransitionTo(t *testing.T) {
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
	require.False(t, st.CanTransitionTo(&requesting{}))
}

func TestConfirming_ExecuteInbound(t *testing.T) {
	followup, err := (&confirming{}).ExecuteInbound(internalContext{}, &metaData{})
	require.Error(t, err)
	require.Nil(t, followup)
}

func TestConfirming_ExecuteOutbound(t *testing.T) {
	followup, err := (&confirming{}).ExecuteOutbound(internalContext{}, &metaData{}, &service.Destination{})
	require.Error(t, err)
	require.Nil(t, followup)
}

func TestAbandoning_CanTransitionTo(t *testing.T) {
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
	require.False(t, st.CanTransitionTo(&requesting{}))
}

func TestAbandoning_ExecuteInbound(t *testing.T) {
	followup, err := (&abandoning{}).ExecuteInbound(internalContext{}, &metaData{})
	require.Error(t, err)
	require.Nil(t, followup)
}

func TestAbandoning_ExecuteOutbound(t *testing.T) {
	followup, err := (&abandoning{}).ExecuteOutbound(internalContext{}, &metaData{}, &service.Destination{})
	require.Error(t, err)
	require.Nil(t, followup)
}

func TestDeciding_CanTransitionTo(t *testing.T) {
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
	require.False(t, st.CanTransitionTo(&requesting{}))
}

func TestDeciding_ExecuteInbound(t *testing.T) {
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

func TestDeciding_ExecuteOutbound(t *testing.T) {
	followup, err := (&deciding{}).ExecuteOutbound(internalContext{}, &metaData{}, &service.Destination{})
	require.Error(t, err)
	require.Nil(t, followup)
}

func TestWaiting_CanTransitionTo(t *testing.T) {
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
	require.False(t, st.CanTransitionTo(&requesting{}))
}

func TestWaiting_ExecuteInbound(t *testing.T) {
	followup, err := (&waiting{}).ExecuteInbound(internalContext{}, &metaData{})
	require.NoError(t, err)
	require.Equal(t, &noOp{}, followup)
}

func TestWaiting_ExecuteOutbound(t *testing.T) {
	followup, err := (&waiting{}).ExecuteOutbound(internalContext{}, &metaData{}, &service.Destination{})
	require.Error(t, err)
	require.Nil(t, followup)
}

func TestRequesting_CanTransitionTo(t *testing.T) {
	st := &requesting{}
	require.Equal(t, stateNameRequesting, st.Name())

	require.True(t, st.CanTransitionTo(&deciding{}))
	require.True(t, st.CanTransitionTo(&done{}))

	require.False(t, st.CanTransitionTo(&noOp{}))
	require.False(t, st.CanTransitionTo(&start{}))
	require.False(t, st.CanTransitionTo(&delivering{}))
	require.False(t, st.CanTransitionTo(&arranging{}))
	require.False(t, st.CanTransitionTo(&confirming{}))
	require.False(t, st.CanTransitionTo(&abandoning{}))
	require.False(t, st.CanTransitionTo(&waiting{}))
	require.False(t, st.CanTransitionTo(&requesting{}))
}

func TestRequesting_ExecuteInbound(t *testing.T) {
	followup, err := (&requesting{}).ExecuteInbound(internalContext{}, &metaData{})
	require.Error(t, err)
	require.Nil(t, followup)
}

func TestRequesting_ExecuteOutbound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	followup, err := (&requesting{}).ExecuteOutbound(internalContext{}, &metaData{
		Msg: &service.DIDCommMsg{Payload: []byte(`[]`)},
	}, nil)

	const errMsg = "requesting outbound unmarshal: json: cannot unmarshal array into Go value of type introduce.Request"

	require.EqualError(t, err, errMsg)
	require.Nil(t, followup)
}
