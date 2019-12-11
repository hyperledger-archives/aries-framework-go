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
	require.EqualError(t, err, "start ExecuteInbound: not implemented yet")
	require.Nil(t, followup)
}

func TestStart_ExecuteOutbound(t *testing.T) {
	followup, err := (&start{}).ExecuteOutbound(internalContext{}, &metaData{}, &service.Destination{})
	require.EqualError(t, err, "start ExecuteOutbound: not implemented yet")
	require.Nil(t, followup)
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
	t.Run("Error send problem-report", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		dispatcher := dispatcherMocks.NewMockOutbound(ctrl)
		dispatcher.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("test error"))

		followup, err := (&abandoning{}).ExecuteInbound(internalContext{Outbound: dispatcher}, &metaData{
			Msg: &service.DIDCommMsg{
				Header:  &service.Header{Type: RequestMsgType},
				Payload: []byte(`{}`),
			},
		})
		require.Nil(t, followup)
		require.EqualError(t, err, "send problem-report: test error")
	})
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

	followup, err := (&deciding{}).ExecuteInbound(ctx, &metaData{})
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
	require.True(t, st.CanTransitionTo(&abandoning{}))

	require.False(t, st.CanTransitionTo(&noOp{}))
	require.False(t, st.CanTransitionTo(&start{}))
	require.False(t, st.CanTransitionTo(&delivering{}))
	require.False(t, st.CanTransitionTo(&arranging{}))
	require.False(t, st.CanTransitionTo(&confirming{}))
	require.False(t, st.CanTransitionTo(&deciding{}))
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
	require.True(t, st.CanTransitionTo(&abandoning{}))

	require.False(t, st.CanTransitionTo(&noOp{}))
	require.False(t, st.CanTransitionTo(&start{}))
	require.False(t, st.CanTransitionTo(&delivering{}))
	require.False(t, st.CanTransitionTo(&arranging{}))
	require.False(t, st.CanTransitionTo(&confirming{}))
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

func Test_getApproveFromMsg(t *testing.T) {
	t.Run("Unmarshal error", func(t *testing.T) {
		approve, ok := getApproveFromMsg(&service.DIDCommMsg{
			Header:  &service.Header{Type: ResponseMsgType},
			Payload: []byte("[]"),
		})
		require.False(t, approve)
		require.False(t, ok)
	})
}

func Test_stateFromName(t *testing.T) {
	st := stateFromName(stateNameNoop)
	require.Equal(t, &noOp{}, st)

	st = stateFromName(stateNameStart)
	require.Equal(t, &start{}, st)

	st = stateFromName(stateNameDone)
	require.Equal(t, &done{}, st)

	st = stateFromName(stateNameArranging)
	require.Equal(t, &arranging{}, st)

	st = stateFromName(stateNameDelivering)
	require.Equal(t, &delivering{}, st)

	st = stateFromName(stateNameConfirming)
	require.Equal(t, &confirming{}, st)

	st = stateFromName(stateNameAbandoning)
	require.Equal(t, &abandoning{}, st)

	st = stateFromName(stateNameDeciding)
	require.Equal(t, &deciding{}, st)

	st = stateFromName(stateNameWaiting)
	require.Equal(t, &waiting{}, st)

	st = stateFromName(stateNameRequesting)
	require.Equal(t, &requesting{}, st)

	st = stateFromName("unknown")
	require.Equal(t, &noOp{}, st)
}
