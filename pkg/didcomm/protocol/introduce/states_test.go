/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"errors"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	serviceMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/common/service"
)

func notTransition(t *testing.T, st state) {
	t.Helper()

	allState := [...]state{
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
	followup, _, err := (&noOp{}).ExecuteInbound(nil, &metaData{})
	require.Error(t, err)
	require.Nil(t, followup)
}

func TestNoOp_saveMetadata(t *testing.T) {
	require.NoError(t, (&Service{}).saveMetadata(nil, ""))
}

func TestNoOp_ExecuteOutbound(t *testing.T) {
	followup, _, err := (&noOp{}).ExecuteOutbound(nil, &metaData{})
	require.Error(t, err)
	require.Nil(t, followup)
}

func TestStart_CanTransitionTo(t *testing.T) {
	st := &start{}
	require.Equal(t, stateNameStart, st.Name())

	require.True(t, st.CanTransitionTo(&arranging{}))
	require.True(t, st.CanTransitionTo(&deciding{}))
	require.True(t, st.CanTransitionTo(&requesting{}))
	require.True(t, st.CanTransitionTo(&abandoning{}))

	require.False(t, st.CanTransitionTo(&delivering{}))
	require.False(t, st.CanTransitionTo(&noOp{}))
	require.False(t, st.CanTransitionTo(&start{}))
	require.False(t, st.CanTransitionTo(&done{}))
	require.False(t, st.CanTransitionTo(&confirming{}))
	require.False(t, st.CanTransitionTo(&waiting{}))
}

func TestStart_ExecuteInbound(t *testing.T) {
	followup, _, err := (&start{}).ExecuteInbound(nil, &metaData{})
	require.EqualError(t, err, "start: ExecuteInbound function is not supposed to be used")
	require.Nil(t, followup)
}

func TestStart_ExecuteOutbound(t *testing.T) {
	followup, _, err := (&start{}).ExecuteOutbound(nil, &metaData{})
	require.EqualError(t, err, "start: ExecuteOutbound function is not supposed to be used")
	require.Nil(t, followup)
}

func TestDone_CanTransitionTo(t *testing.T) {
	st := &done{}
	require.Equal(t, stateNameDone, st.Name())
	notTransition(t, st)
}

func TestDone_ExecuteInbound(t *testing.T) {
	followup, _, err := (&done{}).ExecuteInbound(nil, &metaData{})
	require.NoError(t, err)
	require.Equal(t, &noOp{}, followup)
}

func TestDone_ExecuteOutbound(t *testing.T) {
	followup, _, err := (&done{}).ExecuteOutbound(nil, &metaData{})
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
	const errMsg = "test error"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	messenger := serviceMocks.NewMockMessenger(ctrl)
	messenger.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
	messenger.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New(errMsg))

	followup, action, err := (&arranging{}).ExecuteOutbound(messenger, &metaData{
		transitionalPayload: transitionalPayload{Action: Action{Msg: service.NewDIDCommMsgMap(struct{}{})}},
		saveMetadata:        func(_ service.DIDCommMsgMap, _ string) error { return nil },
	})
	require.NoError(t, err)
	require.NoError(t, action())
	require.Equal(t, &noOp{}, followup)

	// Send an error
	followup, action, err = (&arranging{}).ExecuteOutbound(messenger, &metaData{
		transitionalPayload: transitionalPayload{Action: Action{Msg: service.NewDIDCommMsgMap(struct{}{})}},
		saveMetadata:        func(_ service.DIDCommMsgMap, _ string) error { return nil },
	})
	require.NoError(t, err)
	require.Contains(t, fmt.Sprintf("%v", action()), errMsg)
	require.Equal(t, &noOp{}, followup)

	followup, action, err = (&arranging{}).ExecuteOutbound(messenger, &metaData{
		transitionalPayload: transitionalPayload{Action: Action{Msg: service.NewDIDCommMsgMap(struct{}{})}},
		saveMetadata:        func(_ service.DIDCommMsgMap, _ string) error { return errors.New(errMsg) },
	})
	require.NoError(t, err)
	require.Contains(t, fmt.Sprintf("%v", action()), errMsg)
	require.Equal(t, &noOp{}, followup)

	followup, action, err = (&arranging{}).ExecuteOutbound(messenger, &metaData{
		saveMetadata:        func(msg service.DIDCommMsgMap, thID string) error { return errors.New("test error") },
		transitionalPayload: transitionalPayload{Action: Action{Msg: service.DIDCommMsgMap{}}},
	})
	require.NoError(t, err)
	require.Contains(t, fmt.Sprintf("%v", action()), "test error")
	require.Equal(t, &noOp{}, followup)
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
	followup, _, err := (&delivering{}).ExecuteOutbound(nil, &metaData{})
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
	followup, _, err := (&confirming{}).ExecuteOutbound(nil, &metaData{})
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

func TestAbandoning_ExecuteOutbound(t *testing.T) {
	followup, _, err := (&abandoning{}).ExecuteOutbound(nil, &metaData{})
	require.Error(t, err)
	require.Nil(t, followup)
}

func TestDeciding_CanTransitionTo(t *testing.T) {
	st := &deciding{}
	require.Equal(t, stateNameDeciding, st.Name())

	require.True(t, st.CanTransitionTo(&waiting{}))
	require.True(t, st.CanTransitionTo(&done{}))
	require.True(t, st.CanTransitionTo(&abandoning{}))

	require.False(t, st.CanTransitionTo(&noOp{}))
	require.False(t, st.CanTransitionTo(&start{}))
	require.False(t, st.CanTransitionTo(&delivering{}))
	require.False(t, st.CanTransitionTo(&arranging{}))
	require.False(t, st.CanTransitionTo(&confirming{}))
	require.False(t, st.CanTransitionTo(&deciding{}))
	require.False(t, st.CanTransitionTo(&requesting{}))
}

func TestDeciding_ExecuteInbound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("handles inbound message", func(t *testing.T) {
		messenger := serviceMocks.NewMockMessenger(ctrl)
		messenger.EXPECT().ReplyToMsg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

		followup, action, err := (&deciding{}).ExecuteInbound(messenger, &metaData{
			transitionalPayload: transitionalPayload{Action: Action{Msg: service.NewDIDCommMsgMap(struct{}{})}},
		})

		require.NoError(t, err)
		require.NoError(t, action())
		require.Equal(t, &waiting{}, followup)
	})

	t.Run("adds attachment", func(t *testing.T) {
		expected := &decorator.Attachment{
			ID: uuid.New().String(),
		}
		messenger := serviceMocks.NewMockMessenger(ctrl)
		messenger.EXPECT().ReplyToMsg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(_, msg service.DIDCommMsgMap, _, _ string) error {
				result := &Response{}
				err := msg.Decode(result)
				require.NoError(t, err)
				require.Len(t, result.Attachments, 1)
				require.Equal(t, expected, result.Attachments[0])
				return nil
			},
		).Times(1)
		msg := service.NewDIDCommMsgMap(struct{}{})
		msg.Metadata()[metaAttachment] = []*decorator.Attachment{expected}
		_, action, err := (&deciding{}).ExecuteInbound(messenger, &metaData{
			transitionalPayload: transitionalPayload{Action: Action{Msg: msg}},
		})
		require.NoError(t, err)
		err = action()
		require.NoError(t, err)
	})

	t.Run("fails if attachments used improperly", func(t *testing.T) {
		messenger := serviceMocks.NewMockMessenger(ctrl)
		messenger.EXPECT().ReplyToMsg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).MaxTimes(0)
		msg := service.NewDIDCommMsgMap(struct{}{})
		msg.Metadata()[metaAttachment] = []struct{}{}
		_, action, err := (&deciding{}).ExecuteInbound(messenger, &metaData{
			transitionalPayload: transitionalPayload{Action: Action{Msg: msg}},
		})
		require.NoError(t, err)
		err = action()
		require.Error(t, err)
	})
}

func TestDeciding_ExecuteOutbound(t *testing.T) {
	followup, _, err := (&deciding{}).ExecuteOutbound(nil, &metaData{})
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
	followup, _, err := (&waiting{}).ExecuteInbound(nil, &metaData{})
	require.NoError(t, err)
	require.Equal(t, &noOp{}, followup)
}

func TestWaiting_ExecuteOutbound(t *testing.T) {
	followup, _, err := (&waiting{}).ExecuteOutbound(nil, &metaData{})
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
	followup, _, err := (&requesting{}).ExecuteInbound(nil, &metaData{})
	require.Error(t, err)
	require.Nil(t, followup)
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

func Test_sendProposals(t *testing.T) {
	const errMsg = "test error"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	messenger := serviceMocks.NewMockMessenger(ctrl)
	messenger.EXPECT().ReplyToMsg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New(errMsg))

	msg := service.NewDIDCommMsgMap(struct{}{})
	msg.SetID(uuid.New().String())

	msg.Metadata()[metaRecipients] = map[string]int{}

	require.NoError(t, sendProposals(messenger, &metaData{
		transitionalPayload: transitionalPayload{Action: Action{Msg: msg}},
	}))

	msg.Metadata()[metaRecipients] = []interface{}{&Recipient{}}
	require.Contains(t, fmt.Sprintf("%v", sendProposals(messenger, &metaData{
		transitionalPayload: transitionalPayload{Action: Action{Msg: msg}},
		saveMetadata:        func(_ service.DIDCommMsgMap, _ string) error { return nil },
	})), errMsg)

	require.Contains(t, fmt.Sprintf("%v", sendProposals(messenger, &metaData{
		transitionalPayload: transitionalPayload{Action: Action{Msg: msg}},
		saveMetadata:        func(_ service.DIDCommMsgMap, _ string) error { return errors.New(errMsg) },
	})), errMsg)

	msg = service.NewDIDCommMsgMap(struct{}{})
	msg.Metadata()[metaRecipients] = []interface{}{&Recipient{}}
	require.EqualError(t, sendProposals(messenger, &metaData{
		transitionalPayload: transitionalPayload{Action: Action{Msg: msg}},
	}), "get threadID: threadID not found")

	msg = service.NewDIDCommMsgMap(struct{}{})
	msg.Metadata()[metaRecipients] = []interface{}{&Recipient{MyDID: "my_did"}}
	require.EqualError(t, sendProposals(messenger, &metaData{
		transitionalPayload: transitionalPayload{Action: Action{Msg: msg}},
		saveMetadata:        func(_ service.DIDCommMsgMap, _ string) error { return errors.New(errMsg) },
	}), "save metadata: test error")
}
