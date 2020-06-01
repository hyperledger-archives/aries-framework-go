/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

import (
	"errors"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	serviceMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/common/service"
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
	require.True(t, st.CanTransitionTo(&proposalReceived{}))
	// states for Prover
	require.True(t, st.CanTransitionTo(&requestReceived{}))
	require.False(t, st.CanTransitionTo(&presentationSent{}))
	require.True(t, st.CanTransitionTo(&proposalSent{}))
}

func TestStart_Execute(t *testing.T) {
	followup, action, err := (&start{}).Execute(&metaData{})
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
	require.False(t, st.CanTransitionTo(&proposalReceived{}))
	// states for Prover
	require.False(t, st.CanTransitionTo(&requestReceived{}))
	require.False(t, st.CanTransitionTo(&presentationSent{}))
	require.False(t, st.CanTransitionTo(&proposalSent{}))
}

func TestAbandoning_Execute(t *testing.T) {
	t.Run("Internal Error", func(t *testing.T) {
		md := &metaData{}
		md.Msg = service.NewDIDCommMsgMap(struct{}{})

		thID := uuid.New().String()
		require.NoError(t, md.Msg.SetID(thID))

		followup, action, err := (&abandoning{Code: codeInternalError}).Execute(md)
		require.NoError(t, err)
		require.Equal(t, &done{}, followup)
		require.NotNil(t, action)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		messenger := serviceMocks.NewMockMessenger(ctrl)
		messenger.EXPECT().
			ReplyToNested(thID, gomock.Any(), "", "").
			Do(func(_ string, msg service.DIDCommMsgMap, myDID, theirDID string) error {
				r := &model.ProblemReport{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, codeInternalError, r.Description.Code)
				require.Equal(t, ProblemReportMsgType, r.Type)

				return nil
			})

		require.NoError(t, action(messenger))
	})

	t.Run("Invalid message", func(t *testing.T) {
		followup, action, err := (&abandoning{Code: codeInternalError}).Execute(&metaData{})
		require.EqualError(t, errors.Unwrap(err), service.ErrInvalidMessage.Error())
		require.Nil(t, followup)
		require.Nil(t, action)
	})

	t.Run("Custom Error", func(t *testing.T) {
		md := &metaData{err: customError{error: errors.New("error")}}
		md.Msg = service.NewDIDCommMsgMap(struct{}{})

		thID := uuid.New().String()
		require.NoError(t, md.Msg.SetID(thID))

		followup, action, err := (&abandoning{Code: codeInternalError}).Execute(md)
		require.NoError(t, err)
		require.Equal(t, &done{}, followup)
		require.NotNil(t, action)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		messenger := serviceMocks.NewMockMessenger(ctrl)
		messenger.EXPECT().
			ReplyToNested(thID, gomock.Any(), "", "").
			Do(func(_ string, msg service.DIDCommMsgMap, myDID, theirDID string) error {
				r := &model.ProblemReport{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, codeRejectedError, r.Description.Code)
				require.Equal(t, ProblemReportMsgType, r.Type)

				return nil
			})

		require.NoError(t, action(messenger))
	})

	t.Run("No error code", func(t *testing.T) {
		md := &metaData{}
		md.Msg = service.NewDIDCommMsgMap(struct{}{})

		require.NoError(t, md.Msg.SetID(uuid.New().String()))

		followup, action, err := (&abandoning{}).Execute(md)
		require.NoError(t, err)
		require.Equal(t, &done{}, followup)
		require.NotNil(t, action)

		require.NoError(t, action(nil))
	})
}

func TestDone_CanTransitionTo(t *testing.T) {
	st := &done{}
	require.Equal(t, stateNameDone, st.Name())
	notTransition(t, st)
}

func TestDone_Execute(t *testing.T) {
	followup, action, err := (&done{}).Execute(&metaData{})
	require.NoError(t, err)
	require.Equal(t, &noOp{}, followup)
	require.NoError(t, action(nil))
}

func TestNoOp_CanTransitionTo(t *testing.T) {
	st := &noOp{}
	require.Equal(t, stateNameNoop, st.Name())
	notTransition(t, st)
}

func TestNoOp_Execute(t *testing.T) {
	followup, action, err := (&noOp{}).Execute(&metaData{})
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
	require.False(t, st.CanTransitionTo(&proposalReceived{}))
	// states for Prover
	require.False(t, st.CanTransitionTo(&requestReceived{}))
	require.True(t, st.CanTransitionTo(&presentationSent{}))
	require.True(t, st.CanTransitionTo(&proposalSent{}))
}

func TestRequestReceived_Execute(t *testing.T) {
	t.Run("With presentation", func(t *testing.T) {
		followup, action, err := (&requestReceived{}).Execute(&metaData{
			presentation: &Presentation{},
		})
		require.NoError(t, err)
		require.Equal(t, &presentationSent{}, followup)
		require.NoError(t, action(nil))
	})

	t.Run("Without presentation", func(t *testing.T) {
		followup, action, err := (&requestReceived{}).Execute(&metaData{})
		require.NoError(t, err)
		require.Equal(t, &proposalSent{}, followup)
		require.NoError(t, action(nil))
	})
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
	require.True(t, st.CanTransitionTo(&proposalReceived{}))
	// states for Prover
	require.False(t, st.CanTransitionTo(&requestReceived{}))
	require.False(t, st.CanTransitionTo(&presentationSent{}))
	require.False(t, st.CanTransitionTo(&proposalSent{}))
}

func randomInboundMessage(t string) service.DIDCommMsgMap {
	return service.NewDIDCommMsgMap(struct {
		ID     string           `json:"@id"`
		Thread decorator.Thread `json:"~thread"`
		Type   string           `json:"@type"`
	}{
		ID:     uuid.New().String(),
		Thread: decorator.Thread{ID: uuid.New().String()},
		Type:   t,
	})
}

func TestRequestSent_Execute(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		followup, action, err := (&requestSent{}).Execute(&metaData{
			transitionalPayload: transitionalPayload{Msg: randomInboundMessage("")},
			request:             &RequestPresentation{},
		})
		require.NoError(t, err)
		require.Equal(t, &noOp{}, followup)
		require.NotNil(t, action)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		messenger := serviceMocks.NewMockMessenger(ctrl)
		messenger.EXPECT().ReplyTo(gomock.Any(), gomock.Any())

		require.NoError(t, action(messenger))
	})

	t.Run("Request presentation is absent", func(t *testing.T) {
		followup, action, err := (&requestSent{}).Execute(&metaData{
			transitionalPayload: transitionalPayload{Msg: randomInboundMessage("")},
		})
		require.EqualError(t, err, "request was not provided")
		require.Nil(t, followup)
		require.Nil(t, action)
	})

	t.Run("Success (outbound)", func(t *testing.T) {
		followup, action, err := (&requestSent{}).Execute(&metaData{})
		require.NoError(t, err)
		require.Equal(t, &noOp{}, followup)
		require.NotNil(t, action)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		messenger := serviceMocks.NewMockMessenger(ctrl)
		messenger.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any())

		require.NoError(t, action(messenger))
	})
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
	require.False(t, st.CanTransitionTo(&proposalReceived{}))
	// states for Prover
	require.False(t, st.CanTransitionTo(&requestReceived{}))
	require.False(t, st.CanTransitionTo(&presentationSent{}))
	require.False(t, st.CanTransitionTo(&proposalSent{}))
}

func TestPresentationSent_Execute(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		followup, action, err := (&presentationSent{}).Execute(&metaData{presentation: &Presentation{}})
		require.NoError(t, err)
		require.Equal(t, &noOp{}, followup)
		require.NotNil(t, action)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		messenger := serviceMocks.NewMockMessenger(ctrl)
		messenger.EXPECT().ReplyTo(gomock.Any(), gomock.Any())

		require.NoError(t, action(messenger))
	})

	t.Run("Presentation is absent", func(t *testing.T) {
		followup, action, err := (&presentationSent{}).Execute(&metaData{})
		require.EqualError(t, err, "presentation was not provided")
		require.Nil(t, followup)
		require.Nil(t, action)
	})
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
	require.False(t, st.CanTransitionTo(&proposalReceived{}))
	// states for Prover
	require.False(t, st.CanTransitionTo(&requestReceived{}))
	require.False(t, st.CanTransitionTo(&presentationSent{}))
	require.False(t, st.CanTransitionTo(&proposalSent{}))
}

func TestPresentationReceived_Execute(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		followup, action, err := (&presentationReceived{}).Execute(&metaData{presentation: &Presentation{}})
		require.NoError(t, err)
		require.Equal(t, &done{}, followup)
		require.NotNil(t, action)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		messenger := serviceMocks.NewMockMessenger(ctrl)
		messenger.EXPECT().ReplyTo(gomock.Any(), gomock.Any())

		require.NoError(t, action(messenger))
	})
}

func TestProposePresentationSent_CanTransitionTo(t *testing.T) {
	st := &proposalSent{}
	require.Equal(t, stateNameProposalSent, st.Name())
	// common states
	require.False(t, st.CanTransitionTo(&start{}))
	require.True(t, st.CanTransitionTo(&abandoning{}))
	require.False(t, st.CanTransitionTo(&done{}))
	require.False(t, st.CanTransitionTo(&noOp{}))
	// states for Verifier
	require.False(t, st.CanTransitionTo(&requestSent{}))
	require.False(t, st.CanTransitionTo(&presentationReceived{}))
	require.False(t, st.CanTransitionTo(&proposalReceived{}))
	// states for Prover
	require.True(t, st.CanTransitionTo(&requestReceived{}))
	require.False(t, st.CanTransitionTo(&presentationSent{}))
	require.False(t, st.CanTransitionTo(&proposalSent{}))
}

func TestProposePresentationSent_Execute(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		followup, action, err := (&proposalSent{}).Execute(&metaData{
			transitionalPayload: transitionalPayload{Msg: randomInboundMessage("")},
			proposePresentation: &ProposePresentation{},
		})
		require.NoError(t, err)
		require.Equal(t, &noOp{}, followup)
		require.NotNil(t, action)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		messenger := serviceMocks.NewMockMessenger(ctrl)
		messenger.EXPECT().ReplyTo(gomock.Any(), gomock.Any())

		require.NoError(t, action(messenger))
	})

	t.Run("Propose presentation is absent", func(t *testing.T) {
		followup, action, err := (&proposalSent{}).Execute(&metaData{
			transitionalPayload: transitionalPayload{Msg: randomInboundMessage("")},
		})
		require.EqualError(t, err, "propose-presentation was not provided")
		require.Nil(t, followup)
		require.Nil(t, action)
	})

	t.Run("Success (outbound)", func(t *testing.T) {
		followup, action, err := (&proposalSent{}).Execute(&metaData{})
		require.NoError(t, err)
		require.Equal(t, &noOp{}, followup)
		require.NotNil(t, action)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		messenger := serviceMocks.NewMockMessenger(ctrl)
		messenger.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any())

		require.NoError(t, action(messenger))
	})
}

func TestProposePresentationReceived_CanTransitionTo(t *testing.T) {
	st := &proposalReceived{}
	require.Equal(t, stateNameProposalReceived, st.Name())
	// common states
	require.False(t, st.CanTransitionTo(&start{}))
	require.True(t, st.CanTransitionTo(&abandoning{}))
	require.False(t, st.CanTransitionTo(&done{}))
	require.False(t, st.CanTransitionTo(&noOp{}))
	// states for Verifier
	require.True(t, st.CanTransitionTo(&requestSent{}))
	require.False(t, st.CanTransitionTo(&presentationReceived{}))
	require.False(t, st.CanTransitionTo(&proposalReceived{}))
	// states for Prover
	require.False(t, st.CanTransitionTo(&requestReceived{}))
	require.False(t, st.CanTransitionTo(&presentationSent{}))
	require.False(t, st.CanTransitionTo(&proposalSent{}))
}

func TestProposePresentationReceived_Execute(t *testing.T) {
	followup, action, err := (&proposalReceived{}).Execute(&metaData{})
	require.NoError(t, err)
	require.Equal(t, &requestSent{}, followup)
	require.NoError(t, action(nil))
}

func notTransition(t *testing.T, st state) {
	t.Helper()

	var allState = [...]state{
		// common states
		&start{}, &abandoning{}, &done{}, &noOp{},
		// states for Verifier
		&requestSent{}, &presentationReceived{}, &proposalReceived{},
		// states for Prover
		&requestReceived{}, &presentationSent{}, &proposalSent{},
	}

	for _, s := range allState {
		require.False(t, st.CanTransitionTo(s))
	}
}
