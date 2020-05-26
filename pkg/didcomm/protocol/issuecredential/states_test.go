/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import (
	"errors"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	serviceMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/common/service"
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
	t.Run("With code", func(t *testing.T) {
		md := &metaData{}
		md.Msg = service.NewDIDCommMsgMap(struct{}{})

		thID := uuid.New().String()
		require.NoError(t, md.Msg.SetID(thID))

		followup, action, err := (&abandoning{Code: codeInternalError}).ExecuteInbound(md)
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

	t.Run("With invalid message", func(t *testing.T) {
		followup, action, err := (&abandoning{Code: codeInternalError}).ExecuteInbound(&metaData{})
		require.EqualError(t, errors.Unwrap(err), service.ErrInvalidMessage.Error())
		require.Nil(t, followup)
		require.Nil(t, action)
	})

	t.Run("With custom error", func(t *testing.T) {
		md := &metaData{err: customError{error: errors.New("error")}}
		md.Msg = service.NewDIDCommMsgMap(struct{}{})

		thID := uuid.New().String()
		require.NoError(t, md.Msg.SetID(thID))

		followup, action, err := (&abandoning{Code: codeInternalError}).ExecuteInbound(md)
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

	t.Run("Without code", func(t *testing.T) {
		md := &metaData{}
		md.Msg = service.NewDIDCommMsgMap(struct{}{})

		require.NoError(t, md.Msg.SetID(uuid.New().String()))

		followup, action, err := (&abandoning{}).ExecuteInbound(md)
		require.NoError(t, err)
		require.Equal(t, &done{}, followup)
		require.NotNil(t, action)

		require.NoError(t, action(nil))
	})
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
	require.NoError(t, err)
	require.Equal(t, &offerSent{}, followup)
	require.NotNil(t, action)
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
	t.Run("Success", func(t *testing.T) {
		followup, action, err := (&offerSent{}).ExecuteInbound(&metaData{offerCredential: &OfferCredential{}})
		require.NoError(t, err)
		require.Equal(t, &noOp{}, followup)
		require.NotNil(t, action)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		messenger := serviceMocks.NewMockMessenger(ctrl)
		messenger.EXPECT().ReplyTo(gomock.Any(), gomock.Any())

		require.NoError(t, action(messenger))
	})

	t.Run("OfferCredential is absent", func(t *testing.T) {
		followup, action, err := (&offerSent{}).ExecuteInbound(&metaData{})
		require.Contains(t, fmt.Sprintf("%v", err), "offer credential was not provided")
		require.Nil(t, followup)
		require.Nil(t, action)
	})
}

func TestOfferSent_ExecuteOutbound(t *testing.T) {
	followup, action, err := (&offerSent{}).ExecuteOutbound(&metaData{})
	require.NoError(t, err)
	require.Equal(t, &noOp{}, followup)
	require.NotNil(t, action)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	messenger := serviceMocks.NewMockMessenger(ctrl)
	messenger.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any())

	require.NoError(t, action(messenger))
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
	t.Run("Successes", func(t *testing.T) {
		followup, action, err := (&requestReceived{}).ExecuteInbound(&metaData{issueCredential: &IssueCredential{}})
		require.NoError(t, err)
		require.Equal(t, &credentialIssued{}, followup)
		require.NotNil(t, action)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		messenger := serviceMocks.NewMockMessenger(ctrl)
		messenger.EXPECT().ReplyTo(gomock.Any(), gomock.Any())

		require.NoError(t, action(messenger))
	})

	t.Run("IssueCredential is absent", func(t *testing.T) {
		followup, action, err := (&requestReceived{}).ExecuteInbound(&metaData{})
		require.Contains(t, fmt.Sprintf("%v", err), "issue credential was not provided")
		require.Nil(t, followup)
		require.Nil(t, action)
	})
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
	require.NoError(t, err)
	require.Equal(t, &noOp{}, followup)
	require.NoError(t, action(nil))
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
	t.Run("Successes", func(t *testing.T) {
		followup, action, err := (&proposalSent{}).ExecuteInbound(&metaData{proposeCredential: &ProposeCredential{}})
		require.NoError(t, err)
		require.Equal(t, &noOp{}, followup)
		require.NotNil(t, action)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		messenger := serviceMocks.NewMockMessenger(ctrl)
		messenger.EXPECT().ReplyTo(gomock.Any(), gomock.Any())

		require.NoError(t, action(messenger))
	})

	t.Run("ProposeCredential is absent", func(t *testing.T) {
		followup, action, err := (&proposalSent{}).ExecuteInbound(&metaData{})
		require.Contains(t, fmt.Sprintf("%v", err), "propose credential was not provided")
		require.Nil(t, followup)
		require.Nil(t, action)
	})
}

func TestProposalSent_ExecuteOutbound(t *testing.T) {
	followup, action, err := (&proposalSent{}).ExecuteOutbound(&metaData{})
	require.NoError(t, err)
	require.Equal(t, &noOp{}, followup)
	require.NotNil(t, action)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	messenger := serviceMocks.NewMockMessenger(ctrl)
	messenger.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any())

	require.NoError(t, action(messenger))
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
	t.Run("incorrect data (with ProposeCredential)", func(t *testing.T) {
		msg := service.NewDIDCommMsgMap(struct{}{})

		followup, action, err := (&offerReceived{}).ExecuteInbound(&metaData{
			proposeCredential:   &ProposeCredential{},
			transitionalPayload: transitionalPayload{Msg: msg},
		})
		require.NoError(t, err)
		require.Equal(t, &proposalSent{}, followup)
		require.NotNil(t, action)
	})

	t.Run("correct data (without ProposeCredential)", func(t *testing.T) {
		followup, action, err := (&offerReceived{}).ExecuteInbound(&metaData{})
		require.NoError(t, err)
		require.Equal(t, &requestSent{}, followup)
		require.NotNil(t, action)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		messenger := serviceMocks.NewMockMessenger(ctrl)
		messenger.EXPECT().ReplyTo(gomock.Any(), gomock.Any())

		require.NoError(t, action(messenger))
	})

	t.Run("Decode error", func(t *testing.T) {
		followup, action, err := (&offerReceived{}).ExecuteInbound(&metaData{
			transitionalPayload: transitionalPayload{
				Msg: service.DIDCommMsgMap{"@type": map[int]int{}},
			},
		})

		require.Contains(t, fmt.Sprintf("%v", err), "got unconvertible type")
		require.Nil(t, followup)
		require.Nil(t, action)
	})
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
	require.NoError(t, err)
	require.Equal(t, &noOp{}, followup)
	require.NoError(t, action(nil))
}

func TestRequestSent_ExecuteOutbound(t *testing.T) {
	followup, action, err := (&requestSent{}).ExecuteOutbound(&metaData{})
	require.NoError(t, err)
	require.Equal(t, &noOp{}, followup)
	require.NotNil(t, action)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	messenger := serviceMocks.NewMockMessenger(ctrl)
	messenger.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any())

	require.NoError(t, action(messenger))
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
	t.Run("Successes", func(t *testing.T) {
		followup, action, err := (&credentialReceived{}).ExecuteInbound(&metaData{issueCredential: &IssueCredential{}})
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

func TestCredentialReceived_ExecuteOutbound(t *testing.T) {
	followup, action, err := (&credentialReceived{}).ExecuteOutbound(&metaData{})
	require.Contains(t, fmt.Sprintf("%v", err), "is not implemented yet")
	require.Nil(t, followup)
	require.Nil(t, action)
}
