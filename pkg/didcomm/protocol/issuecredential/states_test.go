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

	allState := [...]state{
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
	followup, action, err := (&start{}).ExecuteInbound(&MetaData{})
	require.Contains(t, fmt.Sprintf("%v", err), "is not implemented yet")
	require.Nil(t, followup)
	require.Nil(t, action)
}

func TestStart_ExecuteOutbound(t *testing.T) {
	followup, action, err := (&start{}).ExecuteOutbound(&MetaData{})
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
		md := &MetaData{}
		md.Msg = service.NewDIDCommMsgMap(struct{}{})

		thID := uuid.New().String()
		md.Msg.SetID(thID)

		followup, action, err := (&abandoning{Code: codeInternalError}).ExecuteInbound(md)
		require.NoError(t, err)
		require.Equal(t, &done{}, followup)
		require.NotNil(t, action)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		messenger := serviceMocks.NewMockMessenger(ctrl)
		messenger.EXPECT().
			ReplyToNested(gomock.Any(), gomock.Any()).
			Do(func(msg service.DIDCommMsgMap, opts *service.NestedReplyOpts) error {
				r := &model.ProblemReport{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, codeInternalError, r.Description.Code)
				require.Equal(t, ProblemReportMsgTypeV2, r.Type)

				return nil
			})

		require.NoError(t, action(messenger))
	})

	t.Run("With invalid message", func(t *testing.T) {
		followup, action, err := (&abandoning{Code: codeInternalError}).ExecuteInbound(&MetaData{})
		require.EqualError(t, errors.Unwrap(err), service.ErrInvalidMessage.Error())
		require.Nil(t, followup)
		require.Nil(t, action)
	})

	t.Run("With custom error", func(t *testing.T) {
		md := &MetaData{err: customError{error: errors.New("error")}}
		md.Msg = service.NewDIDCommMsgMap(struct{}{})

		thID := uuid.New().String()
		md.Msg.SetID(thID)

		followup, action, err := (&abandoning{Code: codeInternalError}).ExecuteInbound(md)
		require.NoError(t, err)
		require.Equal(t, &done{}, followup)
		require.NotNil(t, action)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		messenger := serviceMocks.NewMockMessenger(ctrl)
		messenger.EXPECT().
			ReplyToNested(gomock.Any(), gomock.Any()).
			Do(func(msg service.DIDCommMsgMap, opts *service.NestedReplyOpts) error {
				r := &model.ProblemReport{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, codeRejectedError, r.Description.Code)
				require.Equal(t, ProblemReportMsgTypeV2, r.Type)

				return nil
			})

		require.NoError(t, action(messenger))
	})

	t.Run("Without code", func(t *testing.T) {
		md := &MetaData{}
		md.Msg = service.NewDIDCommMsgMap(struct{}{})
		md.Msg.SetID(uuid.New().String())

		followup, action, err := (&abandoning{}).ExecuteInbound(md)
		require.NoError(t, err)
		require.Equal(t, &done{}, followup)
		require.NotNil(t, action)

		require.NoError(t, action(nil))
	})
}

func TestAbandoning_ExecuteOutbound(t *testing.T) {
	followup, action, err := (&abandoning{}).ExecuteOutbound(&MetaData{})
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
	followup, action, err := (&done{}).ExecuteInbound(&MetaData{})
	require.NoError(t, err)
	require.Equal(t, &noOp{}, followup)
	require.NoError(t, action(nil))
}

func TestDone_ExecuteOutbound(t *testing.T) {
	followup, action, err := (&done{}).ExecuteOutbound(&MetaData{})
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
	followup, action, err := (&noOp{}).ExecuteInbound(&MetaData{})
	require.Contains(t, fmt.Sprintf("%v", err), "cannot execute no-op")
	require.Nil(t, followup)
	require.Nil(t, action)
}

func TestNoOp_ExecuteOutbound(t *testing.T) {
	followup, action, err := (&noOp{}).ExecuteOutbound(&MetaData{})
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
	followup, action, err := (&proposalReceived{}).ExecuteInbound(&MetaData{})
	require.NoError(t, err)
	require.Equal(t, &offerSent{}, followup)
	require.NotNil(t, action)
}

func TestProposalReceived_ExecuteOutbound(t *testing.T) {
	followup, action, err := (&proposalReceived{}).ExecuteOutbound(&MetaData{})
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
		followup, action, err := (&offerSent{}).ExecuteInbound(&MetaData{offerCredentialV2: &OfferCredentialV2{}})
		require.NoError(t, err)
		require.Equal(t, &noOp{}, followup)
		require.NotNil(t, action)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		messenger := serviceMocks.NewMockMessenger(ctrl)
		messenger.EXPECT().ReplyToMsg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())

		require.NoError(t, action(messenger))
	})

	t.Run("OfferCredential is absent", func(t *testing.T) {
		followup, action, err := (&offerSent{}).ExecuteInbound(&MetaData{})
		require.Contains(t, fmt.Sprintf("%v", err), "offer credential was not provided")
		require.Nil(t, followup)
		require.Nil(t, action)
	})
}

func TestOfferSent_ExecuteOutbound(t *testing.T) {
	followup, action, err := (&offerSent{}).ExecuteOutbound(&MetaData{})
	require.NoError(t, err)
	require.Equal(t, &noOp{}, followup)
	require.NotNil(t, action)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	messenger := serviceMocks.NewMockMessenger(ctrl)
	messenger.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())

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
		followup, action, err := (&requestReceived{}).ExecuteInbound(&MetaData{issueCredentialV2: &IssueCredentialV2{}})
		require.NoError(t, err)
		require.Equal(t, &credentialIssued{}, followup)
		require.NotNil(t, action)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		messenger := serviceMocks.NewMockMessenger(ctrl)
		messenger.EXPECT().ReplyToMsg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())

		require.NoError(t, action(messenger))
	})

	t.Run("IssueCredential is absent", func(t *testing.T) {
		followup, action, err := (&requestReceived{}).ExecuteInbound(&MetaData{})
		require.Contains(t, fmt.Sprintf("%v", err), "issue credential was not provided")
		require.Nil(t, followup)
		require.Nil(t, action)
	})
}

func TestRequestReceived_ExecuteOutbound(t *testing.T) {
	followup, action, err := (&requestReceived{}).ExecuteOutbound(&MetaData{})
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
	followup, action, err := (&credentialIssued{}).ExecuteInbound(&MetaData{})
	require.NoError(t, err)
	require.Equal(t, &noOp{}, followup)
	require.NoError(t, action(nil))
}

func TestCredentialIssued_ExecuteOutbound(t *testing.T) {
	followup, action, err := (&credentialIssued{}).ExecuteOutbound(&MetaData{})
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
		followup, action, err := (&proposalSent{}).ExecuteInbound(&MetaData{proposeCredentialV2: &ProposeCredentialV2{}})
		require.NoError(t, err)
		require.Equal(t, &noOp{}, followup)
		require.NotNil(t, action)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		messenger := serviceMocks.NewMockMessenger(ctrl)
		messenger.EXPECT().ReplyToMsg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())

		require.NoError(t, action(messenger))
	})

	t.Run("ProposeCredential is absent", func(t *testing.T) {
		followup, action, err := (&proposalSent{}).ExecuteInbound(&MetaData{})
		require.Contains(t, fmt.Sprintf("%v", err), "propose credential was not provided")
		require.Nil(t, followup)
		require.Nil(t, action)
	})
}

func TestProposalSent_ExecuteOutbound(t *testing.T) {
	followup, action, err := (&proposalSent{}).ExecuteOutbound(&MetaData{})
	require.NoError(t, err)
	require.Equal(t, &noOp{}, followup)
	require.NotNil(t, action)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	messenger := serviceMocks.NewMockMessenger(ctrl)
	messenger.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())

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

		followup, action, err := (&offerReceived{}).ExecuteInbound(&MetaData{
			proposeCredentialV2: &ProposeCredentialV2{},
			transitionalPayload: transitionalPayload{
				Action: Action{Msg: msg},
			},
		})
		require.NoError(t, err)
		require.Equal(t, &proposalSent{}, followup)
		require.NotNil(t, action)
	})

	t.Run("correct data (without ProposeCredential)", func(t *testing.T) {
		followup, action, err := (&offerReceived{}).ExecuteInbound(&MetaData{})
		require.NoError(t, err)
		require.Equal(t, &requestSent{}, followup)
		require.NotNil(t, action)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		messenger := serviceMocks.NewMockMessenger(ctrl)
		messenger.EXPECT().ReplyToMsg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())

		require.NoError(t, action(messenger))
	})

	t.Run("Decode error", func(t *testing.T) {
		followup, action, err := (&offerReceived{}).ExecuteInbound(&MetaData{
			transitionalPayload: transitionalPayload{
				Action: Action{Msg: service.DIDCommMsgMap{"@type": map[int]int{}}},
			},
		})

		require.Contains(t, fmt.Sprintf("%v", err), "got unconvertible type")
		require.Nil(t, followup)
		require.Nil(t, action)
	})
}

func TestOfferReceived_ExecuteOutbound(t *testing.T) {
	followup, action, err := (&offerReceived{}).ExecuteOutbound(&MetaData{})
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
	followup, action, err := (&requestSent{}).ExecuteInbound(&MetaData{})
	require.NoError(t, err)
	require.Equal(t, &noOp{}, followup)
	require.NoError(t, action(nil))
}

func TestRequestSent_ExecuteOutbound(t *testing.T) {
	followup, action, err := (&requestSent{}).ExecuteOutbound(&MetaData{})
	require.NoError(t, err)
	require.Equal(t, &noOp{}, followup)
	require.NotNil(t, action)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	messenger := serviceMocks.NewMockMessenger(ctrl)
	messenger.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())

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
		followup, action, err := (&credentialReceived{}).ExecuteInbound(&MetaData{issueCredentialV2: &IssueCredentialV2{}})
		require.NoError(t, err)
		require.Equal(t, &done{}, followup)
		require.NotNil(t, action)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		messenger := serviceMocks.NewMockMessenger(ctrl)
		messenger.EXPECT().ReplyToMsg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())

		require.NoError(t, action(messenger))
	})
}

func TestCredentialReceived_ExecuteOutbound(t *testing.T) {
	followup, action, err := (&credentialReceived{}).ExecuteOutbound(&MetaData{})
	require.Contains(t, fmt.Sprintf("%v", err), "is not implemented yet")
	require.Nil(t, followup)
	require.Nil(t, action)
}
