/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/client/introduce"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	protocol "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/introduce"
	mocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/client/introduce"
)

func TestNew(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		service := mocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)

		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)
	})

	t.Run("Create client (error)", func(t *testing.T) {
		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(nil, nil)

		cmd, err := New(provider)
		require.EqualError(t, err, "cannot create a client: cast service to Introduce Service failed")
		require.Nil(t, cmd)
	})

	t.Run("Register action event (error)", func(t *testing.T) {
		service := mocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(errors.New("error"))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)

		cmd, err := New(provider)
		require.EqualError(t, err, "register action event: error")
		require.Nil(t, cmd)
	})
}

func TestCommand_Actions(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	service := mocks.NewMockProtocolService(ctrl)
	service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil).AnyTimes()

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(gomock.Any()).Return(service, nil).AnyTimes()

	t.Run("Success", func(t *testing.T) {
		expected := ActionsResponse{Actions: []introduce.Action{{
			PIID: "ID1",
		}, {
			PIID: "ID2",
		}}}

		service.EXPECT().Actions().Return(toProtocolActions(expected.Actions), nil)

		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		require.NoError(t, cmd.Actions(&b, nil))

		response := ActionsResponse{}
		require.NoError(t, json.NewDecoder(&b).Decode(&response))
		require.Equal(t, expected, response)
	})

	t.Run("Error", func(t *testing.T) {
		service.EXPECT().Actions().Return(nil, errors.New("error message"))

		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		cmdErr := cmd.Actions(nil, nil)
		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "error message")
		require.Equal(t, ActionsErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})
}

func TestCommand_SendProposal(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	service := mocks.NewMockProtocolService(ctrl)
	service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil).AnyTimes()

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(gomock.Any()).Return(service, nil).AnyTimes()

	t.Run("Decode error", func(t *testing.T) {
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.SendProposal(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("No recipients", func(t *testing.T) {
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.SendProposal(&b, bytes.NewBufferString("{}"))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errTwoRecipients)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("SendProposal (error)", func(t *testing.T) {
		service := mocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().HandleOutbound(
			gomock.Any(), gomock.Any(),
			gomock.Any(),
		).Return(errors.New("error message"))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)

		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.SendProposal(&b, bytes.NewBufferString(`{"recipients":[{},{}]}`))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "error message")
		require.Equal(t, SendProposalErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
		service := mocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().HandleOutbound(gomock.Any(), gomock.Any(), gomock.Any()).Times(2)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)

		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		require.NoError(t, cmd.SendProposal(&b, bytes.NewBufferString(`{"recipients":[{},{}]}`)))
	})
}

func TestCommand_SendProposalWithOOBRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	service := mocks.NewMockProtocolService(ctrl)
	service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil).AnyTimes()

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(gomock.Any()).Return(service, nil).AnyTimes()

	t.Run("Decode error", func(t *testing.T) {
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.SendProposalWithOOBRequest(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty request", func(t *testing.T) {
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.SendProposalWithOOBRequest(&b, bytes.NewBufferString("{}"))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyRequest)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty recipient", func(t *testing.T) {
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.SendProposalWithOOBRequest(&b, bytes.NewBufferString(`{"request":{}}`))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyRecipient)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("SendProposalWithOOBRequest (error)", func(t *testing.T) {
		service := mocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().HandleOutbound(
			gomock.Any(), gomock.Any(),
			gomock.Any(),
		).Return(errors.New("error message"))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)

		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.SendProposalWithOOBRequest(&b, bytes.NewBufferString(`{"request":{},"recipient":{}}`))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "error message")
		require.Equal(t, SendProposalWithOOBRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
		service := mocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().HandleOutbound(gomock.Any(), gomock.Any(), gomock.Any())

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)

		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"request":{},"recipient":{}}`
		require.NoError(t, cmd.SendProposalWithOOBRequest(&b, bytes.NewBufferString(jsonPayload)))
	})
}

func TestCommand_SendRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	service := mocks.NewMockProtocolService(ctrl)
	service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil).AnyTimes()

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(gomock.Any()).Return(service, nil).AnyTimes()

	t.Run("Decode error", func(t *testing.T) {
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.SendRequest(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty MyDID", func(t *testing.T) {
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.SendRequest(&b, bytes.NewBufferString("{}"))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyMyDID)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty TheirDID", func(t *testing.T) {
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.SendRequest(&b, bytes.NewBufferString(`{"my_did":"my-did"}`))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyTheirDID)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty PleaseIntroduceTo", func(t *testing.T) {
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.SendRequest(&b, bytes.NewBufferString(`{"their_did":"their-did", "my_did":"my-did"}`))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyPleaseIntroduceTo)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("SendRequest (error)", func(t *testing.T) {
		service := mocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().HandleOutbound(
			gomock.Any(), gomock.Any(),
			gomock.Any(),
		).Return(errors.New("error message"))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)

		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"please_introduce_to":{}, "their_did":"their-did", "my_did":"my-did"}`
		cmdErr := cmd.SendRequest(&b, bytes.NewBufferString(jsonPayload))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "error message")
		require.Equal(t, SendRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
		service := mocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().HandleOutbound(gomock.Any(), gomock.Any(), gomock.Any())

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)

		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"please_introduce_to":{}, "their_did":"their-did", "my_did":"my-did"}`
		require.NoError(t, cmd.SendRequest(&b, bytes.NewBufferString(jsonPayload)))
	})
}

func TestCommand_AcceptProposalWithOOBRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	service := mocks.NewMockProtocolService(ctrl)
	service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil).AnyTimes()

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(gomock.Any()).Return(service, nil).AnyTimes()

	t.Run("Decode error", func(t *testing.T) {
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptProposalWithOOBRequest(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty PIID", func(t *testing.T) {
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptProposalWithOOBRequest(&b, bytes.NewBufferString("{}"))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyPIID)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty request", func(t *testing.T) {
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptProposalWithOOBRequest(&b, bytes.NewBufferString(`{"piid":"piid"}`))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyRequest)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("AcceptProposalWithOOBRequest (error)", func(t *testing.T) {
		service := mocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().ActionContinue(
			gomock.Any(), gomock.Any(),
		).Return(errors.New("error message"))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)

		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"piid":"piid","request":{}}`
		cmdErr := cmd.AcceptProposalWithOOBRequest(&b, bytes.NewBufferString(jsonPayload))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "error message")
		require.Equal(t, AcceptProposalWithOOBRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
		service := mocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().ActionContinue(gomock.Any(), gomock.Any())

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)

		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"piid":"piid","request":{}}`
		require.NoError(t, cmd.AcceptProposalWithOOBRequest(&b, bytes.NewBufferString(jsonPayload)))
	})
}

func TestCommand_AcceptRequestWithPublicOOBRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	service := mocks.NewMockProtocolService(ctrl)
	service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil).AnyTimes()

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(gomock.Any()).Return(service, nil).AnyTimes()

	t.Run("Decode error", func(t *testing.T) {
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptRequestWithPublicOOBRequest(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty PIID", func(t *testing.T) {
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptRequestWithPublicOOBRequest(&b, bytes.NewBufferString("{}"))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyPIID)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty request", func(t *testing.T) {
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptRequestWithPublicOOBRequest(&b, bytes.NewBufferString(`{"piid":"piid"}`))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyRequest)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty TO", func(t *testing.T) {
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptRequestWithPublicOOBRequest(&b, bytes.NewBufferString(`{"piid":"piid","request":{}}`))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyTo)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("AcceptRequestWithPublicOOBRequest (error)", func(t *testing.T) {
		service := mocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().ActionContinue(
			gomock.Any(), gomock.Any(),
		).Return(errors.New("error message"))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)

		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"piid":"piid","request":{},"to":{}}`
		cmdErr := cmd.AcceptRequestWithPublicOOBRequest(&b, bytes.NewBufferString(jsonPayload))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "error message")
		require.Equal(t, AcceptRequestWithPublicOOBRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
		service := mocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().ActionContinue(gomock.Any(), gomock.Any())

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)

		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"piid":"piid","request":{},"to":{}}`
		require.NoError(t, cmd.AcceptRequestWithPublicOOBRequest(&b, bytes.NewBufferString(jsonPayload)))
	})
}

func TestCommand_AcceptRequestWithRecipients(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	service := mocks.NewMockProtocolService(ctrl)
	service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil).AnyTimes()

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(gomock.Any()).Return(service, nil).AnyTimes()

	t.Run("Decode error", func(t *testing.T) {
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptRequestWithRecipients(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty PIID", func(t *testing.T) {
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptRequestWithRecipients(&b, bytes.NewBufferString("{}"))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyPIID)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty recipient", func(t *testing.T) {
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptRequestWithRecipients(&b, bytes.NewBufferString(`{"piid":"piid"}`))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyRecipient)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty TO", func(t *testing.T) {
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptRequestWithRecipients(&b, bytes.NewBufferString(`{"piid":"piid","recipient":{}}`))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyTo)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("AcceptRequestWithRecipients (error)", func(t *testing.T) {
		service := mocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().ActionContinue(
			gomock.Any(), gomock.Any(),
		).Return(errors.New("error message"))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)

		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"piid":"piid","recipient":{},"to":{}}`
		cmdErr := cmd.AcceptRequestWithRecipients(&b, bytes.NewBufferString(jsonPayload))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "error message")
		require.Equal(t, AcceptRequestWithRecipientsErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
		service := mocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().ActionContinue(gomock.Any(), gomock.Any())

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)

		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"piid":"piid","recipient":{},"to":{}}`
		require.NoError(t, cmd.AcceptRequestWithRecipients(&b, bytes.NewBufferString(jsonPayload)))
	})
}

func TestCommand_DeclineProposal(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	service := mocks.NewMockProtocolService(ctrl)
	service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil).AnyTimes()

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(gomock.Any()).Return(service, nil).AnyTimes()

	t.Run("Decode error", func(t *testing.T) {
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.DeclineProposal(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty PIID", func(t *testing.T) {
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.DeclineProposal(&b, bytes.NewBufferString("{}"))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyPIID)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("DeclineProposal (error)", func(t *testing.T) {
		service := mocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().ActionStop(
			gomock.Any(), gomock.Any(),
		).Return(errors.New("error message"))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)

		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"piid":"piid"}`
		cmdErr := cmd.DeclineProposal(&b, bytes.NewBufferString(jsonPayload))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "error message")
		require.Equal(t, DeclineProposalErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
		service := mocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().ActionStop(gomock.Any(), gomock.Any())

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)

		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"piid":"piid"}`
		require.NoError(t, cmd.DeclineProposal(&b, bytes.NewBufferString(jsonPayload)))
	})
}

func TestCommand_DeclineRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	service := mocks.NewMockProtocolService(ctrl)
	service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil).AnyTimes()

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(gomock.Any()).Return(service, nil).AnyTimes()

	t.Run("Decode error", func(t *testing.T) {
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.DeclineRequest(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty PIID", func(t *testing.T) {
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.DeclineRequest(&b, bytes.NewBufferString("{}"))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyPIID)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("DeclineRequest (error)", func(t *testing.T) {
		service := mocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().ActionStop(
			gomock.Any(), gomock.Any(),
		).Return(errors.New("error message"))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)

		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"piid":"piid"}`
		cmdErr := cmd.DeclineRequest(&b, bytes.NewBufferString(jsonPayload))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "error message")
		require.Equal(t, DeclineRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
		service := mocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().ActionStop(gomock.Any(), gomock.Any())

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)

		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"piid":"piid"}`
		require.NoError(t, cmd.DeclineRequest(&b, bytes.NewBufferString(jsonPayload)))
	})
}

func toProtocolActions(actions []introduce.Action) []protocol.Action {
	res := make([]protocol.Action, len(actions))
	for i, action := range actions {
		res[i] = protocol.Action(action)
	}

	return res
}
