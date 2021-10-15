/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofband

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	protocol "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"
	mocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/client/outofband"
	mocknotifier "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/controller/webnotifier"
)

const (
	PIID        = "id"
	label       = "label"
	reason      = "reason"
	jsonPayload = `{"piid":"` + PIID + `","label":"` + label + `","reason":"` + reason + `"}`
)

func TestNew(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		service := mocks.NewMockOobService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().MediaTypeProfiles().AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)
	})

	t.Run("Create client (error)", func(t *testing.T) {
		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(nil, nil)

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		const errMsg = "cannot create a client: failed to cast service out-of-band as a dependency"
		require.EqualError(t, err, errMsg)
		require.Nil(t, cmd)
	})

	t.Run("Register action event (error)", func(t *testing.T) {
		service := mocks.NewMockOobService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(errors.New("error"))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().MediaTypeProfiles().AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.EqualError(t, err, "register action event: error")
		require.Nil(t, cmd)
	})

	t.Run("Register msg event (error)", func(t *testing.T) {
		service := mocks.NewMockOobService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(errors.New("error"))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().MediaTypeProfiles().AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.EqualError(t, err, "register msg event: error")
		require.Nil(t, cmd)
	})
}

func TestCommand_CreateInvitation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	service := mocks.NewMockOobService(ctrl)
	service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil).AnyTimes()
	service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil).AnyTimes()

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(gomock.Any()).Return(service, nil).AnyTimes()
	provider.EXPECT().MediaTypeProfiles().AnyTimes()

	t.Run("Decode error", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.CreateInvitation(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("CreateInvitation (error)", func(t *testing.T) {
		service := mocks.NewMockOobService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().SaveInvitation(gomock.Any()).Return(errors.New("error message"))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().MediaTypeProfiles().AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.CreateInvitation(&b, bytes.NewBufferString(`{"service":["did:example:123"]}`))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "error message")
		require.Equal(t, CreateInvitationErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
		service := mocks.NewMockOobService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().SaveInvitation(gomock.Any()).Return(nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().MediaTypeProfiles().AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer

		expected := CreateInvitationArgs{
			Label:     "label",
			Goal:      "goal",
			GoalCode:  "goal_code",
			Service:   []interface{}{"did:example:123"},
			Protocols: []string{"s1"},
		}
		args, err := json.Marshal(expected)
		require.NoError(t, err)
		require.NoError(t, cmd.CreateInvitation(&b, bytes.NewBuffer(args)))
		res := CreateInvitationResponse{}
		require.NoError(t, json.Unmarshal(b.Bytes(), &res))

		require.Equal(t, expected.Label, res.Invitation.Label)
		require.Equal(t, expected.Goal, res.Invitation.Goal)
		require.Equal(t, expected.GoalCode, res.Invitation.GoalCode)
		require.Equal(t, expected.Service, res.Invitation.Services)
		require.Equal(t, expected.Protocols, res.Invitation.Protocols)
	})
}

func TestCommand_AcceptInvitation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	service := mocks.NewMockOobService(ctrl)
	service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil).AnyTimes()
	service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil).AnyTimes()

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(gomock.Any()).Return(service, nil).AnyTimes()
	provider.EXPECT().MediaTypeProfiles().AnyTimes()

	t.Run("Decode error", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptInvitation(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("No request", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptInvitation(&b, bytes.NewBufferString("{}"))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyRequest)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("No label", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptInvitation(&b, bytes.NewBufferString(`{"invitation":{}}`))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyMyLabel)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("AcceptInvitation (error)", func(t *testing.T) {
		service := mocks.NewMockOobService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().AcceptInvitation(gomock.Any(), gomock.Any()).
			Return("", errors.New("error message"))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().MediaTypeProfiles().AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptInvitation(&b, bytes.NewBufferString(`{"invitation":{},"my_label":"label"}`))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "error message")
		require.Equal(t, AcceptInvitationErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
		const connID = "conn-id"
		service := mocks.NewMockOobService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().AcceptInvitation(gomock.Any(), gomock.Any()).Return(connID, nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().MediaTypeProfiles().AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		require.NoError(t, cmd.AcceptInvitation(&b, bytes.NewBufferString(`{"invitation":{},"my_label":"label"}`)))
		res := AcceptInvitationResponse{}
		require.NoError(t, json.Unmarshal(b.Bytes(), &res))
		require.Equal(t, connID, res.ConnectionID)
	})
}

func TestCommand_Actions(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	service := mocks.NewMockOobService(ctrl)
	service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil).AnyTimes()
	service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil).AnyTimes()

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(gomock.Any()).Return(service, nil).AnyTimes()
	provider.EXPECT().MediaTypeProfiles().AnyTimes()

	t.Run("Success", func(t *testing.T) {
		expected := ActionsResponse{Actions: []outofband.Action{{
			PIID: "ID1",
		}, {
			PIID: "ID2",
		}}}

		service.EXPECT().Actions().Return(toProtocolActions(expected.Actions), nil)

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		require.NoError(t, cmd.Actions(&b, nil))

		response := ActionsResponse{}
		require.NoError(t, json.NewDecoder(&b).Decode(&response))
		require.Equal(t, expected, response)
	})

	t.Run("Error", func(t *testing.T) {
		service.EXPECT().Actions().Return(nil, errors.New("some error message"))

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		cmdErr := cmd.Actions(nil, nil)
		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "some error message")
		require.Equal(t, ActionsErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})
}

func TestCommand_ActionStop(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	service := mocks.NewMockOobService(ctrl)
	service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil).AnyTimes()
	service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil).AnyTimes()

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(gomock.Any()).Return(service, nil).AnyTimes()
	provider.EXPECT().MediaTypeProfiles().AnyTimes()

	t.Run("Decode error", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.ActionStop(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty PIID", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.ActionStop(&b, bytes.NewBufferString("{}"))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyPIID)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("ActionStop (error)", func(t *testing.T) {
		service := mocks.NewMockOobService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().ActionStop(PIID, errors.New(reason)).Return(errors.New("some error message"))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().MediaTypeProfiles().AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.ActionStop(&b, bytes.NewBufferString(jsonPayload))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "some error message")
		require.Equal(t, ActionStopErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
		service := mocks.NewMockOobService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().ActionStop(PIID, errors.New(reason))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().MediaTypeProfiles().AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		require.NoError(t, cmd.ActionStop(&b, bytes.NewBufferString(jsonPayload)))
	})
}

func TestCommand_ActionContinue(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	service := mocks.NewMockOobService(ctrl)
	service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil).AnyTimes()
	service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil).AnyTimes()

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(gomock.Any()).Return(service, nil).AnyTimes()
	provider.EXPECT().MediaTypeProfiles().AnyTimes()

	t.Run("Decode error", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.ActionContinue(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty PIID", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.ActionContinue(&b, bytes.NewBufferString("{}"))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyPIID)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("ActionContinue (error)", func(t *testing.T) {
		opt := &outofband.EventOptions{Label: label}

		service := mocks.NewMockOobService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().ActionContinue(PIID, opt).Return(errors.New("some error message"))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().MediaTypeProfiles().AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.ActionContinue(&b, bytes.NewBufferString(jsonPayload))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "some error message")
		require.Equal(t, ActionContinueErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
		opt := &outofband.EventOptions{Label: label}

		service := mocks.NewMockOobService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().ActionContinue(PIID, opt)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().MediaTypeProfiles().AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		require.NoError(t, cmd.ActionContinue(&b, bytes.NewBufferString(jsonPayload)))
	})
}

func TestCommand_GetHandlers(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	service := mocks.NewMockOobService(ctrl)
	service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
	service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(gomock.Any()).Return(service, nil)
	provider.EXPECT().MediaTypeProfiles().AnyTimes()
	cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
	require.NoError(t, err)
	require.Equal(t, 5, len(cmd.GetHandlers()))
}

func toProtocolActions(actions []outofband.Action) []protocol.Action {
	res := make([]protocol.Action, len(actions))
	for i, action := range actions {
		res[i] = protocol.Action(action)
	}

	return res
}
