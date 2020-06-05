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
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	didservice "github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	mocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/client/outofband"
)

func TestNew(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		service := mocks.NewMockOobService(ctrl)
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
		const errMsg = "cannot create a client: failed to cast service out-of-band as a dependency"
		require.EqualError(t, err, errMsg)
		require.Nil(t, cmd)
	})

	t.Run("Register action event (error)", func(t *testing.T) {
		service := mocks.NewMockOobService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(errors.New("error"))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)

		cmd, err := New(provider)
		require.EqualError(t, err, "register action event: error")
		require.Nil(t, cmd)
	})

	t.Run("Execute action event", func(t *testing.T) {
		var done = make(chan struct{})
		service := mocks.NewMockOobService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Do(func(ch chan<- didservice.DIDCommAction) {
			go func() {
				ch <- didservice.DIDCommAction{Continue: func(_ interface{}) {
					done <- struct{}{}
				}}
			}()
		}).Return(nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)

		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})
}

func TestCommand_CreateRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	service := mocks.NewMockOobService(ctrl)
	service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil).AnyTimes()

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(gomock.Any()).Return(service, nil).AnyTimes()

	t.Run("Decode error", func(t *testing.T) {
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.CreateRequest(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("No attachments", func(t *testing.T) {
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.CreateRequest(&b, bytes.NewBufferString("{}"))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errOneAttachmentMustBeProvided)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("CreateRequest (error)", func(t *testing.T) {
		service := mocks.NewMockOobService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().SaveRequest(gomock.Any()).Return(errors.New("error message"))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.CreateRequest(&b, bytes.NewBufferString(`{"service":["s1"], "attachments":[{}]}`))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "error message")
		require.Equal(t, CreateRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
		service := mocks.NewMockOobService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().SaveRequest(gomock.Any()).Return(nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer

		expected := CreateRequestArgs{
			Label:       "label",
			Goal:        "goal",
			GoalCode:    "goal_code",
			Service:     []interface{}{"s1"},
			Attachments: []*decorator.Attachment{{}},
		}
		args, err := json.Marshal(expected)
		require.NoError(t, err)
		require.NoError(t, cmd.CreateRequest(&b, bytes.NewBuffer(args)))
		res := CreateRequestResponse{}
		require.NoError(t, json.Unmarshal(b.Bytes(), &res))

		require.Equal(t, expected.Label, res.Request.Label)
		require.Equal(t, expected.Goal, res.Request.Goal)
		require.Equal(t, expected.GoalCode, res.Request.GoalCode)
		require.Equal(t, expected.Service, res.Request.Service)
		require.Equal(t, expected.Attachments, res.Request.Requests)
	})
}

func TestCommand_CreateInvitation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	service := mocks.NewMockOobService(ctrl)
	service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil).AnyTimes()

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(gomock.Any()).Return(service, nil).AnyTimes()

	t.Run("Decode error", func(t *testing.T) {
		cmd, err := New(provider)
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
		service.EXPECT().SaveInvitation(gomock.Any()).Return(errors.New("error message"))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.CreateInvitation(&b, bytes.NewBufferString(`{"service":["s1"]}`))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "error message")
		require.Equal(t, CreateInvitationErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
		service := mocks.NewMockOobService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().SaveInvitation(gomock.Any()).Return(nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer

		expected := CreateInvitationArgs{
			Label:     "label",
			Goal:      "goal",
			GoalCode:  "goal_code",
			Service:   []interface{}{"s1"},
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
		require.Equal(t, expected.Service, res.Invitation.Service)
		require.Equal(t, expected.Protocols, res.Invitation.Protocols)
	})
}

func TestCommand_AcceptRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	service := mocks.NewMockOobService(ctrl)
	service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil).AnyTimes()

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(gomock.Any()).Return(service, nil).AnyTimes()

	t.Run("Decode error", func(t *testing.T) {
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptRequest(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("No request", func(t *testing.T) {
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptRequest(&b, bytes.NewBufferString("{}"))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyRequest)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("No label", func(t *testing.T) {
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptRequest(&b, bytes.NewBufferString(`{"request":{}}`))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyMyLabel)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("AcceptRequest (error)", func(t *testing.T) {
		service := mocks.NewMockOobService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().AcceptRequest(gomock.Any(), gomock.Any()).Return("", errors.New("error message"))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptRequest(&b, bytes.NewBufferString(`{"request":{},"my_label":"label"}`))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "error message")
		require.Equal(t, AcceptRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
		const connID = "conn-id"
		service := mocks.NewMockOobService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().AcceptRequest(gomock.Any(), gomock.Any()).Return(connID, nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		require.NoError(t, cmd.AcceptRequest(&b, bytes.NewBufferString(`{"request":{},"my_label":"label"}`)))
		res := AcceptRequestResponse{}
		require.NoError(t, json.Unmarshal(b.Bytes(), &res))
		require.Equal(t, connID, res.ConnectionID)
	})
}

func TestCommand_AcceptInvitation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	service := mocks.NewMockOobService(ctrl)
	service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil).AnyTimes()

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(gomock.Any()).Return(service, nil).AnyTimes()

	t.Run("Decode error", func(t *testing.T) {
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptInvitation(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("No request", func(t *testing.T) {
		cmd, err := New(provider)
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
		cmd, err := New(provider)
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
		service.EXPECT().AcceptInvitation(gomock.Any(), gomock.Any()).Return("", errors.New("error message"))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		cmd, err := New(provider)
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
		service.EXPECT().AcceptInvitation(gomock.Any(), gomock.Any()).Return(connID, nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		require.NoError(t, cmd.AcceptInvitation(&b, bytes.NewBufferString(`{"invitation":{},"my_label":"label"}`)))
		res := AcceptInvitationResponse{}
		require.NoError(t, json.Unmarshal(b.Bytes(), &res))
		require.Equal(t, connID, res.ConnectionID)
	})
}

func TestCommand_GetHandlers(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	service := mocks.NewMockOobService(ctrl)
	service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(gomock.Any()).Return(service, nil)
	cmd, err := New(provider)
	require.NoError(t, err)
	require.Equal(t, 4, len(cmd.GetHandlers()))
}
