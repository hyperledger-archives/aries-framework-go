/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofbandv2

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofbandv2"
	mocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/client/outofbandv2"
)

func TestNew(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		service := mocks.NewMockOobService(ctrl)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().MediaTypeProfiles().AnyTimes()

		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)
	})

	t.Run("Create client (error)", func(t *testing.T) {
		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(nil, nil)

		cmd, err := New(provider)
		const errMsg = "cannot create a client: failed to cast service out-of-band/2.0 as a dependency"
		require.EqualError(t, err, errMsg)
		require.Nil(t, cmd)
	})
}

func TestCommand_CreateInvitation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	service := mocks.NewMockOobService(ctrl)
	service.EXPECT().SaveInvitation(gomock.Any()).Return(nil).AnyTimes()

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(gomock.Any()).Return(service, nil).AnyTimes()
	provider.EXPECT().MediaTypeProfiles().AnyTimes()

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

	t.Run("Success", func(t *testing.T) {
		service := mocks.NewMockOobService(ctrl)
		service.EXPECT().SaveInvitation(gomock.Any()).Return(nil).AnyTimes()

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().MediaTypeProfiles().AnyTimes()

		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer

		expected := CreateInvitationArgs{
			Label: "label",
			Body: outofbandv2.InvitationBody{
				Goal:     "goal",
				GoalCode: "goal_code",
			},
		}
		args, err := json.Marshal(expected)
		require.NoError(t, err)
		require.NoError(t, cmd.CreateInvitation(&b, bytes.NewBuffer(args)))
		res := CreateInvitationResponse{}
		require.NoError(t, json.Unmarshal(b.Bytes(), &res))

		require.Equal(t, expected.Label, res.Invitation.Label)
		require.Equal(t, expected.Body.Goal, res.Invitation.Body.Goal)
		require.Equal(t, expected.Body.GoalCode, res.Invitation.Body.GoalCode)
	})

	t.Run("client error", func(t *testing.T) {
		expectErr := fmt.Errorf("expected error")

		service := mocks.NewMockOobService(ctrl)
		service.EXPECT().SaveInvitation(gomock.Any()).Return(expectErr).AnyTimes()

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().MediaTypeProfiles().AnyTimes()

		cmd, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer

		expected := CreateInvitationArgs{
			Label: "label",
			Body: outofbandv2.InvitationBody{
				Goal:     "goal",
				GoalCode: "goal_code",
			},
		}
		args, err := json.Marshal(expected)
		require.NoError(t, err)

		cmdErr := cmd.CreateInvitation(&b, bytes.NewBuffer(args))
		require.Error(t, cmdErr)
		require.Equal(t, CreateInvitationErrorCode, cmdErr.Code())
	})
}

func TestCommand_AcceptInvitation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	service := mocks.NewMockOobService(ctrl)

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(gomock.Any()).Return(service, nil).AnyTimes()
	provider.EXPECT().MediaTypeProfiles().AnyTimes()

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
		service.EXPECT().AcceptInvitation(gomock.Any()).Return("", errors.New("error message"))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().MediaTypeProfiles().AnyTimes()

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
		service := mocks.NewMockOobService(ctrl)
		connID := "123"
		service.EXPECT().AcceptInvitation(gomock.Any()).Return(connID, nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().MediaTypeProfiles().AnyTimes()

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

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(gomock.Any()).Return(service, nil)
	provider.EXPECT().MediaTypeProfiles().AnyTimes()
	cmd, err := New(provider)
	require.NoError(t, err)
	require.Equal(t, 2, len(cmd.GetHandlers()))
}
