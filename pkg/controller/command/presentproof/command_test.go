/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/client/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	didcomm "github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	protocol "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	clientmocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/client/presentproof"
	mocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/controller/command/presentproof"
	mocknotifier "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/controller/webnotifier"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
)

const jsonPayload = `{"piid":"id"}`

func TestNew(t *testing.T) {
	t.Parallel()

	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().ConnectionLookup().Return(nil).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		handlers := cmd.GetHandlers()
		require.NotEmpty(t, handlers)
	})

	t.Run("Create client (error)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(nil, nil)
		provider.EXPECT().ConnectionLookup().Return(nil).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.EqualError(t, err, "cannot create a client: cast service to presentproof service failed")
		require.Nil(t, cmd)
	})

	t.Run("Register action event (error)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(errors.New("error"))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().ConnectionLookup().Return(nil).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.EqualError(t, err, "register action event: error")
		require.Nil(t, cmd)
	})

	t.Run("Register msg event (error)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(errors.New("error"))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().ConnectionLookup().Return(nil).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.EqualError(t, err, "register msg event: error")
		require.Nil(t, cmd)
	})
}

func TestCommand_SendRequestPresentation(t *testing.T) {
	t.Parallel()

	t.Run("Decode error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		provider := createProvider(ctrl)

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.SendRequestPresentation(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty MyDID", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		provider := createProvider(ctrl)

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.SendRequestPresentation(&b, bytes.NewBufferString("{}"))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyMyDID)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty TheirDID", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		provider := createProvider(ctrl)

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.SendRequestPresentation(&b, bytes.NewBufferString(`{"my_did":"id"}`))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyTheirDID)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty RequestPresentation", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		provider := createProvider(ctrl)

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.SendRequestPresentation(&b, bytes.NewBufferString(`{"my_did":"id","their_did":"id"}`))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyRequestPresentation)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("missing connection", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)

		mockConnRec := mockConnectionRecorder(t)

		provider.EXPECT().ConnectionLookup().Return(mockConnRec.Lookup).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"my_did":"id","their_did":"id","request_presentation":{}}`
		cmdErr := cmd.SendRequestPresentation(&b, bytes.NewBufferString(jsonPayload))
		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Contains(t, cmdErr.Error(), errNoConnectionForDIDs)
	})

	t.Run("SendRequestPresentation (error)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().HandleOutbound(
			gomock.Any(), gomock.Any(), gomock.Any(),
		).Return("", errors.New("some error message"))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)

		mockConnRec := mockConnectionRecorder(t, connection.Record{
			MyDID:    "id",
			TheirDID: "id",
		})

		provider.EXPECT().ConnectionLookup().Return(mockConnRec.Lookup).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"my_did":"id","their_did":"id","request_presentation":{}}`
		cmdErr := cmd.SendRequestPresentation(&b, bytes.NewBufferString(jsonPayload))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "some error message")
		require.Equal(t, SendRequestPresentationErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().HandleOutbound(gomock.Any(), gomock.Any(), gomock.Any())

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)

		mockConnRec := mockConnectionRecorder(t, connection.Record{
			MyDID:    "id",
			TheirDID: "id",
		})

		provider.EXPECT().ConnectionLookup().Return(mockConnRec.Lookup).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"my_did":"id","their_did":"id","request_presentation":{}}`
		require.NoError(t, cmd.SendRequestPresentation(&b, bytes.NewBufferString(jsonPayload)))
	})

	t.Run("Success - with connection ID parameter", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().HandleOutbound(gomock.Any(), gomock.Any(), gomock.Any())

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)

		connID := uuid.New().String()

		mockConnRec := mockConnectionRecorder(t, connection.Record{
			ConnectionID: connID,
			MyDID:        "id",
			TheirDID:     "id",
		})

		provider.EXPECT().ConnectionLookup().Return(mockConnRec.Lookup).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		payload := fmt.Sprintf(`{"connection_id":"%s","request_presentation":{}}`, connID)
		require.NoError(t, cmd.SendRequestPresentation(&b, bytes.NewBufferString(payload)))
	})

	t.Run("Success (v3)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().HandleOutbound(gomock.Any(), gomock.Any(), gomock.Any())

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)

		mockConnRec := mockConnectionRecorder(t, connection.Record{
			MyDID:          "id",
			TheirDID:       "id",
			DIDCommVersion: didcomm.V2,
		})

		provider.EXPECT().ConnectionLookup().Return(mockConnRec.Lookup).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"my_did":"id","their_did":"id","request_presentation":{}}`
		require.NoError(t, cmd.SendRequestPresentation(&b, bytes.NewBufferString(jsonPayload)))
	})
}

func TestCommand_SendProposePresentation(t *testing.T) {
	t.Parallel()

	t.Run("Decode error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		provider := createProvider(ctrl)

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.SendProposePresentation(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty MyDID", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		provider := createProvider(ctrl)

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.SendProposePresentation(&b, bytes.NewBufferString("{}"))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyMyDID)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty TheirDID", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		provider := createProvider(ctrl)

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.SendProposePresentation(&b, bytes.NewBufferString(`{"my_did":"id"}`))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyTheirDID)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty ProposePresentation", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		provider := createProvider(ctrl)

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.SendProposePresentation(&b, bytes.NewBufferString(`{"my_did":"id","their_did":"id"}`))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyProposePresentation)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("missing connection", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)

		mockConnRec := mockConnectionRecorder(t)

		provider.EXPECT().ConnectionLookup().Return(mockConnRec.Lookup).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"my_did":"id","their_did":"id","propose_presentation":{}}`
		cmdErr := cmd.SendProposePresentation(&b, bytes.NewBufferString(jsonPayload))
		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Contains(t, cmdErr.Error(), errNoConnectionForDIDs)
	})
	t.Run("SendProposePresentation (error)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().HandleOutbound(
			gomock.Any(), gomock.Any(), gomock.Any(),
		).Return("", errors.New("some error message"))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)

		mockConnRec := mockConnectionRecorder(t, connection.Record{
			MyDID:    "id",
			TheirDID: "id",
		})

		provider.EXPECT().ConnectionLookup().Return(mockConnRec.Lookup).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"my_did":"id","their_did":"id","propose_presentation":{}}`
		cmdErr := cmd.SendProposePresentation(&b, bytes.NewBufferString(jsonPayload))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "some error message")
		require.Equal(t, SendProposePresentationErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().HandleOutbound(gomock.Any(), gomock.Any(), gomock.Any())

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)

		mockConnRec := mockConnectionRecorder(t, connection.Record{
			MyDID:    "id",
			TheirDID: "id",
		})

		provider.EXPECT().ConnectionLookup().Return(mockConnRec.Lookup).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"my_did":"id","their_did":"id","propose_presentation":{}}`
		require.NoError(t, cmd.SendProposePresentation(&b, bytes.NewBufferString(jsonPayload)))
	})

	t.Run("Success - with connection ID parameter", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().HandleOutbound(gomock.Any(), gomock.Any(), gomock.Any())

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)

		connID := uuid.New().String()

		mockConnRec := mockConnectionRecorder(t, connection.Record{
			ConnectionID: connID,
			MyDID:        "id",
			TheirDID:     "id",
		})

		provider.EXPECT().ConnectionLookup().Return(mockConnRec.Lookup).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		payload := fmt.Sprintf(`{"connection_id":"%s","propose_presentation":{}}`, connID)
		require.NoError(t, cmd.SendProposePresentation(&b, bytes.NewBufferString(payload)))
	})

	t.Run("Success (v3)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().HandleOutbound(gomock.Any(), gomock.Any(), gomock.Any())

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)

		mockConnRec := mockConnectionRecorder(t, connection.Record{
			MyDID:          "id",
			TheirDID:       "id",
			DIDCommVersion: didcomm.V2,
		})

		provider.EXPECT().ConnectionLookup().Return(mockConnRec.Lookup).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"my_did":"id","their_did":"id","propose_presentation":{}}`
		require.NoError(t, cmd.SendProposePresentation(&b, bytes.NewBufferString(jsonPayload)))
	})
}

func TestCommand_AcceptRequestPresentation(t *testing.T) {
	t.Parallel()

	t.Run("Decode error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		provider := createProvider(ctrl)

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptRequestPresentation(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty PIID", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		provider := createProvider(ctrl)

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptRequestPresentation(&b, bytes.NewBufferString("{}"))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyPIID)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty Presentation", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		provider := createProvider(ctrl)

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptRequestPresentation(&b, bytes.NewBufferString(`{"piid":"id"}`))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyPresentation)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("AcceptRequestPresentation (error)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().ActionContinue(gomock.Any(), gomock.Any()).Return(errors.New("some error message"))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().ConnectionLookup().Return(nil).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"piid":"id","presentation":{}}`
		cmdErr := cmd.AcceptRequestPresentation(&b, bytes.NewBufferString(jsonPayload))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "some error message")
		require.Equal(t, AcceptRequestPresentationErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().ActionContinue(gomock.Any(), gomock.Any())

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().ConnectionLookup().Return(nil).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"piid":"id","presentation":{}}`
		require.NoError(t, cmd.AcceptRequestPresentation(&b, bytes.NewBufferString(jsonPayload)))
	})

	t.Run("Success (v3)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().ActionContinue(gomock.Any(), gomock.Any())

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().ConnectionLookup().Return(nil).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"piid":"id","presentation":{}}`
		require.NoError(t, cmd.AcceptRequestPresentation(&b, bytes.NewBufferString(jsonPayload)))
	})
}

func TestCommand_NegotiateRequestPresentation(t *testing.T) {
	t.Parallel()

	t.Run("Decode error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		provider := createProvider(ctrl)

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.NegotiateRequestPresentation(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty PIID", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		provider := createProvider(ctrl)

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.NegotiateRequestPresentation(&b, bytes.NewBufferString("{}"))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyPIID)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty ProposePresentation", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		provider := createProvider(ctrl)

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.NegotiateRequestPresentation(&b, bytes.NewBufferString(`{"piid":"id"}`))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyProposePresentation)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("NegotiateRequestPresentation (error)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().ActionContinue(gomock.Any(), gomock.Any()).Return(errors.New("some error message"))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().ConnectionLookup().Return(nil).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"piid":"id","propose_presentation":{}}`
		cmdErr := cmd.NegotiateRequestPresentation(&b, bytes.NewBufferString(jsonPayload))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "some error message")
		require.Equal(t, NegotiateRequestPresentationErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().ActionContinue(gomock.Any(), gomock.Any())

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().ConnectionLookup().Return(nil).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"piid":"id","propose_presentation":{}}`
		require.NoError(t, cmd.NegotiateRequestPresentation(&b, bytes.NewBufferString(jsonPayload)))
	})

	t.Run("Success (v3)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().ActionContinue(gomock.Any(), gomock.Any())

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().ConnectionLookup().Return(nil).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"piid":"id","propose_presentation":{}}`
		require.NoError(t, cmd.NegotiateRequestPresentation(&b, bytes.NewBufferString(jsonPayload)))
	})
}

func TestCommand_AcceptProposePresentation(t *testing.T) {
	t.Parallel()

	t.Run("Decode error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		provider := createProvider(ctrl)

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptProposePresentation(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty PIID", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		provider := createProvider(ctrl)

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptProposePresentation(&b, bytes.NewBufferString("{}"))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyPIID)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty RequestPresentation", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		provider := createProvider(ctrl)

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptProposePresentation(&b, bytes.NewBufferString(`{"piid":"id"}`))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyRequestPresentation)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("AcceptProposePresentation (error)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().ActionContinue(gomock.Any(), gomock.Any()).Return(errors.New("some error message"))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().ConnectionLookup().Return(nil).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"piid":"id","request_presentation":{}}`
		cmdErr := cmd.AcceptProposePresentation(&b, bytes.NewBufferString(jsonPayload))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "some error message")
		require.Equal(t, AcceptProposePresentationErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().ActionContinue(gomock.Any(), gomock.Any())

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().ConnectionLookup().Return(nil).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"piid":"id","request_presentation":{}}`
		require.NoError(t, cmd.AcceptProposePresentation(&b, bytes.NewBufferString(jsonPayload)))
	})

	t.Run("Success (v3)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().ActionContinue(gomock.Any(), gomock.Any())

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().ConnectionLookup().Return(nil).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"piid":"id","request_presentation":{}}`
		require.NoError(t, cmd.AcceptProposePresentation(&b, bytes.NewBufferString(jsonPayload)))
	})
}

func TestCommand_Actions(t *testing.T) {
	initMocks := func(ctrl *gomock.Controller) (*clientmocks.MockProtocolService, *mocks.MockProvider) {
		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil).AnyTimes()
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil).AnyTimes()

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil).AnyTimes()
		provider.EXPECT().ConnectionLookup().Return(nil).AnyTimes()

		return service, provider
	}

	t.Parallel()

	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		service, provider := initMocks(ctrl)

		expected := ActionsResponse{Actions: []presentproof.Action{{
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
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		service, provider := initMocks(ctrl)

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

func TestCommand_AcceptPresentation(t *testing.T) {
	t.Parallel()

	t.Run("Decode error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		provider := createProvider(ctrl)

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptPresentation(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty PIID", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		provider := createProvider(ctrl)

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptPresentation(&b, bytes.NewBufferString("{}"))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyPIID)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("AcceptPresentation (error)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().ActionContinue(gomock.Any(), gomock.Any()).Return(errors.New("some error message"))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().ConnectionLookup().Return(nil).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptPresentation(&b, bytes.NewBufferString(jsonPayload))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "some error message")
		require.Equal(t, AcceptPresentationErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().ActionContinue(gomock.Any(), gomock.Any())

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().ConnectionLookup().Return(nil).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		require.NoError(t, cmd.AcceptPresentation(&b, bytes.NewBufferString(jsonPayload)))
	})
}

func TestCommand_AcceptProblemReport(t *testing.T) {
	t.Parallel()

	t.Run("Decode error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		provider := createProvider(ctrl)

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptProblemReport(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty PIID", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		provider := createProvider(ctrl)

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptProblemReport(&b, bytes.NewBufferString("{}"))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyPIID)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("AcceptProblemReport (error)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().ActionContinue(gomock.Any(), gomock.Any()).Return(errors.New("some error message"))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().ConnectionLookup().Return(nil).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptProblemReport(&b, bytes.NewBufferString(jsonPayload))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "some error message")
		require.Equal(t, AcceptProblemReportErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().ActionContinue(gomock.Any(), gomock.Any())

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().ConnectionLookup().Return(nil).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		require.NoError(t, cmd.AcceptProblemReport(&b, bytes.NewBufferString(jsonPayload)))
	})
}

func TestCommand_DeclineRequestPresentation(t *testing.T) {
	t.Parallel()

	t.Run("Decode error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		provider := createProvider(ctrl)

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.DeclineRequestPresentation(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty PIID", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		provider := createProvider(ctrl)

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.DeclineRequestPresentation(&b, bytes.NewBufferString("{}"))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyPIID)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("DeclineRequestPresentation (error)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().ActionStop(gomock.Any(), gomock.Any()).Return(errors.New("some error message"))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().ConnectionLookup().Return(nil).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.DeclineRequestPresentation(&b, bytes.NewBufferString(jsonPayload))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "some error message")
		require.Equal(t, DeclineRequestPresentationErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().ActionStop(gomock.Any(), gomock.Any())

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().ConnectionLookup().Return(nil).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		require.NoError(t, cmd.DeclineRequestPresentation(&b, bytes.NewBufferString(jsonPayload)))
	})
}

func TestCommand_DeclineProposePresentation(t *testing.T) {
	t.Parallel()

	t.Run("Decode error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		provider := createProvider(ctrl)

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.DeclineProposePresentation(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty PIID", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		provider := createProvider(ctrl)

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.DeclineProposePresentation(&b, bytes.NewBufferString("{}"))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyPIID)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("DeclineProposePresentation (error)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().ActionStop(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("some error message"))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().ConnectionLookup().Return(nil).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.DeclineProposePresentation(&b, bytes.NewBufferString(jsonPayload))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "some error message")
		require.Equal(t, DeclineProposePresentationErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().ActionStop(gomock.Any(), gomock.Any(), gomock.Any())

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().ConnectionLookup().Return(nil).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		require.NoError(t, cmd.DeclineProposePresentation(&b, bytes.NewBufferString(jsonPayload)))
	})
}

func TestCommand_DeclinePresentation(t *testing.T) {
	t.Parallel()

	t.Run("Decode error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		provider := createProvider(ctrl)

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.DeclinePresentation(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty PIID", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		provider := createProvider(ctrl)

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.DeclinePresentation(&b, bytes.NewBufferString("{}"))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyPIID)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("DeclinePresentation (error)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().ActionStop(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("some error message"))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().ConnectionLookup().Return(nil).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.DeclinePresentation(&b, bytes.NewBufferString(jsonPayload))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "some error message")
		require.Equal(t, DeclinePresentationErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().ActionStop(gomock.Any(), gomock.Any(), gomock.Any())

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().ConnectionLookup().Return(nil).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		require.NoError(t, cmd.DeclinePresentation(&b, bytes.NewBufferString(jsonPayload)))
	})
}

func createProvider(ctrl *gomock.Controller) *mocks.MockProvider {
	service := clientmocks.NewMockProtocolService(ctrl)
	service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil).AnyTimes()
	service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil).AnyTimes()

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(gomock.Any()).Return(service, nil).AnyTimes()
	provider.EXPECT().ConnectionLookup().Return(nil).AnyTimes()

	return provider
}

func mockConnectionRecorder(t *testing.T, records ...connection.Record) *connection.Recorder {
	t.Helper()

	storeProv := mockstore.NewMockStoreProvider()

	prov := mockprovider.Provider{
		StorageProviderValue:              storeProv,
		ProtocolStateStorageProviderValue: storeProv,
	}

	recorder, err := connection.NewRecorder(&prov)
	require.NoError(t, err)

	for i := 0; i < len(records); i++ {
		rec := records[i]

		if rec.ConnectionID == "" {
			rec.ConnectionID = uuid.New().String()
		}

		if rec.State == "" {
			rec.State = connection.StateNameCompleted
		}

		err = recorder.SaveConnectionRecord(&rec)
		require.NoError(t, err)
	}

	return recorder
}

func toProtocolActions(actions []presentproof.Action) []protocol.Action {
	res := make([]protocol.Action, len(actions))
	for i, action := range actions {
		res[i] = protocol.Action(action)
	}

	return res
}
