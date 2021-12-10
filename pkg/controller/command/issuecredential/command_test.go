/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/client/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	didcomm "github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	protocol "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	clientmocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/client/issuecredential"
	mocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/controller/command/issuecredential"
	mocknotifier "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/controller/webnotifier"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const jsonPayload = `{"piid":"id"}`

func TestNew(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
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

	t.Run("Success - autoExecuteRFC0593", func(t *testing.T) {
		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(&mockProtocol{}, nil).MaxTimes(2)
		provider.EXPECT().ConnectionLookup().Return(nil).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil), WithAutoExecuteRFC0593(&mockRFC0593Provider{}))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		handlers := cmd.GetHandlers()
		require.NotEmpty(t, handlers)
	})

	t.Run("Create client (error)", func(t *testing.T) {
		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(nil, nil)
		provider.EXPECT().ConnectionLookup().Return(nil).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.EqualError(t, err, "cannot create a client: cast service to issuecredential service failed")
		require.Nil(t, cmd)
	})

	t.Run("Register action event (error)", func(t *testing.T) {
		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterMsgEvent(gomock.Any())
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(errors.New("error"))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().ConnectionLookup().Return(nil).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.EqualError(t, err, "register action event: error")
		require.Nil(t, cmd)
	})

	t.Run("Register msg event (error)", func(t *testing.T) {
		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(errors.New("error"))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().ConnectionLookup().Return(nil).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.EqualError(t, err, "register msg event: error")
		require.Nil(t, cmd)
	})
}

func TestCommand_Actions(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	service := clientmocks.NewMockProtocolService(ctrl)
	service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil).AnyTimes()
	service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil).AnyTimes()

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(gomock.Any()).Return(service, nil).AnyTimes()
	provider.EXPECT().ConnectionLookup().Return(nil).AnyTimes()

	t.Run("Success", func(t *testing.T) {
		expected := ActionsResponse{Actions: []issuecredential.Action{{
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

func TestCommand_SendOffer(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mockProvider(ctrl, nil)

	t.Run("Decode error", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.SendOffer(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty MyDID", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.SendOffer(&b, bytes.NewBufferString("{}"))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyMyDID)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty TheirDID", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.SendOffer(&b, bytes.NewBufferString(`{"my_did":"id"}`))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyTheirDID)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty OfferCredential", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.SendOffer(&b, bytes.NewBufferString(`{"my_did":"id","their_did":"id"}`))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyOfferCredential)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Missing connection", func(t *testing.T) {
		rec := mockConnectionRecorder(t)
		provider := mockProvider(ctrl, rec.Lookup)

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"my_did":"id","their_did":"id","offer_credential":{}}`
		cmdErr := cmd.SendOffer(&b, bytes.NewBufferString(jsonPayload))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errMissingConnection)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("SendOffer (error)", func(t *testing.T) {
		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().HandleOutbound(
			gomock.Any(), gomock.Any(),
			gomock.Any(),
		).Return("", errors.New("some error message"))

		rec := mockConnectionRecorder(t, connection.Record{
			MyDID:    "id",
			TheirDID: "id",
		})

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().ConnectionLookup().Return(rec.Lookup).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"my_did":"id","their_did":"id","offer_credential":{}}`
		cmdErr := cmd.SendOffer(&b, bytes.NewBufferString(jsonPayload))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "some error message")
		require.Equal(t, SendOfferErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().HandleOutbound(gomock.Any(), gomock.Any(), gomock.Any())

		rec := mockConnectionRecorder(t, connection.Record{
			MyDID:    "id",
			TheirDID: "id",
		})

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().ConnectionLookup().Return(rec.Lookup).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"my_did":"id","their_did":"id","offer_credential":{}}`
		require.NoError(t, cmd.SendOffer(&b, bytes.NewBufferString(jsonPayload)))
	})

	t.Run("SendOffer (error) v3", func(t *testing.T) {
		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().HandleOutbound(
			gomock.Any(), gomock.Any(),
			gomock.Any(),
		).Return("", errors.New("some error message"))

		rec := mockConnectionRecorder(t, connection.Record{
			MyDID:          "id",
			TheirDID:       "id",
			DIDCommVersion: didcomm.V2,
		})

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().ConnectionLookup().Return(rec.Lookup).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"my_did":"id","their_did":"id","offer_credential":{}}`
		cmdErr := cmd.SendOffer(&b, bytes.NewBufferString(jsonPayload))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "some error message")
		require.Equal(t, SendOfferErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success v3", func(t *testing.T) {
		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().HandleOutbound(gomock.Any(), gomock.Any(), gomock.Any())

		rec := mockConnectionRecorder(t, connection.Record{
			MyDID:          "id",
			TheirDID:       "id",
			DIDCommVersion: didcomm.V2,
		})

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().ConnectionLookup().Return(rec.Lookup).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"my_did":"id","their_did":"id","offer_credential":{}}`
		require.NoError(t, cmd.SendOffer(&b, bytes.NewBufferString(jsonPayload)))
	})
}

func TestCommand_SendProposal(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mockProvider(ctrl, nil)

	t.Run("Decode error", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.SendProposal(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty MyDID", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.SendProposal(&b, bytes.NewBufferString("{}"))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyMyDID)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty TheirDID", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.SendProposal(&b, bytes.NewBufferString(`{"my_did":"id"}`))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyTheirDID)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty ProposeCredential", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.SendProposal(&b, bytes.NewBufferString(`{"my_did":"id","their_did":"id"}`))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyProposeCredential)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Missing connection", func(t *testing.T) {
		rec := mockConnectionRecorder(t)
		provider := mockProvider(ctrl, rec.Lookup)

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"my_did":"id","their_did":"id","propose_credential":{}}`
		cmdErr := cmd.SendProposal(&b, bytes.NewBufferString(jsonPayload))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errMissingConnection)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("SendProposal (error)", func(t *testing.T) {
		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().HandleOutbound(
			gomock.Any(), gomock.Any(),
			gomock.Any(),
		).Return("", errors.New("some error message"))

		rec := mockConnectionRecorder(t, connection.Record{
			MyDID:    "id",
			TheirDID: "id",
		})

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().ConnectionLookup().Return(rec.Lookup).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"my_did":"id","their_did":"id","propose_credential":{}}`
		cmdErr := cmd.SendProposal(&b, bytes.NewBufferString(jsonPayload))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "some error message")
		require.Equal(t, SendProposalErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().HandleOutbound(gomock.Any(), gomock.Any(), gomock.Any())

		rec := mockConnectionRecorder(t, connection.Record{
			MyDID:    "id",
			TheirDID: "id",
		})

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().ConnectionLookup().Return(rec.Lookup).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"my_did":"id","their_did":"id","propose_credential":{}}`
		require.NoError(t, cmd.SendProposal(&b, bytes.NewBufferString(jsonPayload)))
	})

	t.Run("SendProposal (error) v3", func(t *testing.T) {
		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().HandleOutbound(
			gomock.Any(), gomock.Any(),
			gomock.Any(),
		).Return("", errors.New("some error message"))

		rec := mockConnectionRecorder(t, connection.Record{
			MyDID:          "id",
			TheirDID:       "id",
			DIDCommVersion: didcomm.V2,
		})

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().ConnectionLookup().Return(rec.Lookup).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"my_did":"id","their_did":"id","propose_credential":{}}`
		cmdErr := cmd.SendProposal(&b, bytes.NewBufferString(jsonPayload))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "some error message")
		require.Equal(t, SendProposalErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success v3", func(t *testing.T) {
		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().HandleOutbound(gomock.Any(), gomock.Any(), gomock.Any())

		rec := mockConnectionRecorder(t, connection.Record{
			MyDID:          "id",
			TheirDID:       "id",
			DIDCommVersion: didcomm.V2,
		})

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().ConnectionLookup().Return(rec.Lookup).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"my_did":"id","their_did":"id","propose_credential":{}}`
		require.NoError(t, cmd.SendProposal(&b, bytes.NewBufferString(jsonPayload)))
	})
}

func TestCommand_SendRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mockProvider(ctrl, nil)

	t.Run("Decode error", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.SendRequest(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty MyDID", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
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
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.SendRequest(&b, bytes.NewBufferString(`{"my_did":"id"}`))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyTheirDID)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty RequestCredential", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.SendRequest(&b, bytes.NewBufferString(`{"my_did":"id","their_did":"id"}`))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyRequestCredential)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Missing connection", func(t *testing.T) {
		rec := mockConnectionRecorder(t)
		provider := mockProvider(ctrl, rec.Lookup)

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"my_did":"id","their_did":"id","request_credential":{}}`
		cmdErr := cmd.SendRequest(&b, bytes.NewBufferString(jsonPayload))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errMissingConnection)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("SendRequest (error)", func(t *testing.T) {
		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().HandleOutbound(
			gomock.Any(), gomock.Any(),
			gomock.Any(),
		).Return("", errors.New("some error message"))

		rec := mockConnectionRecorder(t, connection.Record{
			MyDID:    "id",
			TheirDID: "id",
		})

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().ConnectionLookup().Return(rec.Lookup).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"my_did":"id","their_did":"id","request_credential":{}}`
		cmdErr := cmd.SendRequest(&b, bytes.NewBufferString(jsonPayload))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "some error message")
		require.Equal(t, SendRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().HandleOutbound(gomock.Any(), gomock.Any(), gomock.Any())

		rec := mockConnectionRecorder(t, connection.Record{
			MyDID:    "id",
			TheirDID: "id",
		})

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().ConnectionLookup().Return(rec.Lookup).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"my_did":"id","their_did":"id","request_credential":{}}`
		require.NoError(t, cmd.SendRequest(&b, bytes.NewBufferString(jsonPayload)))
	})

	t.Run("SendRequest (error) v3", func(t *testing.T) {
		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().HandleOutbound(
			gomock.Any(), gomock.Any(),
			gomock.Any(),
		).Return("", errors.New("some error message"))

		rec := mockConnectionRecorder(t, connection.Record{
			MyDID:          "id",
			TheirDID:       "id",
			DIDCommVersion: didcomm.V2,
		})

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().ConnectionLookup().Return(rec.Lookup).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"my_did":"id","their_did":"id","request_credential":{}}`
		cmdErr := cmd.SendRequest(&b, bytes.NewBufferString(jsonPayload))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "some error message")
		require.Equal(t, SendRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success v3", func(t *testing.T) {
		service := clientmocks.NewMockProtocolService(ctrl)
		service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
		service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		service.EXPECT().HandleOutbound(gomock.Any(), gomock.Any(), gomock.Any())

		rec := mockConnectionRecorder(t, connection.Record{
			MyDID:          "id",
			TheirDID:       "id",
			DIDCommVersion: didcomm.V2,
		})

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(service, nil)
		provider.EXPECT().ConnectionLookup().Return(rec.Lookup).AnyTimes()

		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		const jsonPayload = `{"my_did":"id","their_did":"id","request_credential":{}}`
		require.NoError(t, cmd.SendRequest(&b, bytes.NewBufferString(jsonPayload)))
	})
}

func TestCommand_AcceptProposal(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mockProvider(ctrl, nil)

	t.Run("Decode error", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptProposal(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty PIID", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptProposal(&b, bytes.NewBufferString("{}"))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyPIID)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty OfferCredential", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptProposal(&b, bytes.NewBufferString(`{"piid":"id"}`))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyOfferCredential)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("AcceptProposal (error)", func(t *testing.T) {
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
		const jsonPayload = `{"piid":"id","offer_credential":{}}`
		cmdErr := cmd.AcceptProposal(&b, bytes.NewBufferString(jsonPayload))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "some error message")
		require.Equal(t, AcceptProposalErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
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
		const jsonPayload = `{"piid":"id","offer_credential":{}}`
		require.NoError(t, cmd.AcceptProposal(&b, bytes.NewBufferString(jsonPayload)))
	})
}

func TestCommand_NegotiateProposal(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mockProvider(ctrl, nil)

	t.Run("Decode error", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.NegotiateProposal(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty PIID", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.NegotiateProposal(&b, bytes.NewBufferString("{}"))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyPIID)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty OfferCredential", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.NegotiateProposal(&b, bytes.NewBufferString(`{"piid":"id"}`))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyProposeCredential)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("NegotiateProposal (error)", func(t *testing.T) {
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
		const jsonPayload = `{"piid":"id","propose_credential":{}}`
		cmdErr := cmd.NegotiateProposal(&b, bytes.NewBufferString(jsonPayload))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "some error message")
		require.Equal(t, NegotiateProposalErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
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
		const jsonPayload = `{"piid":"id","propose_credential":{}}`
		require.NoError(t, cmd.NegotiateProposal(&b, bytes.NewBufferString(jsonPayload)))
	})
}

func TestCommand_DeclineProposal(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mockProvider(ctrl, nil)

	t.Run("Decode error", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.DeclineProposal(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty PIID", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
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
		cmdErr := cmd.DeclineProposal(&b, bytes.NewBufferString(jsonPayload))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "some error message")
		require.Equal(t, DeclineProposalErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
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
		require.NoError(t, cmd.DeclineProposal(&b, bytes.NewBufferString(jsonPayload)))
	})
}

func TestCommand_AcceptOffer(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mockProvider(ctrl, nil)

	t.Run("Decode error", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptOffer(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty PIID", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptOffer(&b, bytes.NewBufferString("{}"))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyPIID)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("AcceptOffer (error)", func(t *testing.T) {
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
		cmdErr := cmd.AcceptOffer(&b, bytes.NewBufferString(jsonPayload))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "some error message")
		require.Equal(t, AcceptOfferErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
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
		require.NoError(t, cmd.AcceptOffer(&b, bytes.NewBufferString(jsonPayload)))
	})
}

func TestCommand_AcceptProblemReport(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mockProvider(ctrl, nil)

	t.Run("Decode error", func(t *testing.T) {
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

func TestCommand_DeclineOffer(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mockProvider(ctrl, nil)

	t.Run("Decode error", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.DeclineOffer(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty PIID", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.DeclineOffer(&b, bytes.NewBufferString("{}"))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyPIID)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("DeclineOffer (error)", func(t *testing.T) {
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
		cmdErr := cmd.DeclineOffer(&b, bytes.NewBufferString(jsonPayload))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "some error message")
		require.Equal(t, DeclineOfferErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
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
		require.NoError(t, cmd.DeclineOffer(&b, bytes.NewBufferString(jsonPayload)))
	})
}

func TestCommand_AcceptRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mockProvider(ctrl, nil)

	t.Run("Decode error", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptRequest(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty PIID", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptRequest(&b, bytes.NewBufferString("{}"))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyPIID)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty IssueCredential", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptRequest(&b, bytes.NewBufferString(`{"piid":"id"}`))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyIssueCredential)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("AcceptRequest (error)", func(t *testing.T) {
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
		const jsonPayload = `{"piid":"id","issue_credential":{}}`
		cmdErr := cmd.AcceptRequest(&b, bytes.NewBufferString(jsonPayload))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "some error message")
		require.Equal(t, AcceptRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
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
		const jsonPayload = `{"piid":"id","issue_credential":{}}`
		require.NoError(t, cmd.AcceptRequest(&b, bytes.NewBufferString(jsonPayload)))
	})
}

func TestCommand_DeclineRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mockProvider(ctrl, nil)

	t.Run("Decode error", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.DeclineRequest(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty PIID", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
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
		cmdErr := cmd.DeclineRequest(&b, bytes.NewBufferString(jsonPayload))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "some error message")
		require.Equal(t, DeclineRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
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
		require.NoError(t, cmd.DeclineRequest(&b, bytes.NewBufferString(jsonPayload)))
	})
}

func TestCommand_AcceptCredential(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mockProvider(ctrl, nil)

	t.Run("Decode error", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptCredential(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty PIID", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.AcceptCredential(&b, bytes.NewBufferString("{}"))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyPIID)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("AcceptCredential (error)", func(t *testing.T) {
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
		cmdErr := cmd.AcceptCredential(&b, bytes.NewBufferString(jsonPayload))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "some error message")
		require.Equal(t, AcceptCredentialErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
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
		require.NoError(t, cmd.AcceptCredential(&b, bytes.NewBufferString(jsonPayload)))
	})
}

func TestCommand_DeclineCredential(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mockProvider(ctrl, nil)

	t.Run("Decode error", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.DeclineCredential(&b, bytes.NewBufferString("}"))

		require.Error(t, cmdErr)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("Empty PIID", func(t *testing.T) {
		cmd, err := New(provider, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.DeclineCredential(&b, bytes.NewBufferString("{}"))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyPIID)
		require.Equal(t, InvalidRequestErrorCode, cmdErr.Code())
		require.Equal(t, command.ValidationError, cmdErr.Type())
	})

	t.Run("DeclineCredential (error)", func(t *testing.T) {
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
		cmdErr := cmd.DeclineCredential(&b, bytes.NewBufferString(jsonPayload))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "some error message")
		require.Equal(t, DeclineCredentialErrorCode, cmdErr.Code())
		require.Equal(t, command.ExecuteError, cmdErr.Type())
	})

	t.Run("Success", func(t *testing.T) {
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
		require.NoError(t, cmd.DeclineCredential(&b, bytes.NewBufferString(jsonPayload)))
	})
}

func toProtocolActions(actions []issuecredential.Action) []protocol.Action {
	res := make([]protocol.Action, len(actions))
	for i, action := range actions {
		res[i] = protocol.Action(action)
	}

	return res
}

type mockRFC0593Provider struct{}

func (m *mockRFC0593Provider) JSONLDDocumentLoader() ld.DocumentLoader {
	panic("implement me")
}

func (m *mockRFC0593Provider) ProtocolStateStorageProvider() storage.Provider {
	return mem.NewProvider()
}

func (m *mockRFC0593Provider) KMS() kms.KeyManager {
	panic("implement me")
}

func (m *mockRFC0593Provider) Crypto() crypto.Crypto {
	panic("implement me")
}

func (m *mockRFC0593Provider) VDRegistry() vdrapi.Registry {
	panic("implement me")
}

type mockProtocol struct{}

func (m *mockProtocol) HandleInbound(didcomm.DIDCommMsg, didcomm.DIDCommContext) (string, error) {
	panic("implement me")
}

func (m *mockProtocol) HandleOutbound(didcomm.DIDCommMsg, string, string) (string, error) {
	panic("implement me")
}

func (m *mockProtocol) RegisterActionEvent(chan<- didcomm.DIDCommAction) error {
	return nil
}

func (m *mockProtocol) UnregisterActionEvent(chan<- didcomm.DIDCommAction) error {
	panic("implement me")
}

func (m *mockProtocol) RegisterMsgEvent(chan<- didcomm.StateMsg) error {
	return nil
}

func (m *mockProtocol) UnregisterMsgEvent(chan<- didcomm.StateMsg) error {
	panic("implement me")
}

func (m *mockProtocol) Actions() ([]protocol.Action, error) {
	panic("implement me")
}

func (m *mockProtocol) ActionContinue(string, ...protocol.Opt) error {
	panic("implement me")
}

func (m *mockProtocol) ActionStop(string, error, ...protocol.Opt) error {
	panic("implement me")
}

func (m *mockProtocol) AddMiddleware(...protocol.Middleware) {}

func mockProvider(ctrl *gomock.Controller, lookup *connection.Lookup) *mocks.MockProvider {
	service := clientmocks.NewMockProtocolService(ctrl)
	service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil).AnyTimes()
	service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil).AnyTimes()

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(gomock.Any()).Return(service, nil).AnyTimes()
	provider.EXPECT().ConnectionLookup().Return(lookup).AnyTimes()

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
