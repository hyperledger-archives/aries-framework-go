/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package messaging

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/client/messaging"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/service/http"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

var logger = log.New("aries-framework/controller/common")

// constants for the Messaging controller.
const (
	// command name.
	CommandName = "messaging"

	// error messages.
	errMsgSvcNameRequired            = "service name is required"
	errMsgInvalidAcceptanceCrit      = "invalid acceptance criteria"
	errMsgBodyEmpty                  = "empty message body"
	errMsgDestinationMissing         = "missing message destination"
	errMsgDestSvcEndpointMissing     = "missing service endpoint in message destination"
	errMsgDestSvcEndpointKeysMissing = "missing service endpoint recipient/routing keys in message destination"
	errMsgIDEmpty                    = "empty message ID"

	// command methods.
	RegisteredServicesCommandMethod         = "Services"
	RegisterMessageServiceCommandMethod     = "RegisterService"
	UnregisterMessageServiceCommandMethod   = "UnregisterService"
	RegisterHTTPMessageServiceCommandMethod = "RegisterHTTPService"
	SendNewMessageCommandMethod             = "Send"
	SendReplyMessageCommandMethod           = "Reply"

	// log constants.
	replyTo       = "replyTo"
	successString = "success"

	// default timeout.
	defaultTimeout = 20 * time.Second
)

// Error codes.
const (
	// InvalidRequestErrorCode is typically a code for invalid requests.
	InvalidRequestErrorCode = command.Code(iota + command.Messaging)

	// RegisterMsgSvcError is for failures while registering new message service.
	RegisterMsgSvcError

	// UnregisterMsgSvcError is for failures while unregistering a message service.
	UnregisterMsgSvcError

	// SendMsgError is for failures while sending messages.
	SendMsgError

	// SendMsgReplyError is for failures while sending message replies.
	SendMsgReplyError
)

// provider contains dependencies for the messaging controller command operations
// and is typically created by using aries.Context().
type provider interface {
	VDRegistry() vdr.Registry
	Messenger() service.Messenger
	ProtocolStateStorageProvider() storage.Provider
	StorageProvider() storage.Provider
	KMS() kms.KeyManager
}

// Command contains basic command operations provided by messaging controller command.
type Command struct {
	msgClient *messaging.Client
}

// New returns new command instance for messaging controller API.
func New(ctx provider, registrar command.MessageHandler, notifier command.Notifier) (*Command, error) {
	msgClient, err := messaging.New(ctx, registrar, notifier)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize message client : %w", err)
	}

	return &Command{msgClient}, nil
}

// GetHandlers returns list of all commands supported by this controller command.
func (o *Command) GetHandlers() []command.Handler {
	return []command.Handler{
		cmdutil.NewCommandHandler(CommandName, RegisteredServicesCommandMethod, o.Services),
		cmdutil.NewCommandHandler(CommandName, RegisterMessageServiceCommandMethod, o.RegisterService),
		cmdutil.NewCommandHandler(CommandName, UnregisterMessageServiceCommandMethod, o.UnregisterService),
		cmdutil.NewCommandHandler(CommandName, RegisterHTTPMessageServiceCommandMethod, o.RegisterHTTPService),
		cmdutil.NewCommandHandler(CommandName, SendNewMessageCommandMethod, o.Send),
		cmdutil.NewCommandHandler(CommandName, SendReplyMessageCommandMethod, o.Reply),
	}
}

// RegisterService registers new message service to message handler registrar.
func (o *Command) RegisterService(rw io.Writer, req io.Reader) command.Error {
	var request RegisterMsgSvcArgs

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, RegisterMessageServiceCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	return o.registerMessageService(&request)
}

// UnregisterService unregisters given message service handler registrar.
func (o *Command) UnregisterService(rw io.Writer, req io.Reader) command.Error {
	var request UnregisterMsgSvcArgs

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, UnregisterMessageServiceCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if request.Name == "" {
		logutil.LogDebug(logger, CommandName, UnregisterMessageServiceCommandMethod, errMsgSvcNameRequired)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errMsgSvcNameRequired))
	}

	err = o.msgClient.UnregisterService(request.Name)
	if err != nil {
		logutil.LogError(logger, CommandName, UnregisterMessageServiceCommandMethod, err.Error(),
			logutil.CreateKeyValueString("name", request.Name))

		return command.NewExecuteError(UnregisterMsgSvcError, err)
	}

	logutil.LogDebug(logger, CommandName, UnregisterMessageServiceCommandMethod, successString,
		logutil.CreateKeyValueString("name", request.Name))

	return nil
}

// Services returns list of registered service names.
func (o *Command) Services(rw io.Writer, req io.Reader) command.Error {
	command.WriteNillableResponse(rw, RegisteredServicesResponse{Names: o.msgClient.Services()}, logger)

	logutil.LogDebug(logger, CommandName, RegisteredServicesCommandMethod, successString)

	return nil
}

// Send sends new message to destination provided.
func (o *Command) Send(rw io.Writer, req io.Reader) command.Error {
	var request SendNewMessageArgs

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, SendNewMessageCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if len(request.MessageBody) == 0 {
		logutil.LogDebug(logger, CommandName, SendNewMessageCommandMethod, errMsgBodyEmpty)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errMsgBodyEmpty))
	}

	err = o.validateMessageDestination(&request)
	if err != nil {
		logutil.LogError(logger, CommandName, SendNewMessageCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	var destination *service.Destination

	if request.ServiceEndpointDestination != nil {
		routingKeys := request.ServiceEndpointDestination.RoutingKeys
		if len(routingKeys) > 0 {
			destination = &service.Destination{
				ServiceEndpoint: model.NewDIDCommV1Endpoint(request.ServiceEndpointDestination.ServiceEndpoint),
				RoutingKeys:     routingKeys,
				RecipientKeys:   request.ServiceEndpointDestination.RecipientKeys,
			}
		} else {
			destination = &service.Destination{
				ServiceEndpoint: model.NewDIDCommV2Endpoint([]model.DIDCommV2Endpoint{{
					URI:         request.ServiceEndpointDestination.ServiceEndpoint,
					RoutingKeys: routingKeys,
				}}),
				RecipientKeys: request.ServiceEndpointDestination.RecipientKeys,
			}
		}
	}

	ctx, cancel := prepareContext(request.AwaitReply.Timeout)
	defer cancel()

	res, err := o.msgClient.Send(request.MessageBody,
		messaging.SendByConnectionID(request.ConnectionID),
		messaging.SendByTheirDID(request.TheirDID),
		messaging.SendByDestination(destination),
		messaging.WaitForResponse(ctx, request.AwaitReply.ReplyMessageType))
	if err != nil {
		logutil.LogError(logger, CommandName, SendNewMessageCommandMethod, err.Error())

		return command.NewExecuteError(SendMsgError, err)
	}

	command.WriteNillableResponse(rw, SendMessageResponse{Response: res}, logger)

	logutil.LogDebug(logger, CommandName, SendNewMessageCommandMethod, successString)

	return nil
}

// Reply sends reply to existing message.
func (o *Command) Reply(rw io.Writer, req io.Reader) command.Error {
	var request SendReplyMessageArgs

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, SendReplyMessageCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if len(request.MessageBody) == 0 {
		logutil.LogDebug(logger, CommandName, SendReplyMessageCommandMethod, errMsgBodyEmpty)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errMsgBodyEmpty))
	}

	if request.MessageID == "" {
		logutil.LogDebug(logger, CommandName, SendReplyMessageCommandMethod, errMsgIDEmpty)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errMsgIDEmpty))
	}

	ctx, cancel := prepareContext(request.AwaitReply.Timeout)
	defer cancel()

	res, err := o.msgClient.Reply(ctx, request.MessageBody, request.MessageID, request.StartNewThread,
		request.AwaitReply.ReplyMessageType)
	if err != nil {
		logutil.LogError(logger, CommandName, SendReplyMessageCommandMethod, err.Error(),
			logutil.CreateKeyValueString(replyTo, request.MessageID))
		return command.NewExecuteError(SendMsgReplyError, err)
	}

	command.WriteNillableResponse(rw, SendMessageResponse{Response: res}, logger)

	logutil.LogDebug(logger, CommandName, SendNewMessageCommandMethod, successString)

	return nil
}

// RegisterHTTPService registers new http over didcomm service to message handler registrar.
func (o *Command) RegisterHTTPService(rw io.Writer, req io.Reader) command.Error {
	var request RegisterHTTPMsgSvcArgs

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, RegisterHTTPMessageServiceCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	return o.registerMessageService(&RegisterMsgSvcArgs{
		Name:    request.Name,
		Type:    http.OverDIDCommMsgRequestType,
		Purpose: request.Purpose,
	})
}

func (o *Command) registerMessageService(params *RegisterMsgSvcArgs) command.Error {
	if params.Name == "" {
		logutil.LogDebug(logger, CommandName, RegisterMessageServiceCommandMethod, errMsgSvcNameRequired)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errMsgSvcNameRequired))
	}

	if params.Type == "" {
		logutil.LogDebug(logger, CommandName, RegisterMessageServiceCommandMethod, errMsgInvalidAcceptanceCrit)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errMsgInvalidAcceptanceCrit))
	}

	err := o.msgClient.RegisterService(params.Name, params.Type, params.Purpose...)
	if err != nil {
		logutil.LogError(logger, CommandName, RegisterMessageServiceCommandMethod, err.Error(),
			logutil.CreateKeyValueString("name", params.Name),
			logutil.CreateKeyValueString("type", params.Type))

		return command.NewExecuteError(RegisterMsgSvcError, err)
	}

	return nil
}

func (o *Command) validateMessageDestination(dest *SendNewMessageArgs) error {
	didMissing, connIDMissing, svcEPMissing := dest.TheirDID == "",
		dest.ConnectionID == "",
		dest.ServiceEndpointDestination == nil

	if didMissing && connIDMissing && svcEPMissing {
		return fmt.Errorf(errMsgDestinationMissing)
	}

	if !didMissing || !connIDMissing {
		return nil
	}

	if dest.ServiceEndpointDestination.ServiceEndpoint == "" {
		return fmt.Errorf(errMsgDestSvcEndpointMissing)
	}

	if len(dest.ServiceEndpointDestination.RecipientKeys) == 0 &&
		len(dest.ServiceEndpointDestination.RoutingKeys) == 0 {
		return fmt.Errorf(errMsgDestSvcEndpointKeysMissing)
	}

	return nil
}

func prepareContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout == 0 {
		timeout = defaultTimeout
	}

	return context.WithTimeout(context.Background(), timeout)
}
