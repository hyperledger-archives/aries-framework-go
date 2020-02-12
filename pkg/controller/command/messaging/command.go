/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package messaging

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/controller/webhook"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/service/http"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
)

var logger = log.New("aries-framework/controller/common")

const (
	// command name
	commandName = "messaging"

	// states
	stateNameCompleted = "completed"

	// error messages
	errMsgSvcNameRequired               = "service name is required"
	errMsgInvalidAcceptanceCrit         = "invalid acceptance criteria"
	errMsgBodyEmpty                     = "empty message body"
	errMsgDestinationMissing            = "missing message destination"
	errMsgDestSvcEndpointMissing        = "missing service endpoint in message destination"
	errMsgDestSvcEndpointKeysMissing    = "missing service endpoint recipient/routing keys in message destination"
	errMsgConnectionMatchingDIDNotFound = "unable to find connection matching theirDID[%s]"
	errMsgIDEmpty                       = "empty message ID"
)

// Error codes
const (
	// InvalidRequestErrorCode is typically a code for invalid requests
	InvalidRequestErrorCode = command.Code(iota + command.Messaging)

	// RegisterMsgSvcError is for failures while registering new message service
	RegisterMsgSvcError

	// UnregisterMsgSvcError is for failures while unregistering a message service
	UnregisterMsgSvcError

	// SendMsgError is for failures while sending messages
	SendMsgError

	// SendMsgReplyError is for failures while sending message replies
	SendMsgReplyError
)

// provider contains dependencies for the messaging controller command operations
// and is typically created by using aries.Context()
type provider interface {
	OutboundDispatcher() dispatcher.Outbound
	TransientStorageProvider() storage.Provider
	StorageProvider() storage.Provider
	LegacyKMS() legacykms.KeyManager
}

// Command contains basic command operations provided by messaging controller command
type Command struct {
	ctx              provider
	msgRegistrar     command.MessageHandler
	notifier         webhook.Notifier
	connectionLookup *connection.Lookup
}

// New returns new command instance for messaging controller API
func New(ctx provider, registrar command.MessageHandler, notifier webhook.Notifier) (*Command, error) {
	connectionLookup, err := connection.NewLookup(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize connection lookup : %w", err)
	}

	o := &Command{
		ctx:              ctx,
		msgRegistrar:     registrar,
		notifier:         notifier,
		connectionLookup: connectionLookup,
	}

	return o, nil
}

// GetHandlers returns list of all commands supported by this controller command
func (o *Command) GetHandlers() []command.Handler {
	return []command.Handler{
		cmdutil.NewCommandHandler(commandName, "RegisteredServices", o.RegisteredServices),
		cmdutil.NewCommandHandler(commandName, "RegisterMessageService", o.RegisterMessageService),
		cmdutil.NewCommandHandler(commandName, "UnregisterMessageService", o.UnregisterMessageService),
		cmdutil.NewCommandHandler(commandName, "RegisterHTTPMessageService", o.RegisterHTTPMessageService),
		cmdutil.NewCommandHandler(commandName, "SendNewMessage", o.SendNewMessage),
		cmdutil.NewCommandHandler(commandName, "SendReplyMessage", o.SendReplyMessage),
	}
}

// RegisterMessageService registers new message service to message handler registrar
func (o *Command) RegisterMessageService(rw io.Writer, req io.Reader) command.Error {
	var request RegisterMsgSvcArgs

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	return o.registerMessageService(&request)
}

// UnregisterMessageService unregisters given message service handler registrar
func (o *Command) UnregisterMessageService(rw io.Writer, req io.Reader) command.Error {
	var request UnregisterMsgSvcArgs

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if request.Name == "" {
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errMsgSvcNameRequired))
	}

	err = o.msgRegistrar.Unregister(request.Name)
	if err != nil {
		return command.NewExecuteError(UnregisterMsgSvcError, err)
	}

	return nil
}

// RegisteredServices returns list of registered service names
func (o *Command) RegisteredServices(rw io.Writer, req io.Reader) command.Error {
	names := []string{}
	for _, svc := range o.msgRegistrar.Services() {
		names = append(names, svc.Name())
	}

	command.WriteNillableResponse(rw, RegisteredServicesResponse{Names: names}, logger)

	return nil
}

// SendNewMessage sends new message to destination provided
func (o *Command) SendNewMessage(rw io.Writer, req io.Reader) command.Error {
	var request SendNewMessageArgs

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if len(request.MessageBody) == 0 {
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errMsgBodyEmpty))
	}

	err = o.validateMessageDestination(&request)
	if err != nil {
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if request.ConnectionID != "" {
		conn, err := o.connectionLookup.GetConnectionRecord(request.ConnectionID)
		if err != nil {
			return command.NewExecuteError(SendMsgError, err)
		}

		return o.sendMessageToConnection(request.MessageBody, conn)
	}

	if request.TheirDID != "" {
		conn, err := o.getConnectionByTheirDID(request.TheirDID)
		if err != nil {
			return command.NewExecuteError(SendMsgError, err)
		}

		return o.sendMessageToConnection(request.MessageBody, conn)
	}

	return o.sendMessageToDestination(request.MessageBody, request.ServiceEndpointDestination)
}

// SendReplyMessage sends reply to existing message
func (o *Command) SendReplyMessage(rw io.Writer, req io.Reader) command.Error {
	var request SendReplyMessageArgs

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if len(request.MessageBody) == 0 {
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errMsgBodyEmpty))
	}

	if request.MessageID == "" {
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errMsgIDEmpty))
	}

	// TODO this operation will be supported once messenger API [Issue #1039] is available
	// TODO implementation for SendReply to be added as part of [Issue #1089]
	return command.NewExecuteError(SendMsgReplyError, fmt.Errorf("to be implemented"))
}

// RegisterHTTPMessageService registers new http over didcomm service to message handler registrar
func (o *Command) RegisterHTTPMessageService(rw io.Writer, req io.Reader) command.Error {
	var request RegisterHTTPMsgSvcArgs

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
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
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errMsgSvcNameRequired))
	}

	if params.Type == "" {
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errMsgInvalidAcceptanceCrit))
	}

	err := o.msgRegistrar.Register(newMessageService(params, o.notifier))
	if err != nil {
		return command.NewExecuteError(RegisterMsgSvcError, err)
	}

	return nil
}

func (o *Command) validateMessageDestination(dest *SendNewMessageArgs) error {
	var didMissing, connIDMissing, svcEPMissing = dest.TheirDID == "",
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

func (o *Command) getConnectionByTheirDID(theirDID string) (*connection.Record, error) {
	records, err := o.connectionLookup.QueryConnectionRecords()
	if err != nil {
		return nil, err
	}

	for _, record := range records {
		if record.State == stateNameCompleted && record.TheirDID == theirDID {
			return record, nil
		}
	}

	return nil, fmt.Errorf(errMsgConnectionMatchingDIDNotFound, theirDID)
}

func (o *Command) sendMessageToConnection(msg json.RawMessage, conn *connection.Record) command.Error {
	err := o.ctx.OutboundDispatcher().SendToDID(msg, conn.MyDID, conn.TheirDID)
	if err != nil {
		return command.NewExecuteError(SendMsgError, err)
	}

	return nil
}

func (o *Command) sendMessageToDestination(msg json.RawMessage, dest *ServiceEndpointDestinationParams) command.Error {
	_, sigPubKey, err := o.ctx.LegacyKMS().CreateKeySet()
	if err != nil {
		return command.NewExecuteError(SendMsgError, err)
	}

	err = o.ctx.OutboundDispatcher().Send(msg, sigPubKey, &service.Destination{
		RoutingKeys:     dest.RoutingKeys,
		RecipientKeys:   dest.RecipientKeys,
		ServiceEndpoint: dest.ServiceEndpoint,
	})
	if err != nil {
		return command.NewExecuteError(SendMsgError, err)
	}

	return nil
}
