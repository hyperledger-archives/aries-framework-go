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
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/service/http"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
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
	errMsgConnectionMatchingDIDNotFound = "unable to find connection matching DID"
	errMsgIDEmpty                       = "empty message ID"

	// command methods
	registeredServicesCommandMethod         = "Services"
	registerMessageServiceCommandMethod     = "RegisterService"
	unregisterMessageServiceCommandMethod   = "UnregisterService"
	registerHTTPMessageServiceCommandMethod = "RegisterHTTPService"
	sendNewMessageCommandMethod             = "Send"
	sendReplyMessageCommandMethod           = "Reply"

	// log constants
	connectionIDString = "connectionID"
	destinationString  = "destination"
	destinationDID     = "destinationDID"
	replyTo            = "replyTo"
	successString      = "success"
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

// errConnForDIDNotFound when matching connection ID not found
var errConnForDIDNotFound = fmt.Errorf(errMsgConnectionMatchingDIDNotFound)

// provider contains dependencies for the messaging controller command operations
// and is typically created by using aries.Context()
type provider interface {
	VDRIRegistry() vdri.Registry
	Messenger() service.Messenger
	ProtocolStateStorageProvider() storage.Provider
	StorageProvider() storage.Provider
	LegacyKMS() legacykms.KeyManager
}

// Command contains basic command operations provided by messaging controller command
type Command struct {
	ctx              provider
	msgRegistrar     command.MessageHandler
	notifier         command.Notifier
	connectionLookup *connection.Lookup
}

// New returns new command instance for messaging controller API
func New(ctx provider, registrar command.MessageHandler, notifier command.Notifier) (*Command, error) {
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
		cmdutil.NewCommandHandler(commandName, registeredServicesCommandMethod, o.Services),
		cmdutil.NewCommandHandler(commandName, registerMessageServiceCommandMethod, o.RegisterService),
		cmdutil.NewCommandHandler(commandName, unregisterMessageServiceCommandMethod, o.UnregisterService),
		cmdutil.NewCommandHandler(commandName, registerHTTPMessageServiceCommandMethod, o.RegisterHTTPService),
		cmdutil.NewCommandHandler(commandName, sendNewMessageCommandMethod, o.Send),
		cmdutil.NewCommandHandler(commandName, sendReplyMessageCommandMethod, o.Reply),
	}
}

// RegisterService registers new message service to message handler registrar
func (o *Command) RegisterService(rw io.Writer, req io.Reader) command.Error {
	var request RegisterMsgSvcArgs

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, commandName, registerMessageServiceCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	return o.registerMessageService(&request)
}

// UnregisterService unregisters given message service handler registrar
func (o *Command) UnregisterService(rw io.Writer, req io.Reader) command.Error {
	var request UnregisterMsgSvcArgs

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, commandName, unregisterMessageServiceCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if request.Name == "" {
		logutil.LogDebug(logger, commandName, unregisterMessageServiceCommandMethod, errMsgSvcNameRequired)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errMsgSvcNameRequired))
	}

	err = o.msgRegistrar.Unregister(request.Name)
	if err != nil {
		logutil.LogError(logger, commandName, registerMessageServiceCommandMethod, err.Error(),
			logutil.CreateKeyValueString("name", request.Name))

		return command.NewExecuteError(UnregisterMsgSvcError, err)
	}

	logutil.LogDebug(logger, commandName, unregisterMessageServiceCommandMethod, successString,
		logutil.CreateKeyValueString("name", request.Name))

	return nil
}

// Services returns list of registered service names
func (o *Command) Services(rw io.Writer, req io.Reader) command.Error {
	names := []string{}
	for _, svc := range o.msgRegistrar.Services() {
		names = append(names, svc.Name())
	}

	command.WriteNillableResponse(rw, RegisteredServicesResponse{Names: names}, logger)

	logutil.LogDebug(logger, commandName, registeredServicesCommandMethod, successString)

	return nil
}

// Send sends new message to destination provided
func (o *Command) Send(rw io.Writer, req io.Reader) command.Error {
	var request SendNewMessageArgs

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, commandName, sendNewMessageCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if len(request.MessageBody) == 0 {
		logutil.LogDebug(logger, commandName, sendNewMessageCommandMethod, errMsgBodyEmpty)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errMsgBodyEmpty))
	}

	err = o.validateMessageDestination(&request)
	if err != nil {
		logutil.LogError(logger, commandName, sendNewMessageCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if request.ConnectionID != "" {
		conn, err := o.connectionLookup.GetConnectionRecord(request.ConnectionID)
		if err != nil {
			logutil.LogError(logger, commandName, sendNewMessageCommandMethod, err.Error(),
				logutil.CreateKeyValueString(connectionIDString, request.ConnectionID))

			return command.NewExecuteError(SendMsgError, err)
		}

		return o.sendToConnection(request.MessageBody, conn)
	}

	if request.TheirDID != "" {
		conn, err := o.getConnectionByTheirDID(request.TheirDID)
		if err != nil && err != errConnForDIDNotFound {
			logutil.LogError(logger, commandName, sendNewMessageCommandMethod, err.Error())
			return command.NewExecuteError(SendMsgError, err)
		}

		if conn != nil {
			return o.sendToConnection(request.MessageBody, conn)
		}
	}

	return o.sendToDestination(&request)
}

// Reply sends reply to existing message
func (o *Command) Reply(rw io.Writer, req io.Reader) command.Error {
	var request SendReplyMessageArgs

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, commandName, sendReplyMessageCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if len(request.MessageBody) == 0 {
		logutil.LogDebug(logger, commandName, sendReplyMessageCommandMethod, errMsgBodyEmpty)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errMsgBodyEmpty))
	}

	if request.MessageID == "" {
		logutil.LogDebug(logger, commandName, sendReplyMessageCommandMethod, errMsgIDEmpty)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errMsgIDEmpty))
	}

	msg, err := service.ParseDIDCommMsgMap(request.MessageBody)
	if err != nil {
		logutil.LogError(logger, commandName, sendReplyMessageCommandMethod, err.Error(),
			logutil.CreateKeyValueString(replyTo, request.MessageID))
		return command.NewExecuteError(SendMsgReplyError, err)
	}

	err = o.ctx.Messenger().ReplyTo(request.MessageID, msg)
	if err != nil {
		logutil.LogError(logger, commandName, sendReplyMessageCommandMethod, err.Error(),
			logutil.CreateKeyValueString(replyTo, request.MessageID))
		return command.NewExecuteError(SendMsgReplyError, err)
	}

	return nil
}

// RegisterHTTPService registers new http over didcomm service to message handler registrar
func (o *Command) RegisterHTTPService(rw io.Writer, req io.Reader) command.Error {
	var request RegisterHTTPMsgSvcArgs

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, commandName, registerHTTPMessageServiceCommandMethod, err.Error())
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
		logutil.LogDebug(logger, commandName, registerMessageServiceCommandMethod, errMsgSvcNameRequired)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errMsgSvcNameRequired))
	}

	if params.Type == "" {
		logutil.LogDebug(logger, commandName, registerMessageServiceCommandMethod, errMsgInvalidAcceptanceCrit)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errMsgInvalidAcceptanceCrit))
	}

	err := o.msgRegistrar.Register(newMessageService(params, o.notifier))
	if err != nil {
		logutil.LogError(logger, commandName, registerMessageServiceCommandMethod, err.Error(),
			logutil.CreateKeyValueString("name", params.Name),
			logutil.CreateKeyValueString("type", params.Type))

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

	return nil, errConnForDIDNotFound
}

func (o *Command) sendToConnection(msg json.RawMessage, conn *connection.Record) command.Error {
	didcommMsg, err := service.ParseDIDCommMsgMap(msg)
	if err != nil {
		logutil.LogError(logger, commandName, sendNewMessageCommandMethod, err.Error(),
			logutil.CreateKeyValueString(connectionIDString, conn.ConnectionID))
		return command.NewExecuteError(SendMsgError, err)
	}

	err = o.ctx.Messenger().Send(didcommMsg, conn.MyDID, conn.TheirDID)
	if err != nil {
		logutil.LogError(logger, commandName, sendNewMessageCommandMethod, err.Error(),
			logutil.CreateKeyValueString(connectionIDString, conn.ConnectionID))
		return command.NewExecuteError(SendMsgError, err)
	}

	logutil.LogDebug(logger, commandName, sendNewMessageCommandMethod, successString,
		logutil.CreateKeyValueString(connectionIDString, conn.ConnectionID))

	return nil
}

func (o *Command) sendToDestination(rqst *SendNewMessageArgs) command.Error {
	var dest *service.Destination

	// prepare destination
	if rqst.TheirDID != "" {
		var err error

		dest, err = service.GetDestination(rqst.TheirDID, o.ctx.VDRIRegistry())
		if err != nil {
			logutil.LogError(logger, commandName, sendNewMessageCommandMethod, err.Error(),
				logutil.CreateKeyValueString(destinationDID, rqst.TheirDID))

			return command.NewExecuteError(SendMsgError, err)
		}
	} else if rqst.ServiceEndpointDestination != nil {
		dest = &service.Destination{
			RoutingKeys:     rqst.ServiceEndpointDestination.RoutingKeys,
			RecipientKeys:   rqst.ServiceEndpointDestination.RecipientKeys,
			ServiceEndpoint: rqst.ServiceEndpointDestination.ServiceEndpoint,
		}
	}

	if dest == nil {
		logutil.LogError(logger, commandName, sendNewMessageCommandMethod, errMsgDestinationMissing)

		return command.NewExecuteError(SendMsgError, fmt.Errorf(errMsgDestinationMissing))
	}

	_, sigPubKey, err := o.ctx.LegacyKMS().CreateKeySet()
	if err != nil {
		logutil.LogError(logger, commandName, sendNewMessageCommandMethod, err.Error(),
			logutil.CreateKeyValueString(destinationString, dest.ServiceEndpoint))

		return command.NewExecuteError(SendMsgError, err)
	}

	didcommMsg, err := service.ParseDIDCommMsgMap(rqst.MessageBody)
	if err != nil {
		logutil.LogError(logger, commandName, sendNewMessageCommandMethod, err.Error(),
			logutil.CreateKeyValueString(destinationString, dest.ServiceEndpoint))
		return command.NewExecuteError(SendMsgError, err)
	}

	err = o.ctx.Messenger().SendToDestination(didcommMsg, sigPubKey, dest)
	if err != nil {
		logutil.LogError(logger, commandName, sendNewMessageCommandMethod, err.Error(),
			logutil.CreateKeyValueString(destinationString, dest.ServiceEndpoint))

		return command.NewExecuteError(SendMsgError, err)
	}

	logutil.LogDebug(logger, commandName, sendNewMessageCommandMethod, successString,
		logutil.CreateKeyValueString(destinationString, dest.ServiceEndpoint))

	return nil
}
