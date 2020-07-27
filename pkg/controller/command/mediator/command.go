/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mediator

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/hyperledger/aries-framework-go/pkg/client/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/client/messagepickup"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
)

var logger = log.New("aries-framework/command/route")

// Error codes
const (
	// InvalidRequestErrorCode for invalid requests.
	InvalidRequestErrorCode = command.Code(iota + command.ROUTE)

	// ResponseWriteErrorCode for connection ID validation error.
	RegisterMissingConnIDCode

	// RegisterRouterErrorCode for register router error.
	RegisterRouterErrorCode

	// UnregisterRouterErrorCode for unregister router error.
	UnregisterRouterErrorCode

	// Connection for get connection id error.
	GetConnectionIDErrorCode

	// ReconnectMissingConnIDCode for connection ID validation error.
	ReconnectMissingConnIDCode

	// ReconnectRouterErrorCode for reconnecting router error.
	ReconnectRouterErrorCode
)

const (
	// command name
	commandName = "mediator"

	// command methods
	registerCommandMethod        = "Register"
	unregisterCommandMethod      = "Unregister"
	getConnectionIDCommandMethod = "Connection"
	reconnectCommandMethod       = "Reconnect"

	// log constants
	connectionID  = "connectionID"
	successString = "success"
)

// provider contains dependencies for the route protocol and is typically created by using aries.Context().
type provider interface {
	Service(id string) (interface{}, error)
}

// Command contains command operations provided by route controller.
type Command struct {
	routeClient   *mediator.Client
	messageClient *messagepickup.Client
}

// New returns new route controller command instance.
func New(ctx provider, autoAccept bool) (*Command, error) {
	routeClient, err := mediator.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("create route client : %w", err)
	}

	if !autoAccept {
		// TODO add support sending action approvals to webhooks
		autoAccept = true
	}

	if autoAccept {
		actions := make(chan service.DIDCommAction)

		err = routeClient.RegisterActionEvent(actions)
		if err != nil {
			return nil, fmt.Errorf("failed to register action events : %w", err)
		}

		go service.AutoExecuteActionEvent(actions)
	}

	messageClient, err := messagepickup.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create message client : %w", err)
	}

	return &Command{
		routeClient:   routeClient,
		messageClient: messageClient,
	}, nil
}

// GetHandlers returns list of all commands supported by this controller command.
func (o *Command) GetHandlers() []command.Handler {
	return []command.Handler{
		cmdutil.NewCommandHandler(commandName, registerCommandMethod, o.Register),
		cmdutil.NewCommandHandler(commandName, unregisterCommandMethod, o.Unregister),
		cmdutil.NewCommandHandler(commandName, getConnectionIDCommandMethod, o.Connection),
		cmdutil.NewCommandHandler(commandName, reconnectCommandMethod, o.Reconnect),
	}
}

// Register registers the agent with the router.
// nolint:dupl
func (o *Command) Register(rw io.Writer, req io.Reader) command.Error {
	var request RegisterRoute

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, commandName, registerCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	if request.ConnectionID == "" {
		logutil.LogDebug(logger, commandName, registerCommandMethod, "missing connectionID",
			logutil.CreateKeyValueString(connectionID, request.ConnectionID))
		return command.NewValidationError(RegisterMissingConnIDCode, errors.New("connectionID is mandatory"))
	}

	err = o.routeClient.Register(request.ConnectionID)
	if err != nil {
		logutil.LogError(logger, commandName, registerCommandMethod, err.Error(),
			logutil.CreateKeyValueString(connectionID, request.ConnectionID))
		return command.NewExecuteError(RegisterRouterErrorCode, err)
	}

	command.WriteNillableResponse(rw, nil, logger)

	logutil.LogDebug(logger, commandName, registerCommandMethod, successString,
		logutil.CreateKeyValueString(connectionID, request.ConnectionID))

	return nil
}

// Unregister unregisters the agent with the router.
func (o *Command) Unregister(rw io.Writer, req io.Reader) command.Error {
	err := o.routeClient.Unregister()
	if err != nil {
		logutil.LogError(logger, commandName, registerCommandMethod, err.Error())
		return command.NewExecuteError(UnregisterRouterErrorCode, err)
	}

	command.WriteNillableResponse(rw, nil, logger)

	logutil.LogDebug(logger, commandName, registerCommandMethod, successString)

	return nil
}

// Connection returns the connectionID of the router.
func (o *Command) Connection(rw io.Writer, req io.Reader) command.Error {
	connectionID, err := o.routeClient.GetConnection()
	if err != nil {
		logutil.LogError(logger, commandName, getConnectionIDCommandMethod, err.Error())
		return command.NewExecuteError(GetConnectionIDErrorCode, err)
	}

	command.WriteNillableResponse(rw, &RegisterRoute{
		ConnectionID: connectionID,
	}, logger)

	logutil.LogDebug(logger, commandName, getConnectionIDCommandMethod, successString)

	return nil
}

// Reconnect sends noop message to reestablish a connection when there is no other reason to message the mediator
// nolint:dupl
func (o *Command) Reconnect(rw io.Writer, req io.Reader) command.Error {
	var request RegisterRoute

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, commandName, reconnectCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	if request.ConnectionID == "" {
		logutil.LogDebug(logger, commandName, reconnectCommandMethod, "missing connectionID",
			logutil.CreateKeyValueString(connectionID, request.ConnectionID))
		return command.NewValidationError(ReconnectMissingConnIDCode, errors.New("connectionID is mandatory"))
	}

	err = o.messageClient.Noop(request.ConnectionID)
	if err != nil {
		logutil.LogError(logger, commandName, reconnectCommandMethod, err.Error(),
			logutil.CreateKeyValueString(connectionID, request.ConnectionID))
		return command.NewExecuteError(ReconnectRouterErrorCode, err)
	}

	command.WriteNillableResponse(rw, nil, logger)

	logutil.LogDebug(logger, commandName, reconnectCommandMethod, successString,
		logutil.CreateKeyValueString(connectionID, request.ConnectionID))

	return nil
}
