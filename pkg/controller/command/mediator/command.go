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

	// StatusRequestMissingConnIDCode for connection ID validation error.
	StatusRequestMissingConnIDCode

	// StatusRequestErrorCode for status request error.
	StatusRequestErrorCode

	// BatchPickupMissingConnIDCode for connection ID validation error.
	BatchPickupMissingConnIDCode

	// BatchPickupRequestErrorCode for batch pick up error.
	BatchPickupRequestErrorCode
)

// constant for the mediator controller
const (
	// command name
	CommandName = "mediator"

	// command methods
	RegisterCommandMethod        = "Register"
	UnregisterCommandMethod      = "Unregister"
	GetConnectionIDCommandMethod = "Connection"
	ReconnectCommandMethod       = "Reconnect"
	StatusCommandMethod          = "Status"
	BatchPickupCommandMethod     = "BatchPickup"

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
		cmdutil.NewCommandHandler(CommandName, RegisterCommandMethod, o.Register),
		cmdutil.NewCommandHandler(CommandName, UnregisterCommandMethod, o.Unregister),
		cmdutil.NewCommandHandler(CommandName, GetConnectionIDCommandMethod, o.Connection),
		cmdutil.NewCommandHandler(CommandName, ReconnectCommandMethod, o.Reconnect),
		cmdutil.NewCommandHandler(CommandName, StatusCommandMethod, o.Reconnect),
		cmdutil.NewCommandHandler(CommandName, BatchPickupCommandMethod, o.Reconnect),
	}
}

// Register registers the agent with the router.
// nolint:dupl
func (o *Command) Register(rw io.Writer, req io.Reader) command.Error {
	var request RegisterRoute

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, RegisterCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	if request.ConnectionID == "" {
		logutil.LogDebug(logger, CommandName, RegisterCommandMethod, "missing connectionID",
			logutil.CreateKeyValueString(connectionID, request.ConnectionID))
		return command.NewValidationError(RegisterMissingConnIDCode, errors.New("connectionID is mandatory"))
	}

	err = o.routeClient.Register(request.ConnectionID)
	if err != nil {
		logutil.LogError(logger, CommandName, RegisterCommandMethod, err.Error(),
			logutil.CreateKeyValueString(connectionID, request.ConnectionID))
		return command.NewExecuteError(RegisterRouterErrorCode, err)
	}

	command.WriteNillableResponse(rw, nil, logger)

	logutil.LogDebug(logger, CommandName, RegisterCommandMethod, successString,
		logutil.CreateKeyValueString(connectionID, request.ConnectionID))

	return nil
}

// Unregister unregisters the agent with the router.
func (o *Command) Unregister(rw io.Writer, req io.Reader) command.Error {
	err := o.routeClient.Unregister()
	if err != nil {
		logutil.LogError(logger, CommandName, UnregisterCommandMethod, err.Error())
		return command.NewExecuteError(UnregisterRouterErrorCode, err)
	}

	command.WriteNillableResponse(rw, nil, logger)

	logutil.LogDebug(logger, CommandName, UnregisterCommandMethod, successString)

	return nil
}

// Connection returns the connectionID of the router.
func (o *Command) Connection(rw io.Writer, req io.Reader) command.Error {
	connectionID, err := o.routeClient.GetConnection()
	if err != nil {
		logutil.LogError(logger, CommandName, GetConnectionIDCommandMethod, err.Error())
		return command.NewExecuteError(GetConnectionIDErrorCode, err)
	}

	command.WriteNillableResponse(rw, &RegisterRoute{
		ConnectionID: connectionID,
	}, logger)

	logutil.LogDebug(logger, CommandName, GetConnectionIDCommandMethod, successString)

	return nil
}

// Reconnect sends noop message to reestablish a connection when there is no other reason to message the mediator
// nolint:dupl
func (o *Command) Reconnect(rw io.Writer, req io.Reader) command.Error {
	var request RegisterRoute

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, ReconnectCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	if request.ConnectionID == "" {
		logutil.LogDebug(logger, CommandName, ReconnectCommandMethod, "missing connectionID",
			logutil.CreateKeyValueString(connectionID, request.ConnectionID))
		return command.NewValidationError(ReconnectMissingConnIDCode, errors.New("connectionID is mandatory"))
	}

	err = o.messageClient.Noop(request.ConnectionID)
	if err != nil {
		logutil.LogError(logger, CommandName, ReconnectCommandMethod, err.Error(),
			logutil.CreateKeyValueString(connectionID, request.ConnectionID))
		return command.NewExecuteError(ReconnectRouterErrorCode, err)
	}

	command.WriteNillableResponse(rw, nil, logger)

	logutil.LogDebug(logger, CommandName, ReconnectCommandMethod, successString,
		logutil.CreateKeyValueString(connectionID, request.ConnectionID))

	return nil
}

// Status returns details about pending messages for given connection.
func (o *Command) Status(rw io.Writer, req io.Reader) command.Error {
	var request StatusRequest

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogError(logger, CommandName, StatusCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	if request.ConnectionID == "" {
		logutil.LogDebug(logger, CommandName, StatusCommandMethod, "missing connectionID",
			logutil.CreateKeyValueString(connectionID, request.ConnectionID))
		return command.NewValidationError(StatusRequestMissingConnIDCode, errors.New("connectionID is mandatory"))
	}

	status, err := o.messageClient.StatusRequest(request.ConnectionID)
	if err != nil {
		logutil.LogError(logger, CommandName, StatusCommandMethod, err.Error(),
			logutil.CreateKeyValueString(connectionID, request.ConnectionID))
		return command.NewExecuteError(StatusRequestErrorCode, err)
	}

	command.WriteNillableResponse(rw, &StatusResponse{status}, logger)

	logutil.LogDebug(logger, CommandName, StatusCommandMethod, successString,
		logutil.CreateKeyValueString(connectionID, request.ConnectionID))

	return nil
}

// BatchPickup dispatches pending messages for given connection.
func (o *Command) BatchPickup(rw io.Writer, req io.Reader) command.Error {
	var request BatchPickupRequest

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, BatchPickupCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	if request.ConnectionID == "" {
		logutil.LogDebug(logger, CommandName, BatchPickupCommandMethod, "missing connectionID",
			logutil.CreateKeyValueString(connectionID, request.ConnectionID))
		return command.NewValidationError(BatchPickupMissingConnIDCode, errors.New("connectionID is mandatory"))
	}

	count, err := o.messageClient.BatchPickup(request.ConnectionID, request.Size)
	if err != nil {
		logutil.LogError(logger, CommandName, BatchPickupCommandMethod, err.Error(),
			logutil.CreateKeyValueString(connectionID, request.ConnectionID))
		return command.NewExecuteError(BatchPickupRequestErrorCode, err)
	}

	command.WriteNillableResponse(rw, &BatchPickupResponse{count}, logger)

	logutil.LogDebug(logger, CommandName, BatchPickupCommandMethod, successString,
		logutil.CreateKeyValueString(connectionID, request.ConnectionID))

	return nil
}
