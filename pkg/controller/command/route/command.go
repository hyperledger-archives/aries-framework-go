/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package route

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/hyperledger/aries-framework-go/pkg/client/route"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
)

var logger = log.New("aries-framework/command/route")

// Error codes
const (
	// InvalidRequestErrorCode for invalid requests
	InvalidRequestErrorCode = command.Code(iota + command.ROUTE)

	// ResponseWriteErrorCode for response write error
	RegisterMissingConnIDCode

	// RegisterRouterErrorCode for register router error
	RegisterRouterErrorCode

	// UnregisterRouterErrorCode for unregister router error
	UnregisterRouterErrorCode

	// GetConnection for get connection id error
	GetConnectionIDErrorCode
)

const (
	// command name
	commandName = "router"

	// command methods
	registerCommandMethod        = "Register"
	unregisterCommandMethod      = "Unregister"
	getConnectionIDCommandMethod = "GetConnection"

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
	routeClient *route.Client
}

// New returns new route controller command instance.
func New(ctx provider) (*Command, error) {
	routeClient, err := route.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("create route client : %w", err)
	}

	return &Command{
		routeClient: routeClient,
	}, nil
}

// GetHandlers returns list of all commands supported by this controller command
func (o *Command) GetHandlers() []command.Handler {
	return []command.Handler{
		cmdutil.NewCommandHandler(commandName, registerCommandMethod, o.Register),
		cmdutil.NewCommandHandler(commandName, unregisterCommandMethod, o.Unregister),
		cmdutil.NewCommandHandler(commandName, getConnectionIDCommandMethod, o.GetConnection),
	}
}

// Register registers the agent with the router.
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

// GetConnection returns the connectionID of the router.
func (o *Command) GetConnection(rw io.Writer, req io.Reader) command.Error {
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
