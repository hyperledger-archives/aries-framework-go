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
	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	mediatorSvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

var logger = log.New("aries-framework/command/route")

// Error codes.
const (
	// InvalidRequestErrorCode for invalid requests.
	InvalidRequestErrorCode = command.Code(iota + command.ROUTE)

	// ResponseWriteErrorCode for connection ID validation error.
	RegisterMissingConnIDCode

	// RegisterRouterErrorCode for register router error.
	RegisterRouterErrorCode

	// UnregisterRouterErrorCode for unregister router error.
	UnregisterRouterErrorCode

	// GetConnectionsErrorCode for get connections error.
	GetConnectionsErrorCode

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

	// ReconnectAllError is typically a code for mediator reconnectAll errors.
	ReconnectAllError
)

// constant for the mediator controller.
const (
	// command name.
	CommandName = "mediator"

	// command methods.
	RegisterCommandMethod       = "Register"
	UnregisterCommandMethod     = "Unregister"
	GetConnectionsCommandMethod = "Connections"
	ReconnectCommandMethod      = "Reconnect"
	StatusCommandMethod         = "Status"
	BatchPickupCommandMethod    = "BatchPickup"
	ReconnectAllCommandMethod   = "ReconnectAll"

	// log constants.
	connectionID  = "connectionID"
	successString = "success"
)

// provider contains dependencies for the route protocol and is typically created by using aries.Context().
type provider interface {
	Service(id string) (interface{}, error)
	KMS() kms.KeyManager
	ServiceEndpoint() string
	KeyType() kms.KeyType
	KeyAgreementType() kms.KeyType
	MediaTypeProfiles() []string
}

// Command contains command operations provided by route controller.
type Command struct {
	routeClient   *mediator.Client
	messageClient *messagepickup.Client
	outOfBand     *outofband.Client
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

	outOfBandClient, err := outofband.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create out-of-band client : %w", err)
	}

	return &Command{
		routeClient:   routeClient,
		messageClient: messageClient,
		outOfBand:     outOfBandClient,
	}, nil
}

// GetHandlers returns list of all commands supported by this controller command.
func (o *Command) GetHandlers() []command.Handler {
	return []command.Handler{
		cmdutil.NewCommandHandler(CommandName, RegisterCommandMethod, o.Register),
		cmdutil.NewCommandHandler(CommandName, UnregisterCommandMethod, o.Unregister),
		cmdutil.NewCommandHandler(CommandName, GetConnectionsCommandMethod, o.Connections),
		cmdutil.NewCommandHandler(CommandName, ReconnectCommandMethod, o.Reconnect),
		cmdutil.NewCommandHandler(CommandName, ReconnectAllCommandMethod, o.ReconnectAll),
		cmdutil.NewCommandHandler(CommandName, StatusCommandMethod, o.Status),
		cmdutil.NewCommandHandler(CommandName, BatchPickupCommandMethod, o.BatchPickup),
	}
}

// Register registers the agent with the router.
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
	var request RegisterRoute

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, UnregisterCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	if request.ConnectionID == "" {
		logutil.LogDebug(logger, CommandName, UnregisterCommandMethod, "missing connectionID",
			logutil.CreateKeyValueString(connectionID, request.ConnectionID))
		return command.NewValidationError(UnregisterRouterErrorCode, errors.New("connectionID is mandatory"))
	}

	err = o.routeClient.Unregister(request.ConnectionID)
	if err != nil {
		logutil.LogError(logger, CommandName, UnregisterCommandMethod, err.Error())
		return command.NewExecuteError(UnregisterRouterErrorCode, err)
	}

	command.WriteNillableResponse(rw, nil, logger)

	logutil.LogDebug(logger, CommandName, UnregisterCommandMethod, successString)

	return nil
}

// Connections returns the connections of the router.
func (o *Command) Connections(rw io.Writer, req io.Reader) command.Error {
	var request ConnectionsRequest

	if req != nil {
		reqData, err := io.ReadAll(req)
		if err != nil {
			logutil.LogInfo(logger, CommandName, GetConnectionsCommandMethod, err.Error())
			return command.NewValidationError(GetConnectionsErrorCode, fmt.Errorf("read request : %w", err))
		}

		if len(reqData) > 0 {
			err = json.Unmarshal(reqData, &request)
			if err != nil {
				logutil.LogInfo(logger, CommandName, GetConnectionsCommandMethod, err.Error())
				return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("decode request : %w", err))
			}
		}
	}

	opts := []mediator.ConnectionOption{}

	switch {
	case request.DIDCommV1Only && request.DIDCommV2Only:
		errMsg := "can't request didcomm v1 only at the same time as didcomm v2 only"

		logutil.LogError(logger, CommandName, GetConnectionsCommandMethod, errMsg)

		return command.NewValidationError(GetConnectionsErrorCode, fmt.Errorf("%s", errMsg))
	case request.DIDCommV2Only:
		opts = append(opts, mediatorSvc.ConnectionByVersion(service.V2))
	case request.DIDCommV1Only:
		opts = append(opts, mediatorSvc.ConnectionByVersion(service.V1))
	}

	connections, err := o.routeClient.GetConnections(opts...)
	if err != nil {
		logutil.LogError(logger, CommandName, GetConnectionsCommandMethod, err.Error())
		return command.NewExecuteError(GetConnectionsErrorCode, err)
	}

	command.WriteNillableResponse(rw, &ConnectionsResponse{
		Connections: connections,
	}, logger)

	logutil.LogDebug(logger, CommandName, GetConnectionsCommandMethod, successString)

	return nil
}

// Reconnect sends noop message to given connection to re-establish a network connection.
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

// ReconnectAll performs reconnection on all available mediator connections.
// This command is useful in re-establishing lost connections (ex: lost websocket connection).
func (o *Command) ReconnectAll(rw io.Writer, req io.Reader) command.Error {
	connections, err := o.routeClient.GetConnections()
	if err != nil {
		logutil.LogError(logger, CommandName, ReconnectAllCommandMethod, err.Error())

		return command.NewExecuteError(ReconnectAllError, err)
	}

	for _, connection := range connections {
		err = o.messageClient.Noop(connection)
		if err != nil {
			logutil.LogError(logger, CommandName, ReconnectAllCommandMethod, err.Error(),
				logutil.CreateKeyValueString(connectionID, connection))
			return command.NewExecuteError(ReconnectRouterErrorCode, err)
		}
	}

	command.WriteNillableResponse(rw, nil, logger)

	logutil.LogDebug(logger, CommandName, ReconnectAllCommandMethod, successString)

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
