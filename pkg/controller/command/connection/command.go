/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connection

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/didrotate"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
)

var logger = log.New("aries-framework/controller/connection")

// constants for connection management endpoints.
const (
	CommandName = "connection"

	RotateDIDCommandMethod = "RotateDID"

	errEmptyConnID = "empty connection ID"
	errEmptyKID    = "empty signing KID"
	errEmptyNewDID = "empty new DID"

	// log constants.
	connectionIDString = "connectionID"
	newDIDString       = "newDID"
	successString      = "success"
)

const (
	// InvalidRequestErrorCode is typically a code for validation errors
	// for invalid connection controller requests.
	InvalidRequestErrorCode = command.Code(iota + command.Connection)
)

type provider interface {
	DIDRotator() *didrotate.DIDRotator
}

// Command provides controller API for connection commands.
type Command struct {
	didRotator *didrotate.DIDRotator
}

// New creates connection Command.
func New(prov provider) *Command {
	return &Command{
		didRotator: prov.DIDRotator(),
	}
}

// GetHandlers returns list of all commands supported by this controller command.
func (c *Command) GetHandlers() []command.Handler {
	return []command.Handler{
		cmdutil.NewCommandHandler(CommandName, RotateDIDCommandMethod, c.RotateDID),
	}
}

// RotateDIDGivenConnIDCmd takes a connection ID and returns a command.Exec that rotates the given connection's DID.
func (c *Command) RotateDIDGivenConnIDCmd(connID string) command.Exec {
	return func(rw io.Writer, req io.Reader) command.Error {
		var request RotateDIDRequest

		err := json.NewDecoder(req).Decode(&request)
		if err != nil {
			logutil.LogInfo(logger, CommandName, RotateDIDCommandMethod, err.Error())

			return command.NewValidationError(InvalidRequestErrorCode, err)
		}

		request.ID = connID

		return c.rotateDID(&request)
	}
}

// RotateDID handles a didcomm v2 DID rotation request.
func (c *Command) RotateDID(rw io.Writer, req io.Reader) command.Error {
	var request RotateDIDRequest

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, RotateDIDCommandMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	return c.rotateDID(&request)
}

func (c *Command) rotateDID(request *RotateDIDRequest) command.Error {
	if request.ID == "" {
		logutil.LogDebug(logger, CommandName, RotateDIDCommandMethod, errEmptyConnID)

		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyConnID))
	}

	if request.KID == "" {
		logutil.LogDebug(logger, CommandName, RotateDIDCommandMethod, errEmptyKID)

		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyKID))
	}

	if request.NewDID == "" {
		logutil.LogDebug(logger, CommandName, RotateDIDCommandMethod, errEmptyNewDID)

		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyNewDID))
	}

	err := c.didRotator.RotateConnectionDID(request.ID, request.KID, request.NewDID)
	if err != nil {
		logutil.LogDebug(logger, CommandName, RotateDIDCommandMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	logutil.LogDebug(logger, CommandName, RotateDIDCommandMethod, successString,
		logutil.CreateKeyValueString(connectionIDString, request.ID),
		logutil.CreateKeyValueString(newDIDString, request.NewDID),
	)

	return nil
}
