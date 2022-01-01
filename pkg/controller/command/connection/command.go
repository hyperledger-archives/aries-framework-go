/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connection

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/hyperledger/aries-framework-go/pkg/client/connection"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/middleware"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/store/did"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

var logger = log.New("aries-framework/controller/connection")

// constants for connection management endpoints.
const (
	CommandName = "connection"

	RotateDIDCommandMethod = "RotateDID"
	CreateV2CommandMethod  = "CreateConnectionV2"
	SetToV2CommandMethod   = "SetConnectionToDIDCommV2"

	errEmptyConnID   = "empty connection ID"
	errEmptyKID      = "empty signing KID"
	errEmptyNewDID   = "empty new DID"
	errEmptyMyDID    = "empty my DID"
	errEmptyTheirDID = "empty their DID"

	// log constants.
	connectionIDString = "connectionID"
	newDIDString       = "newDID"
	successString      = "success"
)

const (
	// InvalidRequestErrorCode is typically a code for validation errors
	// for invalid connection controller requests.
	InvalidRequestErrorCode = command.Code(iota + command.Connection)

	// CreateConnectionErrorCode is for failures in create connection command.
	CreateConnectionErrorCode
	// SetToDIDCommV2ErrorCode is for failures in create peer DID command.
	SetToDIDCommV2ErrorCode
	// RotateDIDErrorCode is for failures in rotate DID command.
	RotateDIDErrorCode
)

type provider interface {
	VDRegistry() vdr.Registry
	DIDRotator() *middleware.DIDCommMessageMiddleware
	StorageProvider() storage.Provider
	ProtocolStateStorageProvider() storage.Provider
	DIDConnectionStore() did.ConnectionStore
	KMS() kms.KeyManager
	KeyType() kms.KeyType
	KeyAgreementType() kms.KeyType
}

// Command provides controller API for connection commands.
type Command struct {
	client *connection.Client
}

// New creates connection Command.
func New(prov provider) (*Command, error) {
	client, err := connection.New(prov)
	if err != nil {
		return nil, fmt.Errorf("creating client: %w", err)
	}

	return &Command{
		client: client,
	}, nil
}

// GetHandlers returns list of all commands supported by this controller command.
func (c *Command) GetHandlers() []command.Handler {
	return []command.Handler{
		cmdutil.NewCommandHandler(CommandName, RotateDIDCommandMethod, c.RotateDID),
		cmdutil.NewCommandHandler(CommandName, CreateV2CommandMethod, c.CreateConnectionV2),
		cmdutil.NewCommandHandler(CommandName, SetToV2CommandMethod, c.SetConnectionToDIDCommV2),
	}
}

// CreateConnectionV2 creates a DIDComm v2 connection.
func (c *Command) CreateConnectionV2(rw io.Writer, req io.Reader) command.Error {
	var request CreateConnectionRequest

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, CreateV2CommandMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if request.MyDID == "" {
		logutil.LogDebug(logger, CommandName, CreateV2CommandMethod, errEmptyMyDID)

		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyMyDID))
	}

	if request.TheirDID == "" {
		logutil.LogDebug(logger, CommandName, CreateV2CommandMethod, errEmptyTheirDID)

		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyTheirDID))
	}

	connID, err := c.client.CreateConnectionV2(request.MyDID, request.TheirDID)
	if err != nil {
		logutil.LogInfo(logger, CommandName, CreateV2CommandMethod, err.Error())

		return command.NewExecuteError(CreateConnectionErrorCode, err)
	}

	command.WriteNillableResponse(rw, &IDMessage{
		ConnectionID: connID,
	}, logger)

	logutil.LogDebug(logger, CommandName, CreateV2CommandMethod, successString,
		logutil.CreateKeyValueString(connectionIDString, connID))

	return nil
}

// SetConnectionToDIDCommV2 sets that a connection is using didcomm v2, and associated versions of protocols.
func (c *Command) SetConnectionToDIDCommV2(_ io.Writer, req io.Reader) command.Error {
	var request IDMessage

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, SetToV2CommandMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if request.ConnectionID == "" {
		logutil.LogInfo(logger, CommandName, SetToV2CommandMethod, errEmptyConnID)

		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyConnID))
	}

	err = c.client.SetConnectionToDIDCommV2(request.ConnectionID)
	if err != nil {
		logutil.LogInfo(logger, CommandName, SetToV2CommandMethod, err.Error())

		return command.NewExecuteError(SetToDIDCommV2ErrorCode, err)
	}

	logutil.LogDebug(logger, CommandName, SetToV2CommandMethod, successString)

	return nil
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

		return c.rotateDID(rw, &request)
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

	return c.rotateDID(rw, &request)
}

func (c *Command) rotateDID(rw io.Writer, request *RotateDIDRequest) command.Error {
	if request.ID == "" {
		logutil.LogDebug(logger, CommandName, RotateDIDCommandMethod, errEmptyConnID)

		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyConnID))
	}

	if request.KID == "" {
		logutil.LogDebug(logger, CommandName, RotateDIDCommandMethod, errEmptyKID)

		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyKID))
	}

	if request.NewDID == "" && !request.CreatePeerDID {
		logutil.LogDebug(logger, CommandName, RotateDIDCommandMethod, errEmptyNewDID)

		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyNewDID))
	}

	var opts []connection.RotateDIDOption

	if request.NewDID != "" {
		opts = append(opts, connection.WithNewDID(request.NewDID))
	}

	if request.CreatePeerDID {
		opts = append(opts, connection.ByCreatingPeerDID())
	}

	newDID, err := c.client.RotateDID(request.ID, request.KID, opts...)
	if err != nil {
		logutil.LogDebug(logger, CommandName, RotateDIDCommandMethod, err.Error())

		return command.NewExecuteError(RotateDIDErrorCode, err)
	}

	command.WriteNillableResponse(rw, &RotateDIDResponse{
		NewDID: newDID,
	}, logger)

	logutil.LogDebug(logger, CommandName, RotateDIDCommandMethod, successString,
		logutil.CreateKeyValueString(connectionIDString, request.ID),
		logutil.CreateKeyValueString(newDIDString, request.NewDID),
	)

	return nil
}
