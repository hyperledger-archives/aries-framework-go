/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package legacyconnection

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/client/legacyconnection"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/controller/webnotifier"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	protocol "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/legacyconnection"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

var logger = log.New("aries-framework/controller/legacy-connection")

// constants for endpoints of legacy-connection.
const (
	CommandName = "legacyconnection"

	// error messages.
	errEmptyInviterDID = "empty inviter DID"
	errEmptyConnID     = "empty connection ID"

	AcceptConnectionRequestCommandMethod  = "AcceptConnectionRequest"
	AcceptInvitationCommandMethod         = "AcceptInvitation"
	CreateImplicitInvitationCommandMethod = "CreateImplicitInvitation"
	CreateInvitationCommandMethod         = "CreateInvitation"
	QueryConnectionByIDCommandMethod      = "QueryConnectionByID"
	QueryConnectionsCommandMethod         = "QueryConnections"
	ReceiveInvitationCommandMethod        = "ReceiveInvitation"
	CreateConnectionCommandMethod         = "CreateConnection"
	RemoveConnectionCommandMethod         = "RemoveConnection"

	// log constants.
	connectionIDString = "connectionID"
	successString      = "success"
	invitationIDString = "invitationID"
)

const (
	// InvalidRequestErrorCode is typically a code for validation errors
	// for invalid legacy-connection controller requests.
	InvalidRequestErrorCode = command.Code(iota + command.LegacyConnection)

	// CreateInvitationErrorCode is for failures in create invitation command.
	CreateInvitationErrorCode

	// CreateImplicitInvitationErrorCode is for failures in create implicit invitation command.
	CreateImplicitInvitationErrorCode

	// ReceiveInvitationErrorCode is for failures in receive invitation command.
	ReceiveInvitationErrorCode

	// AcceptInvitationErrorCode is for failures in accept invitation command.
	AcceptInvitationErrorCode

	// AcceptConnectionRequestErrorCode is for failures in accept connection request command.
	AcceptConnectionRequestErrorCode

	// QueryConnectionsErrorCode is for failures in query connection command.
	QueryConnectionsErrorCode

	// RemoveConnectionErrorCode is for failures in remove connection command.
	RemoveConnectionErrorCode

	// CreateConnectionErrorCode is for failures in create connection command.
	CreateConnectionErrorCode

	_actions = "_actions"
	_states  = "_states"
)

// provider contains dependencies for the legacy-connection command and is typically created by using aries.Context().
type provider interface {
	Service(id string) (interface{}, error)
	KMS() kms.KeyManager
	ServiceEndpoint() string
	StorageProvider() storage.Provider
	ProtocolStateStorageProvider() storage.Provider
	KeyType() kms.KeyType
	KeyAgreementType() kms.KeyType
	MediaTypeProfiles() []string
}

// New returns new legacy-connection controller command instance.
func New(ctx provider, notifier command.Notifier, defaultLabel string, autoAccept bool) (*Command, error) {
	legacyConnection, err := legacyconnection.New(ctx)
	if err != nil {
		return nil, err
	}

	// creates action channel
	actions := make(chan service.DIDCommAction)
	// registers action channel to listen for events
	if err := legacyConnection.RegisterActionEvent(actions); err != nil {
		return nil, fmt.Errorf("register action event: %w", err)
	}

	// creates state channel
	states := make(chan service.StateMsg)
	// registers state channel to listen for events
	if err := legacyConnection.RegisterMsgEvent(states); err != nil {
		return nil, fmt.Errorf("register msg event: %w", err)
	}

	subscribers := []chan service.DIDCommAction{
		make(chan service.DIDCommAction),
	}

	if autoAccept {
		subscribers = append(subscribers, make(chan service.DIDCommAction))

		go service.AutoExecuteActionEvent(subscribers[1])
	}

	go func() {
		for action := range actions {
			for i := range subscribers {
				action.Message = action.Message.Clone()
				subscribers[i] <- action
			}
		}
	}()

	obs := webnotifier.NewObserver(notifier)
	obs.RegisterAction(protocol.LegacyConnection+_actions, subscribers[0])
	obs.RegisterStateMsg(protocol.LegacyConnection+_states, states)

	cmd := &Command{
		ctx:          ctx,
		client:       legacyConnection,
		msgCh:        make(chan service.StateMsg),
		defaultLabel: defaultLabel,
	}

	return cmd, nil
}

// Command is controller command for legacy-connection.
type Command struct {
	ctx          provider
	client       *legacyconnection.Client
	msgCh        chan service.StateMsg
	defaultLabel string
}

// GetHandlers returns list of all commands supported by this controller command.
func (c *Command) GetHandlers() []command.Handler {
	return []command.Handler{
		cmdutil.NewCommandHandler(CommandName, CreateInvitationCommandMethod, c.CreateInvitation),
		cmdutil.NewCommandHandler(CommandName, ReceiveInvitationCommandMethod, c.ReceiveInvitation),
		cmdutil.NewCommandHandler(CommandName, AcceptInvitationCommandMethod, c.AcceptInvitation),
		cmdutil.NewCommandHandler(CommandName, CreateConnectionCommandMethod, c.CreateConnection),
		cmdutil.NewCommandHandler(CommandName, RemoveConnectionCommandMethod, c.RemoveConnection),
		cmdutil.NewCommandHandler(CommandName, QueryConnectionByIDCommandMethod, c.QueryConnectionByID),
		cmdutil.NewCommandHandler(CommandName, QueryConnectionsCommandMethod, c.QueryConnections),
		cmdutil.NewCommandHandler(CommandName, AcceptConnectionRequestCommandMethod, c.AcceptConnectionRequest),
		cmdutil.NewCommandHandler(CommandName, CreateImplicitInvitationCommandMethod, c.CreateImplicitInvitation),
	}
}

// CreateInvitation Creates a new connection invitation.
func (c *Command) CreateInvitation(rw io.Writer, req io.Reader) command.Error {
	var request CreateInvitationArgs

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, CreateInvitationCommandMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	var invitation *legacyconnection.Invitation
	// call legacyconnection client
	if request.Public != "" {
		invitation, err = c.client.CreateInvitationWithDID(c.defaultLabel, request.Public)
	} else {
		invitation, err = c.client.CreateInvitation(c.defaultLabel,
			legacyconnection.WithRouterConnectionID(request.RouterConnectionID))
	}

	if err != nil {
		logutil.LogError(logger, CommandName, CreateInvitationCommandMethod, err.Error())

		return command.NewExecuteError(CreateInvitationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &CreateInvitationResponse{
		Invitation: invitation,
		Alias:      request.Alias,
	},
		logger)

	logutil.LogDebug(logger, CommandName, CreateInvitationCommandMethod, successString,
		logutil.CreateKeyValueString(invitationIDString, invitation.ID))

	return nil
}

// ReceiveInvitation receives a new connection invitation.
func (c *Command) ReceiveInvitation(rw io.Writer, req io.Reader) command.Error {
	var request legacyconnection.Invitation

	err := json.NewDecoder(req).Decode(&request.Invitation)
	if err != nil {
		logutil.LogInfo(logger, CommandName, ReceiveInvitationCommandMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	connectionID, err := c.client.HandleInvitation(&request)
	if err != nil {
		logutil.LogError(logger, CommandName, ReceiveInvitationCommandMethod, err.Error(),
			logutil.CreateKeyValueString(invitationIDString, request.ID),
			logutil.CreateKeyValueString("label", request.Label),
			logutil.CreateKeyValueString(connectionIDString, connectionID))

		return command.NewExecuteError(ReceiveInvitationErrorCode, err)
	}

	command.WriteNillableResponse(rw, ReceiveInvitationResponse{
		ConnectionID: connectionID,
	}, logger)

	logutil.LogDebug(logger, CommandName, ReceiveInvitationCommandMethod, successString,
		logutil.CreateKeyValueString(invitationIDString, request.ID),
		logutil.CreateKeyValueString("label", request.Label),
		logutil.CreateKeyValueString(connectionIDString, connectionID))

	return nil
}

// AcceptInvitation accepts a stored connection invitation.
func (c *Command) AcceptInvitation(rw io.Writer, req io.Reader) command.Error {
	var request AcceptInvitationArgs

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, AcceptInvitationCommandMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if request.ID == "" {
		logutil.LogDebug(logger, CommandName, AcceptInvitationCommandMethod, errEmptyConnID)

		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyConnID))
	}

	err = c.client.AcceptInvitation(request.ID, request.Public, c.defaultLabel,
		legacyconnection.WithRouterConnections(strings.Split(request.RouterConnections, ",")...))
	if err != nil {
		logutil.LogError(logger, CommandName, AcceptInvitationCommandMethod, err.Error(),
			logutil.CreateKeyValueString(connectionIDString, request.ID))

		return command.NewExecuteError(AcceptInvitationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &AcceptInvitationResponse{
		ConnectionID: request.ID,
	}, logger)

	logutil.LogDebug(logger, CommandName, AcceptInvitationCommandMethod, successString,
		logutil.CreateKeyValueString(connectionIDString, request.ID))

	return nil
}

// CreateImplicitInvitation creates implicit invitation using inviter DID.
func (c *Command) CreateImplicitInvitation(rw io.Writer, req io.Reader) command.Error {
	var request ImplicitInvitationArgs

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, CreateImplicitInvitationCommandMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if request.InviterDID == "" {
		logutil.LogDebug(logger, CommandName, CreateImplicitInvitationCommandMethod, errEmptyInviterDID)

		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyInviterDID))
	}

	logger.Debugf("create implicit invitation: inviterDID[%s], inviterLabel[%s], inviteeDID[%s], inviteeLabel[%s]",
		request.InviterDID, request.InviterLabel, request.InviteeDID, request.InviterLabel)

	inviter := &legacyconnection.DIDInfo{DID: request.InviterDID, Label: request.InviterLabel}

	var id string

	if request.InviteeDID != "" {
		invitee := &legacyconnection.DIDInfo{DID: request.InviteeDID, Label: request.InviteeLabel}
		id, err = c.client.CreateImplicitInvitationWithDID(inviter, invitee)
	} else {
		id, err = c.client.CreateImplicitInvitation(inviter.Label, inviter.DID,
			legacyconnection.WithRouterConnections(strings.Split(request.RouterConnections, ",")...))
	}

	if err != nil {
		logutil.LogError(logger, CommandName, CreateImplicitInvitationCommandMethod, err.Error())

		return command.NewExecuteError(CreateImplicitInvitationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &ImplicitInvitationResponse{
		ConnectionID: id,
	}, logger)

	logutil.LogDebug(logger, CommandName, CreateImplicitInvitationCommandMethod, successString)

	return nil
}

// AcceptConnectionRequest accepts a stored connection request.
func (c *Command) AcceptConnectionRequest(rw io.Writer, req io.Reader) command.Error {
	var request AcceptConnectionRequestArgs

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, AcceptConnectionRequestCommandMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if request.ID == "" {
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyConnID))
	}

	err = c.client.AcceptConnectionRequest(request.ID, request.Public,
		c.defaultLabel, legacyconnection.WithRouterConnections(strings.Split(request.RouterConnections, ",")...))
	if err != nil {
		logutil.LogError(logger, CommandName, AcceptConnectionRequestCommandMethod, err.Error(),
			logutil.CreateKeyValueString(connectionIDString, request.ID))

		return command.NewExecuteError(AcceptConnectionRequestErrorCode, err)
	}

	command.WriteNillableResponse(rw, &ConnectionResponse{
		ConnectionID: request.ID,
	}, logger)

	logutil.LogDebug(logger, CommandName, AcceptConnectionRequestCommandMethod, successString,
		logutil.CreateKeyValueString(connectionIDString, request.ID))

	return nil
}

// QueryConnections queries agent to agent connections.
func (c *Command) QueryConnections(rw io.Writer, req io.Reader) command.Error {
	var request QueryConnectionsArgs

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, QueryConnectionsCommandMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	results, err := c.client.QueryConnections(&request.QueryConnectionsParams)
	if err != nil {
		logutil.LogError(logger, CommandName, QueryConnectionsCommandMethod, err.Error())

		return command.NewExecuteError(QueryConnectionsErrorCode, err)
	}

	command.WriteNillableResponse(rw, &QueryConnectionsResponse{
		Results: results,
	}, logger)

	logutil.LogDebug(logger, CommandName, QueryConnectionsCommandMethod, successString)

	return nil
}

// QueryConnectionByID fetches a single connection record by connection ID.
func (c *Command) QueryConnectionByID(rw io.Writer, req io.Reader) command.Error {
	var request ConnectionIDArg

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, QueryConnectionByIDCommandMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if request.ID == "" {
		logutil.LogDebug(logger, CommandName, QueryConnectionByIDCommandMethod, errEmptyConnID)

		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyConnID))
	}

	result, err := c.client.GetConnection(request.ID)
	if err != nil {
		logutil.LogError(logger, CommandName, QueryConnectionByIDCommandMethod, err.Error(),
			logutil.CreateKeyValueString(connectionIDString, request.ID))

		return command.NewExecuteError(QueryConnectionsErrorCode, err)
	}

	command.WriteNillableResponse(rw, &QueryConnectionResponse{
		Result: result,
	}, logger)

	logutil.LogDebug(logger, CommandName, QueryConnectionByIDCommandMethod, successString,
		logutil.CreateKeyValueString(connectionIDString, request.ID))

	return nil
}

// CreateConnection creates a new connection record in completed state and returns the generated connectionID.
func (c *Command) CreateConnection(rw io.Writer, req io.Reader) command.Error {
	request := &CreateConnectionRequest{}

	err := json.NewDecoder(req).Decode(request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, CreateConnectionCommandMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	theirDID, err := did.ParseDocument(request.TheirDID.Contents)
	if err != nil {
		logutil.LogInfo(logger, CommandName, CreateConnectionCommandMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	id, err := c.client.CreateConnection(request.MyDID, theirDID,
		legacyconnection.WithImplicit(request.Implicit),
		legacyconnection.WithTheirLabel(request.TheirLabel),
		legacyconnection.WithInvitationDID(request.InvitationDID),
		legacyconnection.WithInvitationID(request.InvitationID),
		legacyconnection.WithParentThreadID(request.ParentThreadID),
		legacyconnection.WithThreadID(request.ThreadID))
	if err != nil {
		logutil.LogError(logger, CommandName, CreateConnectionCommandMethod, err.Error())

		return command.NewExecuteError(CreateConnectionErrorCode, err)
	}

	command.WriteNillableResponse(rw, &ConnectionIDArg{
		ID: id,
	}, logger)

	logutil.LogDebug(logger, CommandName, CreateConnectionCommandMethod, successString,
		logutil.CreateKeyValueString(connectionIDString, id))

	return nil
}

// RemoveConnection removes given connection record.
func (c *Command) RemoveConnection(_ io.Writer, req io.Reader) command.Error {
	var request ConnectionIDArg

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, RemoveConnectionCommandMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if request.ID == "" {
		logutil.LogDebug(logger, CommandName, RemoveConnectionCommandMethod, errEmptyConnID)

		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyConnID))
	}

	logger.Debugf("Removing connection record for id [%s]", request.ID)

	err = c.client.RemoveConnection(request.ID)
	if err != nil {
		logutil.LogError(logger, CommandName, RemoveConnectionCommandMethod, err.Error(),
			logutil.CreateKeyValueString(connectionIDString, request.ID))

		return command.NewExecuteError(RemoveConnectionErrorCode, err)
	}

	logutil.LogDebug(logger, CommandName, RemoveConnectionCommandMethod, successString,
		logutil.CreateKeyValueString(connectionIDString, request.ID))

	return nil
}
