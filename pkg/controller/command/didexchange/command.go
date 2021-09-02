/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/controller/webnotifier"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	protocol "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

var logger = log.New("aries-framework/controller/did-exchange")

// constants for endpoints of DIDExchange.
const (
	CommandName = "didexchange"

	// error messages.
	errEmptyInviterDID = "empty inviter DID"
	errEmptyConnID     = "empty connection ID"

	AcceptExchangeRequestCommandMethod    = "AcceptExchangeRequest"
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
	// for invalid didexchange controller requests.
	InvalidRequestErrorCode = command.Code(iota + command.DIDExchange)

	// CreateInvitationErrorCode is for failures in create invitation command.
	CreateInvitationErrorCode

	// CreateImplicitInvitationErrorCode is for failures in create implicit invitation command.
	CreateImplicitInvitationErrorCode

	// ReceiveInvitationErrorCode is for failures in receive invitation command.
	ReceiveInvitationErrorCode

	// AcceptInvitationErrorCode is for failures in accept invitation command.
	AcceptInvitationErrorCode

	// AcceptExchangeRequestErrorCode is for failures in accept exchange request command.
	AcceptExchangeRequestErrorCode

	// QueryConnectionsErrorCode is for failures in query connection command.
	QueryConnectionsErrorCode

	// RemoveConnectionErrorCode is for failures in remove connection command.
	RemoveConnectionErrorCode

	// CreateConnectionErrorCode is for failures in create connection command.
	CreateConnectionErrorCode

	_actions = "_actions"
	_states  = "_states"
)

// provider contains dependencies for the DID Exchange command and is typically created by using aries.Context().
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

// New returns new DID Exchange controller command instance.
func New(ctx provider, notifier command.Notifier, defaultLabel string, autoAccept bool) (*Command, error) {
	didExchange, err := didexchange.New(ctx)
	if err != nil {
		return nil, err
	}

	// creates action channel
	actions := make(chan service.DIDCommAction)
	// registers action channel to listen for events
	if err := didExchange.RegisterActionEvent(actions); err != nil {
		return nil, fmt.Errorf("register action event: %w", err)
	}

	// creates state channel
	states := make(chan service.StateMsg)
	// registers state channel to listen for events
	if err := didExchange.RegisterMsgEvent(states); err != nil {
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
	obs.RegisterAction(protocol.DIDExchange+_actions, subscribers[0])
	obs.RegisterStateMsg(protocol.DIDExchange+_states, states)

	cmd := &Command{
		ctx:          ctx,
		client:       didExchange,
		msgCh:        make(chan service.StateMsg),
		defaultLabel: defaultLabel,
	}

	return cmd, nil
}

// Command is controller command for DID Exchange.
type Command struct {
	ctx          provider
	client       *didexchange.Client
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
		cmdutil.NewCommandHandler(CommandName, AcceptExchangeRequestCommandMethod, c.AcceptExchangeRequest),
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

	var invitation *didexchange.Invitation
	// call didexchange client
	if request.Public != "" {
		invitation, err = c.client.CreateInvitationWithDID(c.defaultLabel, request.Public)
	} else {
		invitation, err = c.client.CreateInvitation(c.defaultLabel,
			didexchange.WithRouterConnectionID(request.RouterConnectionID))
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
	var request didexchange.Invitation

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
		didexchange.WithRouterConnections(strings.Split(request.RouterConnections, ",")...))
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

	inviter := &didexchange.DIDInfo{DID: request.InviterDID, Label: request.InviterLabel}

	var id string

	if request.InviteeDID != "" {
		invitee := &didexchange.DIDInfo{DID: request.InviteeDID, Label: request.InviteeLabel}
		id, err = c.client.CreateImplicitInvitationWithDID(inviter, invitee)
	} else {
		id, err = c.client.CreateImplicitInvitation(inviter.Label, inviter.DID,
			didexchange.WithRouterConnections(strings.Split(request.RouterConnections, ",")...))
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

// AcceptExchangeRequest accepts a stored connection request.
func (c *Command) AcceptExchangeRequest(rw io.Writer, req io.Reader) command.Error {
	var request AcceptExchangeRequestArgs

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, AcceptExchangeRequestCommandMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if request.ID == "" {
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyConnID))
	}

	err = c.client.AcceptExchangeRequest(request.ID, request.Public,
		c.defaultLabel, didexchange.WithRouterConnections(strings.Split(request.RouterConnections, ",")...))
	if err != nil {
		logutil.LogError(logger, CommandName, AcceptExchangeRequestCommandMethod, err.Error(),
			logutil.CreateKeyValueString(connectionIDString, request.ID))

		return command.NewExecuteError(AcceptExchangeRequestErrorCode, err)
	}

	command.WriteNillableResponse(rw, &ExchangeResponse{
		ConnectionID: request.ID,
	}, logger)

	logutil.LogDebug(logger, CommandName, AcceptExchangeRequestCommandMethod, successString,
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
		didexchange.WithImplicit(request.Implicit),
		didexchange.WithTheirLabel(request.TheirLabel),
		didexchange.WithInvitationDID(request.InvitationDID),
		didexchange.WithInvitationID(request.InvitationID),
		didexchange.WithParentThreadID(request.ParentThreadID),
		didexchange.WithThreadID(request.ThreadID))
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
func (c *Command) RemoveConnection(rw io.Writer, req io.Reader) command.Error {
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
