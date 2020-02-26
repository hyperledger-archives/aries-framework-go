/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

var logger = log.New("aries-framework/controller/did-exchange")

const (
	// command name
	commandName = "didexchange"

	// webhook notifier topic
	connectionsWebhookTopic = "connections"

	// error messages
	errEmptyInviterDID = "empty inviter DID"
	errEmptyConnID     = "empty connection ID"

	// command methods
	acceptExchangeRequestCommandMethod    = "AcceptExchangeRequest"
	acceptInvitationCommandMethod         = "AcceptInvitation"
	createImplicitInvitationCommandMethod = "CreateImplicitInvitation"
	createInvitationCommandMethod         = "CreateInvitation"
	queryConnectionByIDCommandMethod      = "QueryConnectionByID"
	queryConnectionsCommandMethod         = "QueryConnections"
	receiveInvitationCommandMethod        = "ReceiveInvitation"
	removeConnectionCommandMethod         = "RemoveConnection"

	// log constants
	connectionIDString         = "connectionID"
	stateIDString              = "stateID"
	successString              = "success"
	invitationIDString         = "invitationID"
	sendConnectionNotification = "sendConnectionNotification"
)

const (
	// InvalidRequestErrorCode is typically a code for validation errors
	// for invalid didexchange controller requests
	InvalidRequestErrorCode = command.Code(iota + command.DIDExchange)

	// CreateInvitationErrorCode is for failures in create invitation command
	CreateInvitationErrorCode

	// CreateImplicitInvitationErrorCode is for failures in create implicit invitation command
	CreateImplicitInvitationErrorCode

	// ReceiveInvitationErrorCode is for failures in receive invitation command
	ReceiveInvitationErrorCode

	// AcceptInvitationErrorCode is for failures in accept invitation command
	AcceptInvitationErrorCode

	// AcceptExchangeRequestErrorCode is for failures in accept exchange request command
	AcceptExchangeRequestErrorCode

	// QueryConnectionsErrorCode is for failures in query connection command
	QueryConnectionsErrorCode

	// RemoveConnectionErrorCode is for failures in remove connection command
	RemoveConnectionErrorCode
)

// provider contains dependencies for the DID Exchange command and is typically created by using aries.Context()
type provider interface {
	Service(id string) (interface{}, error)
	LegacyKMS() legacykms.KeyManager
	ServiceEndpoint() string
	StorageProvider() storage.Provider
	TransientStorageProvider() storage.Provider
}

// New returns new DID Exchange controller command instance
func New(ctx provider, notifier command.Notifier, defaultLabel string, autoAccept bool) (*Command, error) {
	didExchange, err := didexchange.New(ctx)
	if err != nil {
		return nil, err
	}

	if autoAccept {
		actionCh := make(chan service.DIDCommAction)

		err = didExchange.RegisterActionEvent(actionCh)
		if err != nil {
			return nil, fmt.Errorf("register action event failed: %w", err)
		}

		go service.AutoExecuteActionEvent(actionCh)
	}

	cmd := &Command{
		ctx:          ctx,
		client:       didExchange,
		msgCh:        make(chan service.StateMsg),
		notifier:     notifier,
		defaultLabel: defaultLabel,
	}

	err = cmd.startClientEventListener()
	if err != nil {
		return nil, fmt.Errorf("event listener startup failed: %w", err)
	}

	return cmd, nil
}

// Command is controller command for DID Exchange
type Command struct {
	ctx          provider
	client       *didexchange.Client
	msgCh        chan service.StateMsg
	notifier     command.Notifier
	defaultLabel string
}

// GetHandlers returns list of all commands supported by this controller command
func (c *Command) GetHandlers() []command.Handler {
	return []command.Handler{
		cmdutil.NewCommandHandler(commandName, createInvitationCommandMethod, c.CreateInvitation),
		cmdutil.NewCommandHandler(commandName, receiveInvitationCommandMethod, c.ReceiveInvitation),
		cmdutil.NewCommandHandler(commandName, acceptInvitationCommandMethod, c.AcceptInvitation),
		cmdutil.NewCommandHandler(commandName, removeConnectionCommandMethod, c.RemoveConnection),
		cmdutil.NewCommandHandler(commandName, queryConnectionByIDCommandMethod, c.QueryConnectionByID),
		cmdutil.NewCommandHandler(commandName, queryConnectionsCommandMethod, c.QueryConnections),
		cmdutil.NewCommandHandler(commandName, acceptExchangeRequestCommandMethod, c.AcceptExchangeRequest),
		cmdutil.NewCommandHandler(commandName, createImplicitInvitationCommandMethod, c.CreateImplicitInvitation),
	}
}

// CreateInvitation Creates a new connection invitation.
func (c *Command) CreateInvitation(rw io.Writer, req io.Reader) command.Error {
	var request CreateInvitationArgs

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, commandName, createInvitationCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	var invitation *didexchange.Invitation
	// call didexchange client
	if request.Public != "" {
		invitation, err = c.client.CreateInvitationWithDID(c.defaultLabel, request.Public)
	} else {
		invitation, err = c.client.CreateInvitation(c.defaultLabel)
	}

	if err != nil {
		logutil.LogError(logger, commandName, createInvitationCommandMethod, err.Error())
		return command.NewExecuteError(CreateInvitationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &CreateInvitationResponse{
		Invitation: invitation,
		Alias:      request.Alias},
		logger)

	logutil.LogDebug(logger, commandName, createInvitationCommandMethod, successString,
		logutil.CreateKeyValueString(invitationIDString, invitation.ID))

	return nil
}

// ReceiveInvitation receives a new connection invitation.
func (c *Command) ReceiveInvitation(rw io.Writer, req io.Reader) command.Error {
	var request didexchange.Invitation

	err := json.NewDecoder(req).Decode(&request.Invitation)
	if err != nil {
		logutil.LogInfo(logger, commandName, receiveInvitationCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	connectionID, err := c.client.HandleInvitation(&request)
	if err != nil {
		logutil.LogError(logger, commandName, receiveInvitationCommandMethod, err.Error(),
			logutil.CreateKeyValueString(invitationIDString, request.ID),
			logutil.CreateKeyValueString("label", request.Label),
			logutil.CreateKeyValueString(connectionIDString, connectionID))

		return command.NewExecuteError(ReceiveInvitationErrorCode, err)
	}

	command.WriteNillableResponse(rw, ReceiveInvitationResponse{
		ConnectionID: connectionID,
	}, logger)

	logutil.LogDebug(logger, commandName, receiveInvitationCommandMethod, successString,
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
		logutil.LogInfo(logger, commandName, acceptInvitationCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if request.ID == "" {
		logutil.LogDebug(logger, commandName, acceptInvitationCommandMethod, errEmptyConnID)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyConnID))
	}

	err = c.client.AcceptInvitation(request.ID, request.Public, c.defaultLabel)
	if err != nil {
		logutil.LogError(logger, commandName, acceptInvitationCommandMethod, err.Error(),
			logutil.CreateKeyValueString(connectionIDString, request.ID))
		return command.NewExecuteError(AcceptInvitationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &AcceptInvitationResponse{
		ConnectionID: request.ID,
	}, logger)

	logutil.LogDebug(logger, commandName, acceptInvitationCommandMethod, successString,
		logutil.CreateKeyValueString(connectionIDString, request.ID))

	return nil
}

// CreateImplicitInvitation creates implicit invitation using inviter DID.
func (c *Command) CreateImplicitInvitation(rw io.Writer, req io.Reader) command.Error {
	var request ImplicitInvitationArgs

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, commandName, createImplicitInvitationCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if request.InviterDID == "" {
		logutil.LogDebug(logger, commandName, createImplicitInvitationCommandMethod, errEmptyInviterDID)
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
		id, err = c.client.CreateImplicitInvitation(inviter.Label, inviter.DID)
	}

	if err != nil {
		logutil.LogError(logger, commandName, createImplicitInvitationCommandMethod, err.Error())
		return command.NewExecuteError(CreateImplicitInvitationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &ImplicitInvitationResponse{
		ConnectionID: id,
	}, logger)

	logutil.LogDebug(logger, commandName, createImplicitInvitationCommandMethod, successString)

	return nil
}

// AcceptExchangeRequest accepts a stored connection request.
func (c *Command) AcceptExchangeRequest(rw io.Writer, req io.Reader) command.Error {
	var request AcceptExchangeRequestArgs

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, commandName, acceptExchangeRequestCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if request.ID == "" {
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyConnID))
	}

	err = c.client.AcceptExchangeRequest(request.ID, request.Public, c.defaultLabel)
	if err != nil {
		logutil.LogError(logger, commandName, acceptExchangeRequestCommandMethod, err.Error(),
			logutil.CreateKeyValueString(connectionIDString, request.ID))
		return command.NewExecuteError(AcceptExchangeRequestErrorCode, err)
	}

	command.WriteNillableResponse(rw, &ExchangeResponse{
		ConnectionID: request.ID,
	}, logger)

	logutil.LogDebug(logger, commandName, acceptExchangeRequestCommandMethod, successString,
		logutil.CreateKeyValueString(connectionIDString, request.ID))

	return nil
}

// QueryConnections queries agent to agent connections.
func (c *Command) QueryConnections(rw io.Writer, req io.Reader) command.Error {
	var request QueryConnectionsArgs

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, commandName, queryConnectionsCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	results, err := c.client.QueryConnections(&request.QueryConnectionsParams)
	if err != nil {
		logutil.LogError(logger, commandName, queryConnectionsCommandMethod, err.Error())
		return command.NewExecuteError(QueryConnectionsErrorCode, err)
	}

	command.WriteNillableResponse(rw, &QueryConnectionsResponse{
		Results: results,
	}, logger)

	logutil.LogDebug(logger, commandName, queryConnectionsCommandMethod, successString)

	return nil
}

// QueryConnectionByID fetches a single connection record by connection ID.
func (c *Command) QueryConnectionByID(rw io.Writer, req io.Reader) command.Error {
	var request ConnectionIDArg

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, commandName, queryConnectionByIDCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if request.ID == "" {
		logutil.LogDebug(logger, commandName, queryConnectionByIDCommandMethod, errEmptyConnID)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyConnID))
	}

	result, err := c.client.GetConnection(request.ID)
	if err != nil {
		logutil.LogError(logger, commandName, queryConnectionByIDCommandMethod, err.Error(),
			logutil.CreateKeyValueString(connectionIDString, request.ID))
		return command.NewExecuteError(QueryConnectionsErrorCode, err)
	}

	command.WriteNillableResponse(rw, &QueryConnectionResponse{
		Result: result,
	}, logger)

	logutil.LogDebug(logger, commandName, queryConnectionByIDCommandMethod, successString,
		logutil.CreateKeyValueString(connectionIDString, request.ID))

	return nil
}

// RemoveConnection removes given connection record.
func (c *Command) RemoveConnection(rw io.Writer, req io.Reader) command.Error {
	var request ConnectionIDArg

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, commandName, removeConnectionCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if request.ID == "" {
		logutil.LogDebug(logger, commandName, removeConnectionCommandMethod, errEmptyConnID)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyConnID))
	}

	logger.Debugf("Removing connection record for id [%s]", request.ID)

	err = c.client.RemoveConnection(request.ID)
	if err != nil {
		logutil.LogError(logger, commandName, removeConnectionCommandMethod, err.Error(),
			logutil.CreateKeyValueString(connectionIDString, request.ID))
		return command.NewExecuteError(RemoveConnectionErrorCode, err)
	}

	logutil.LogDebug(logger, commandName, removeConnectionCommandMethod, successString,
		logutil.CreateKeyValueString(connectionIDString, request.ID))

	return nil
}

// startClientEventListener listens to action and message events from DID Exchange service.
func (c *Command) startClientEventListener() error {
	// register the message event channel
	err := c.client.RegisterMsgEvent(c.msgCh)
	if err != nil {
		return fmt.Errorf("didexchange message event registration failed: %w", err)
	}

	// event listeners
	go func() {
		for e := range c.msgCh {
			err := c.handleMessageEvents(e)
			if err != nil {
				logger.Errorf("handle message events failed : %s", err)
			}
		}
	}()

	return nil
}

func (c *Command) handleMessageEvents(e service.StateMsg) error {
	if e.Type == service.PostState {
		switch v := e.Properties.(type) {
		case didexchange.Event:
			props := v

			err := c.sendConnectionNotification(props.ConnectionID(), e.StateID)
			if err != nil {
				return fmt.Errorf("send connection notification failed : %w", err)
			}
		case error:
			return fmt.Errorf("service processing failed : %w", v)
		default:
			return errors.New("event is not of DIDExchange event type")
		}
	}

	return nil
}

func (c *Command) sendConnectionNotification(connectionID, stateID string) error {
	conn, err := c.client.GetConnectionAtState(connectionID, stateID)
	if err != nil {
		logutil.LogError(logger, commandName, sendConnectionNotification, err.Error(),
			logutil.CreateKeyValueString(connectionIDString, connectionID),
			logutil.CreateKeyValueString(stateIDString, stateID))

		return fmt.Errorf("connection notification webhook : %w", err)
	}

	connMsg := &ConnectionMsg{
		ConnectionID: conn.ConnectionID,
		State:        conn.State,
		MyDid:        conn.MyDID,
		TheirDid:     conn.TheirDID,
		TheirLabel:   conn.TheirLabel,
		TheirRole:    conn.TheirLabel,
	}

	jsonMessage, err := json.Marshal(connMsg)
	if err != nil {
		logutil.LogError(logger, commandName, sendConnectionNotification, err.Error(),
			logutil.CreateKeyValueString(connectionIDString, connectionID),
			logutil.CreateKeyValueString(stateIDString, stateID))

		return fmt.Errorf("connection notification json marshal : %w", err)
	}

	logger.Debugf("Sending notification on topic '%s', message body : %s", connectionsWebhookTopic, jsonMessage)

	err = c.notifier.Notify(connectionsWebhookTopic, jsonMessage)
	if err != nil {
		logutil.LogError(logger, commandName, "sendConnectionNotification", err.Error(),
			logutil.CreateKeyValueString(connectionIDString, connectionID),
			logutil.CreateKeyValueString(stateIDString, stateID))

		return fmt.Errorf("connection notification webhook : %w", err)
	}

	logutil.LogDebug(logger, commandName, sendConnectionNotification, successString,
		logutil.CreateKeyValueString(connectionIDString, connectionID),
		logutil.CreateKeyValueString(stateIDString, stateID))

	return nil
}
