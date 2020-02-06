/*
 *
 * Copyright SecureKey Technologies Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 *
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
	"github.com/hyperledger/aries-framework-go/pkg/controller/webhook"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

var logger = log.New("aries-framework/controller/did-exchange")

const (
	// webhook notifier topic
	connectionsWebhookTopic = "connections"

	// error messages
	errEmptyInviterDID = "empty inviter DID"
	errEmptyConnID     = "empty connection ID"
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
func New(ctx provider, notifier webhook.Notifier, defaultLabel string, autoAccept bool) (*Command, error) {
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

	svc := &Command{
		ctx:          ctx,
		client:       didExchange,
		msgCh:        make(chan service.StateMsg),
		notifier:     notifier,
		defaultLabel: defaultLabel,
	}

	err = svc.startClientEventListener()
	if err != nil {
		return nil, fmt.Errorf("event listener startup failed: %w", err)
	}

	return svc, nil
}

// Command is controller command for DID Exchange
type Command struct {
	ctx          provider
	client       *didexchange.Client
	msgCh        chan service.StateMsg
	notifier     webhook.Notifier
	defaultLabel string
}

// CreateInvitation Creates a new connection invitation.
func (c *Command) CreateInvitation(rw io.Writer, req io.Reader) command.Error {
	logger.Debugf("Creating connection invitation ")

	var request CreateInvitationArgs

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
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
		return command.NewExecuteError(CreateInvitationErrorCode, err)
	}

	c.writeResponse(rw, &CreateInvitationResponse{
		Invitation: invitation,
		Alias:      request.Alias})

	return nil
}

// ReceiveInvitation receives a new connection invitation.
func (c *Command) ReceiveInvitation(rw io.Writer, req io.Reader) command.Error {
	logger.Debugf("Receiving connection invitation ")

	var request didexchange.Invitation

	err := json.NewDecoder(req).Decode(&request.Invitation)
	if err != nil {
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	connectionID, err := c.client.HandleInvitation(&request)
	if err != nil {
		return command.NewExecuteError(ReceiveInvitationErrorCode, err)
	}

	c.writeResponse(rw, ReceiveInvitationResponse{
		ConnectionID: connectionID,
	})

	return nil
}

// AcceptInvitation accepts a stored connection invitation.
func (c *Command) AcceptInvitation(rw io.Writer, req io.Reader) command.Error {
	var request AcceptInvitationArgs

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if request.ID == "" {
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyConnID))
	}

	logger.Debugf("Accepting connection invitation for id[%s], label[%s], publicDID[%s]",
		request.ID, c.defaultLabel, request.Public)

	err = c.client.AcceptInvitation(request.ID, request.Public, c.defaultLabel)
	if err != nil {
		logger.Errorf("accept invitation api failed for id %s with error %s", request.ID, err)

		return command.NewExecuteError(AcceptInvitationErrorCode, err)
	}

	c.writeResponse(rw, &AcceptInvitationResponse{
		ConnectionID: request.ID,
	})

	return nil
}

// CreateImplicitInvitation creates implicit invitation using inviter DID.
func (c *Command) CreateImplicitInvitation(rw io.Writer, req io.Reader) command.Error {
	var request ImplicitInvitationArgs

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if request.InviterDID == "" {
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
		logger.Errorf("create implicit invitation api failed for id %s with error %s", id, err)
		return command.NewExecuteError(CreateImplicitInvitationErrorCode, err)
	}

	c.writeResponse(rw, &ImplicitInvitationResponse{
		ConnectionID: id,
	})

	return nil
}

// AcceptExchangeRequest accepts a stored connection request.
func (c *Command) AcceptExchangeRequest(rw io.Writer, req io.Reader) command.Error {
	var request AcceptInvitationArgs

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if request.ID == "" {
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyConnID))
	}

	logger.Debugf("Accepting connection request for id [%s]", request.ID)

	err = c.client.AcceptExchangeRequest(request.ID, request.Public, c.defaultLabel)
	if err != nil {
		logger.Errorf("accepting connection request failed for id %s with error %s", request.ID, err)
		return command.NewExecuteError(AcceptExchangeRequestErrorCode, err)
	}

	c.writeResponse(rw, &ExchangeResponse{
		ConnectionID: request.ID,
	})

	return nil
}

// QueryConnections queries agent to agent connections.
func (c *Command) QueryConnections(rw io.Writer, req io.Reader) command.Error {
	logger.Debugf("Querying connection invitations ")

	var request QueryConnectionsArgs

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	results, err := c.client.QueryConnections(&request.QueryConnectionsParams)
	if err != nil {
		return command.NewExecuteError(QueryConnectionsErrorCode, err)
	}

	c.writeResponse(rw, &QueryConnectionsResponse{
		Results: results,
	})

	return nil
}

// QueryConnectionByID fetches a single connection record by connection ID.
func (c *Command) QueryConnectionByID(rw io.Writer, req io.Reader) command.Error {
	var request QueryConnectionByIDArgs

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if request.ID == "" {
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyConnID))
	}

	logger.Debugf("Querying connection invitation for id [%s]", request.ID)

	result, err := c.client.GetConnection(request.ID)
	if err != nil {
		return command.NewExecuteError(QueryConnectionsErrorCode, err)
	}

	c.writeResponse(rw, &QueryConnectionResponse{
		Result: result,
	})

	return nil
}

// RemoveConnection removes given connection record.
func (c *Command) RemoveConnection(rw io.Writer, req io.Reader) command.Error {
	var request QueryConnectionByIDArgs

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if request.ID == "" {
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyConnID))
	}

	logger.Debugf("Removing connection record for id [%s]", request.ID)

	err = c.client.RemoveConnection(request.ID)
	if err != nil {
		return command.NewExecuteError(RemoveConnectionErrorCode, err)
	}

	return nil
}

// writeResponse writes interface value to response
func (c *Command) writeResponse(rw io.Writer, v interface{}) {
	err := json.NewEncoder(rw).Encode(v)
	// as of now, just log errors for writing response
	if err != nil {
		logger.Errorf("Unable to send error response, %s", err)
	}
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
		logger.Errorf("Send notification failed, topic[%s], connectionID[%s]", connectionsWebhookTopic, connectionID)
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
		return fmt.Errorf("connection notification json marshal : %w", err)
	}

	logger.Debugf("Sending notification on topic '%s', message body : %s", connectionsWebhookTopic, jsonMessage)

	err = c.notifier.Notify(connectionsWebhookTopic, jsonMessage)
	if err != nil {
		return fmt.Errorf("connection notification webhook : %w", err)
	}

	return nil
}
