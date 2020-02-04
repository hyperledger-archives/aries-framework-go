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
	"net/http"
	"net/url"

	"github.com/gorilla/mux"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/internal/common/support"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
	resterrors "github.com/hyperledger/aries-framework-go/pkg/restapi/errors"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/operation"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/operation/didexchange/models"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/webhook"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

var logger = log.New("aries-framework/controller/did-exchange")

const (
	operationID                  = "/connections"
	createInvitationPath         = operationID + "/create-invitation"
	createImplicitInvitationPath = operationID + "/create-implicit-invitation"
	receiveInvitationPath        = operationID + "/receive-invitation"
	acceptInvitationPath         = operationID + "/{id}/accept-invitation"
	connections                  = operationID
	connectionsByID              = operationID + "/{id}"
	acceptExchangeRequest        = operationID + "/{id}/accept-request"
	removeConnection             = operationID + "/{id}/remove"
	connectionsWebhookTopic      = "connections"
)

const (
	// InvalidRequestErrorCode is typically a code for validation errors
	// for invalid didexchange controller requests
	InvalidRequestErrorCode = resterrors.Code(iota + resterrors.DIDExchange)

	// CreateInvitationErrorCode is for failures in create invitation endpoint
	CreateInvitationErrorCode

	// CreateImplicitInvitationErrorCode is for failures in create implicit invitation endpoint
	CreateImplicitInvitationErrorCode

	// ReceiveInvitationErrorCode is for failures in receive invitation endpoint
	ReceiveInvitationErrorCode

	// AcceptInvitationErrorCode is for failures in accept invitation endpoint
	AcceptInvitationErrorCode

	// AcceptExchangeRequestErrorCode is for failures in accept exchange request endpoint
	AcceptExchangeRequestErrorCode

	// QueryConnectionsErrorCode is for failures in query connection endpoints
	QueryConnectionsErrorCode

	// RemoveConnectionErrorCode is for failures in remove connection endpoint
	RemoveConnectionErrorCode
)

// provider contains dependencies for the Exchange protocol and is typically created by using aries.Context()
type provider interface {
	Service(id string) (interface{}, error)
	LegacyKMS() legacykms.KeyManager
	ServiceEndpoint() string
	StorageProvider() storage.Provider
	TransientStorageProvider() storage.Provider
}

// New returns new DID Exchange rest client protocol instance
func New(ctx provider, notifier webhook.Notifier, defaultLabel string, autoAccept bool) (*Operation, error) {
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

	svc := &Operation{
		ctx:          ctx,
		client:       didExchange,
		msgCh:        make(chan service.StateMsg),
		notifier:     notifier,
		defaultLabel: defaultLabel,
	}
	svc.registerHandler()

	err = svc.startClientEventListener()
	if err != nil {
		return nil, fmt.Errorf("event listener startup failed: %w", err)
	}

	return svc, nil
}

// Operation is controller REST service controller for DID Exchange
type Operation struct {
	ctx          provider
	client       *didexchange.Client
	handlers     []operation.Handler
	msgCh        chan service.StateMsg
	notifier     webhook.Notifier
	defaultLabel string
}

// CreateInvitation swagger:route POST /connections/create-invitation did-exchange createInvitation
//
// Creates a new connection invitation....
//
// Responses:
//    default: genericError
//        200: createInvitationResponse
func (c *Operation) CreateInvitation(rw http.ResponseWriter, req *http.Request) {
	logger.Debugf("Creating connection invitation ")

	var request models.CreateInvitationRequest

	err := getQueryParams(&request, req.URL.Query())
	if err != nil {
		resterrors.SendHTTPBadRequest(rw, InvalidRequestErrorCode, err)
		return
	}

	var alias, did string
	if request.CreateInvitationParams != nil {
		alias = request.CreateInvitationParams.Alias
		did = request.CreateInvitationParams.Public
	}

	var invitation *didexchange.Invitation
	// call didexchange client
	if did != "" {
		invitation, err = c.client.CreateInvitationWithDID(c.defaultLabel, did)
	} else {
		invitation, err = c.client.CreateInvitation(c.defaultLabel)
	}

	if err != nil {
		resterrors.SendHTTPInternalServerError(rw, CreateInvitationErrorCode, err)
		return
	}

	c.writeResponse(rw, &models.CreateInvitationResponse{
		Invitation: invitation,
		Alias:      alias})
}

// ReceiveInvitation swagger:route POST /connections/receive-invitation did-exchange receiveInvitation
//
// Receive a new connection invitation....
//
// Responses:
//    default: genericError
//        200: receiveInvitationResponse
func (c *Operation) ReceiveInvitation(rw http.ResponseWriter, req *http.Request) {
	logger.Debugf("Receiving connection invitation ")

	var request models.ReceiveInvitationRequest

	err := json.NewDecoder(req.Body).Decode(&request.Invitation)
	if err != nil {
		resterrors.SendHTTPBadRequest(rw, InvalidRequestErrorCode, err)
		return
	}

	connectionID, err := c.client.HandleInvitation(request.Invitation)
	if err != nil {
		resterrors.SendHTTPInternalServerError(rw, ReceiveInvitationErrorCode, err)
		return
	}

	resp := models.ReceiveInvitationResponse{
		ConnectionID: connectionID,
	}

	c.writeResponse(rw, resp)
}

// AcceptInvitation swagger:route POST /connections/{id}/accept-invitation did-exchange acceptInvitation
//
// Accept a stored connection invitation....
//
// Responses:
//    default: genericError
//        200: acceptInvitationResponse
func (c *Operation) AcceptInvitation(rw http.ResponseWriter, req *http.Request) {
	id := mux.Vars(req)["id"]
	if id == "" {
		resterrors.SendHTTPBadRequest(rw, InvalidRequestErrorCode, fmt.Errorf("empty connection ID"))
	}

	var request models.AcceptInvitationRequest

	err := getQueryParams(&request, req.URL.Query())
	if err != nil {
		resterrors.SendHTTPBadRequest(rw, InvalidRequestErrorCode, err)
		return
	}

	logger.Debugf("Accepting connection invitation for id[%s], label[%s], publicDID[%s]",
		id, c.defaultLabel, request.Public)

	err = c.client.AcceptInvitation(id, request.Public, c.defaultLabel)
	if err != nil {
		logger.Errorf("accept invitation api failed for id %s with error %s", id, err)
		resterrors.SendHTTPInternalServerError(rw, AcceptInvitationErrorCode, err)

		return
	}

	response := &models.AcceptInvitationResponse{
		ConnectionID: id,
	}

	c.writeResponse(rw, response)
}

// CreateImplicitInvitation swagger:route POST /connections/create-implicit-invitation did-exchange implicitInvitation
//
//  Create implicit invitation using inviter DID.
//
// Responses:
//    default: genericError
//        200: implicitInvitationResponse
func (c *Operation) CreateImplicitInvitation(rw http.ResponseWriter, req *http.Request) {
	var err error

	var request models.ImplicitInvitationRequest

	err = getQueryParams(&request, req.URL.Query())
	if err != nil {
		resterrors.SendHTTPBadRequest(rw, InvalidRequestErrorCode, err)
		return
	}

	if request.InviterDID == "" {
		resterrors.SendHTTPBadRequest(rw, InvalidRequestErrorCode, fmt.Errorf("empty inviter DID"))
		return
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
		resterrors.SendHTTPInternalServerError(rw, CreateImplicitInvitationErrorCode, err)

		return
	}

	response := &models.ImplicitInvitationResponse{
		ConnectionID: id,
	}

	c.writeResponse(rw, response)
}

// AcceptExchangeRequest swagger:route POST /connections/{id}/accept-request did-exchange acceptRequest
//
// Accepts a stored connection request.
//
// Responses:
//    default: genericError
//        200: acceptExchangeResponse
func (c *Operation) AcceptExchangeRequest(rw http.ResponseWriter, req *http.Request) {
	id := mux.Vars(req)["id"]
	if id == "" {
		resterrors.SendHTTPBadRequest(rw, InvalidRequestErrorCode, fmt.Errorf("empty connection ID"))
	}

	logger.Infof("Accepting connection request for id [%s]", id)

	var request models.AcceptInvitationRequest

	err := getQueryParams(&request, req.URL.Query())
	if err != nil {
		resterrors.SendHTTPBadRequest(rw, InvalidRequestErrorCode, err)
		return
	}

	err = c.client.AcceptExchangeRequest(id, request.Public, c.defaultLabel)
	if err != nil {
		logger.Errorf("accepting connection request failed for id %s with error %s", id, err)
		resterrors.SendHTTPInternalServerError(rw, AcceptExchangeRequestErrorCode, err)

		return
	}

	result := &models.ExchangeResponse{
		ConnectionID: id,
	}

	response := models.AcceptExchangeResult{Result: result}

	c.writeResponse(rw, response)
}

// QueryConnections swagger:route GET /connections did-exchange queryConnections
//
// query agent to agent connections.
//
// Responses:
//    default: genericError
//        200: queryConnectionsResponse
func (c *Operation) QueryConnections(rw http.ResponseWriter, req *http.Request) {
	logger.Debugf("Querying connection invitations ")

	var request didexchange.QueryConnectionsParams

	err := getQueryParams(&request, req.URL.Query())
	if err != nil {
		resterrors.SendHTTPBadRequest(rw, InvalidRequestErrorCode, err)
		return
	}

	results, err := c.client.QueryConnections(&request)
	if err != nil {
		resterrors.SendHTTPInternalServerError(rw, QueryConnectionsErrorCode, err)
		return
	}

	response := models.QueryConnectionsResponse{
		Results: results,
	}

	c.writeResponse(rw, response)
}

// QueryConnectionByID swagger:route GET /connections/{id} did-exchange getConnection
//
// Fetch a single connection record.
//
// Responses:
//    default: genericError
//        200: queryConnectionResponse
func (c *Operation) QueryConnectionByID(rw http.ResponseWriter, req *http.Request) {
	id := mux.Vars(req)["id"]
	if id == "" {
		resterrors.SendHTTPBadRequest(rw, InvalidRequestErrorCode, fmt.Errorf("empty connection ID"))
	}

	logger.Debugf("Querying connection invitation for id [%s]", id)

	result, err := c.client.GetConnection(id)
	if err != nil {
		resterrors.SendHTTPInternalServerError(rw, QueryConnectionsErrorCode, err)
		return
	}

	response := models.QueryConnectionResponse{
		Result: result,
	}

	c.writeResponse(rw, response)
}

// RemoveConnection swagger:route POST /connections/{id}/remove did-exchange removeConnection
//
// Removes given connection record.
//
// Responses:
//    default: genericError
//    200: removeConnectionResponse
func (c *Operation) RemoveConnection(rw http.ResponseWriter, req *http.Request) {
	id := mux.Vars(req)["id"]
	if id == "" {
		resterrors.SendHTTPBadRequest(rw, InvalidRequestErrorCode, fmt.Errorf("empty connection ID"))
	}

	logger.Debugf("Removing connection record for id [%s]", id)

	err := c.client.RemoveConnection(id)
	if err != nil {
		resterrors.SendHTTPInternalServerError(rw, RemoveConnectionErrorCode, err)
		return
	}
}

// writeResponse writes interface value to response
func (c *Operation) writeResponse(rw io.Writer, v interface{}) {
	err := json.NewEncoder(rw).Encode(v)
	// as of now, just log errors for writing response
	if err != nil {
		logger.Errorf("Unable to send error response, %s", err)
	}
}

// GetRESTHandlers get all controller API handler available for this protocol service
func (c *Operation) GetRESTHandlers() []operation.Handler {
	return c.handlers
}

// registerHandler register handlers to be exposed from this protocol service as REST API endpoints
func (c *Operation) registerHandler() {
	// Add more protocol endpoints here to expose them as controller API endpoints
	c.handlers = []operation.Handler{
		support.NewHTTPHandler(connections, http.MethodGet, c.QueryConnections),
		support.NewHTTPHandler(connectionsByID, http.MethodGet, c.QueryConnectionByID),
		support.NewHTTPHandler(createInvitationPath, http.MethodPost, c.CreateInvitation),
		support.NewHTTPHandler(createImplicitInvitationPath, http.MethodPost, c.CreateImplicitInvitation),
		support.NewHTTPHandler(receiveInvitationPath, http.MethodPost, c.ReceiveInvitation),
		support.NewHTTPHandler(acceptInvitationPath, http.MethodPost, c.AcceptInvitation),
		support.NewHTTPHandler(acceptExchangeRequest, http.MethodPost, c.AcceptExchangeRequest),
		support.NewHTTPHandler(removeConnection, http.MethodPost, c.RemoveConnection),
	}
}

// getQueryParams converts query strings to `map[string]string`
// and unmarshals to the value pointed by v by following
// `json.Unmarshal` rules.
func getQueryParams(v interface{}, vals url.Values) error {
	// normalize all query string key/values
	args := make(map[string]string)

	for k, v := range vals {
		if len(v) > 0 {
			args[k] = v[0]
		}
	}

	bytes, err := json.Marshal(args)
	if err != nil {
		return err
	}

	return json.Unmarshal(bytes, v)
}

// startClientEventListener listens to action and message events from DID Exchange service.
func (c *Operation) startClientEventListener() error {
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

func (c *Operation) handleMessageEvents(e service.StateMsg) error {
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

func (c *Operation) sendConnectionNotification(connectionID, stateID string) error {
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
