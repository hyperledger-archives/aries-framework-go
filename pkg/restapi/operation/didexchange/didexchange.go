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
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	didexchangeSvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/internal/common/support"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/operation"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/operation/didexchange/models"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/webhook"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

var logger = log.New("aries-framework/did-exchange")

const (
	operationID             = "/connections"
	createInvitationPath    = operationID + "/create-invitation"
	receiveInvitationPath   = operationID + "/receive-invitation"
	acceptInvitationPath    = operationID + "/{id}/accept-invitation"
	connections             = operationID
	connectionsByID         = operationID + "/{id}"
	acceptExchangeRequest   = operationID + "/{id}/accept-request"
	removeConnection        = operationID + "/{id}/remove"
	connectionsWebhookTopic = "connections"
)

// provider contains dependencies for the Exchange protocol and is typically created by using aries.Context()
type provider interface {
	Service(id string) (interface{}, error)
	KMS() kms.KeyManager
	InboundTransportEndpoint() string
	StorageProvider() storage.Provider
}

// New returns new DID Exchange rest client protocol instance
func New(ctx provider, notifier webhook.Notifier, defaultLabel string) (*Operation, error) {
	didExchange, err := didexchange.New(ctx)
	if err != nil {
		return nil, err
	}

	svc := &Operation{
		ctx:    ctx,
		client: didExchange,
		// TODO channel size - https://github.com/hyperledger/aries-framework-go/issues/246
		actionCh:     make(chan service.DIDCommAction, 10),
		msgCh:        make(chan service.StateMsg, 10),
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
	actionCh     chan service.DIDCommAction
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
		c.writeGenericError(rw, err)
		return
	}

	var alias string
	if request.CreateInvitationParams != nil {
		alias = request.CreateInvitationParams.Alias
	}

	// call didexchange client
	invitation, err := c.client.CreateInvitation(c.defaultLabel)
	if err != nil {
		c.writeGenericError(rw, err)
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
		c.writeGenericError(rw, err)
		return
	}

	err = c.client.HandleInvitation(request.Invitation)
	if err != nil {
		c.writeGenericError(rw, err)
		return
	}

	// TODO https://github.com/hyperledger/aries-framework-go/issues/537 Return Connection data
	sampleResponse := models.ReceiveInvitationResponse{
		ConnectionID:  "f52024c4-04e7-4aeb-8486-1040155c6764",
		DID:           "TAaW9Dmxa93B8e5x6iLwFJ",
		State:         "requested",
		CreateTime:    time.Now(),
		UpdateTime:    time.Now(),
		Accept:        "auto",
		Initiator:     "external",
		InvitationKey: "none",
		InviterLabel:  "other party",
		Mode:          "none",
		RequestID:     "678ad4b6-4e2b-40a1-804e-8ba504945e26",
		RoutingState:  "none",
	}

	c.writeResponse(rw, sampleResponse)
}

// AcceptInvitation swagger:route POST /connections/{id}/accept-invitation did-exchange acceptInvitation
//
// Accept a stored connection invitation....
//
// Responses:
//    default: genericError
//        200: acceptInvitationResponse
func (c *Operation) AcceptInvitation(rw http.ResponseWriter, req *http.Request) {
	params := mux.Vars(req)
	logger.Debugf("Accepting connection invitation for id[%s]", params["id"])

	// TODO https://github.com/hyperledger/aries-framework-go/issues/550 Support for AcceptInvitation API
	response := models.AcceptInvitationResponse{
		ConnectionID:  params["id"],
		DID:           "TAaW9Dmxa93B8e5x6iLwFJ",
		State:         "requested",
		CreateTime:    time.Now(),
		UpdateTime:    time.Now(),
		Accept:        "auto",
		Initiator:     "external",
		InvitationKey: "none",
		InviterLabel:  "other party",
		Mode:          "none",
		RequestID:     "678ad4b6-4e2b-40a1-804e-8ba504945e26",
		RoutingState:  "none",
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
	params := mux.Vars(req)
	logger.Debugf("Accepting connection request for id [%s]", params["id"])

	// TODO https://github.com/hyperledger/aries-framework-go/issues/549 Support for AcceptExchangeRequest API
	result := &models.ExchangeResponse{
		ConnectionID: uuid.New().String(), CreatedTime: time.Now(),
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
		c.writeGenericError(rw, err)
		return
	}

	records, err := c.client.QueryConnections(&request)
	if err != nil {
		c.writeGenericError(rw, err)
		return
	}

	// TODO more filters to be applied as part of [Issue #655]
	var result []*didexchangeSvc.ConnectionRecord
	if request.State != "" {
		// filter by state
		for _, record := range records {
			if strings.EqualFold(record.State, request.State) {
				result = append(result, record)
			}
		}
	} else {
		result = records
	}

	response := models.QueryConnectionsResponse{
		Results: result,
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
	params := mux.Vars(req)
	logger.Debugf("Querying connection invitation for id [%s]", params["id"])

	result, err := c.client.GetConnection(params["id"])
	if err != nil {
		c.writeGenericError(rw, err)
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
	params := mux.Vars(req)
	logger.Debugf("Removing connection record for id [%s]", params["id"])

	err := c.client.RemoveConnection(params["id"])
	if err != nil {
		c.writeGenericError(rw, err)
		return
	}
}

// writeGenericError writes given error to writer as generic error response
func (c *Operation) writeGenericError(rw io.Writer, err error) {
	errResponse := models.GenericError{
		Body: struct {
			Code    int32  `json:"code"`
			Message string `json:"message"`
		}{
			// TODO implement error codes, below is sample error code
			Code:    1,
			Message: err.Error(),
		},
	}
	c.writeResponse(rw, errResponse)
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
	// register the action event channel
	err := c.client.RegisterActionEvent(c.actionCh)
	if err != nil {
		return fmt.Errorf("didexchange action event registration failed: %w", err)
	}

	// register the message event channel
	err = c.client.RegisterMsgEvent(c.msgCh)
	if err != nil {
		return fmt.Errorf("didexchange message event registration failed: %w", err)
	}

	// event listeners
	go func() {
		for {
			select {
			case e := <-c.actionCh:
				c.handleActionEvents(e)
			case e := <-c.msgCh:
				err := c.handleMessageEvents(e)
				if err != nil {
					logger.Errorf("handle message events failed : %s", err)
				}
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

func (c *Operation) handleActionEvents(e service.DIDCommAction) {
	// TODO https://github.com/hyperledger/aries-framework-go/issues/579 - Integrate Action events with webhooks
	e.Continue()
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
