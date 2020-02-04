/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/webhook"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	svchttp "github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/service/http"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/internal/common/support"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
	resterrors "github.com/hyperledger/aries-framework-go/pkg/restapi/errors"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/operation"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
)

var logger = log.New("aries-framework/controller/common")

const (
	// vdri endpoints
	vdriOperationID     = "/vdri"
	createPublicDIDPath = vdriOperationID + "/create-public-did"

	// http over didcomm endpoints
	httpOverDIDComm                = "/http-over-didcomm"
	registerHTTPOverDIDCommService = httpOverDIDComm + "/register"

	// message service endpoints
	msgServiceOperationID = "/message"
	registerMsgService    = msgServiceOperationID + "/register-service"
	unregisterMsgService  = msgServiceOperationID + "/unregister-service"
	msgServiceList        = msgServiceOperationID + "/services"
	sendNewMsg            = msgServiceOperationID + "/send"
	sendReplyMsg          = msgServiceOperationID + "/reply"

	// states
	stateNameCompleted = "completed"

	// error messages
	errMsgSvcNameRequired               = "service name is required"
	errMsgInvalidAcceptanceCrit         = "invalid acceptance criteria"
	errMsgBodyEmpty                     = "empty message body"
	errMsgDestinationMissing            = "missing message destination"
	errMsgDestSvcEndpointMissing        = "missing service endpoint in message destination"
	errMsgDestSvcEndpointKeysMissing    = "missing service endpoint recipient/routing keys in message destination"
	errMsgConnectionMatchingDIDNotFound = "unable to find connection matching theirDID[%s]"
	errMsgIDEmpty                       = "empty message ID"
)

// Error codes
const (
	// InvalidRequestErrorCode is typically a code for invalid requests
	InvalidRequestErrorCode = resterrors.Code(iota + resterrors.Common)

	// CreatePublicDIDError is for failures while creating public DIDs
	CreatePublicDIDError

	// RegisterMsgSvcError is for failures while registering new message service
	RegisterMsgSvcError

	// UnregisterMsgSvcError is for failures while unregistering a message service
	UnregisterMsgSvcError

	// SendMsgError is for failures while sending messages
	SendMsgError

	// SendMsgReplyError is for failures while sending message replies
	SendMsgReplyError
)

// provider contains dependencies for the common controller operations
// and is typically created by using aries.Context()
type provider interface {
	VDRIRegistry() vdriapi.Registry
	OutboundDispatcher() dispatcher.Outbound
	TransientStorageProvider() storage.Provider
	StorageProvider() storage.Provider
	LegacyKMS() legacykms.KeyManager
}

// Operation contains basic common operations provided by controller REST API
type Operation struct {
	ctx              provider
	handlers         []operation.Handler
	msgRegistrar     operation.MessageHandler
	notifier         webhook.Notifier
	connectionLookup *connection.Lookup
}

// New returns new common operations rest client instance
func New(ctx provider, registrar operation.MessageHandler, notifier webhook.Notifier) (*Operation, error) {
	connectionLookup, err := connection.NewLookup(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize connection lookup : %w", err)
	}

	o := &Operation{
		ctx:              ctx,
		msgRegistrar:     registrar,
		notifier:         notifier,
		connectionLookup: connectionLookup,
	}
	defer o.registerHandler()

	return o, nil
}

// GetRESTHandlers get all controller API handler available for this service
func (o *Operation) GetRESTHandlers() []operation.Handler {
	return o.handlers
}

// registerHandler register handlers to be exposed from this protocol service as REST API endpoints
func (o *Operation) registerHandler() {
	// Add more protocol endpoints here to expose them as controller API endpoints
	o.handlers = []operation.Handler{
		support.NewHTTPHandler(createPublicDIDPath, http.MethodPost, o.CreatePublicDID),
		support.NewHTTPHandler(registerMsgService, http.MethodPost, o.RegisterMessageService),
		support.NewHTTPHandler(unregisterMsgService, http.MethodPost, o.UnregisterMessageService),
		support.NewHTTPHandler(msgServiceList, http.MethodGet, o.RegisteredServices),
		support.NewHTTPHandler(sendNewMsg, http.MethodPost, o.SendNewMessage),
		support.NewHTTPHandler(sendReplyMsg, http.MethodPost, o.SendReplyMessage),
		support.NewHTTPHandler(registerHTTPOverDIDCommService, http.MethodPost, o.RegisterHTTPMessageService),
	}
}

// CreatePublicDID swagger:route POST /vdri/create-public-did vdri createPublicDID
//
// Creates a new Public DID....
//
// Responses:
//    default: genericError
//        200: createPublicDIDResponse
func (o *Operation) CreatePublicDID(rw http.ResponseWriter, req *http.Request) {
	var request CreatePublicDIDRequest

	err := getQueryParams(&request, req.URL.Query())
	if err != nil {
		resterrors.SendHTTPBadRequest(rw, InvalidRequestErrorCode, err)
		return
	}

	if request.CreatePublicDIDParams == nil || request.Method == "" {
		resterrors.SendHTTPBadRequest(rw, InvalidRequestErrorCode, fmt.Errorf("invalid method name"))
		return
	}

	logger.Debugf("creating public DID for method[%s]", request.Method)

	doc, err := o.ctx.VDRIRegistry().Create(strings.ToLower(request.Method),
		vdriapi.WithRequestBuilder(getBasicRequestBuilder(request.RequestHeader)))
	if err != nil {
		resterrors.SendHTTPInternalServerError(rw, CreatePublicDIDError, err)
		return
	}

	o.writeResponse(rw, CreatePublicDIDResponse{DID: doc})
}

// RegisterMessageService swagger:route POST /message/register-service message registerMsgSvc
//
// registers new message service to message handler registrar
//
// Responses:
//    default: genericError
func (o *Operation) RegisterMessageService(rw http.ResponseWriter, req *http.Request) {
	var request RegisterMessageServiceRequest

	err := json.NewDecoder(req.Body).Decode(&request.Params)
	if err != nil {
		resterrors.SendHTTPBadRequest(rw, InvalidRequestErrorCode, err)
		return
	}

	o.registerMessageService(rw, request.Params)
}

// UnregisterMessageService swagger:route POST /message/unregister-service message http-over-didcomm unregisterMsgSvc
//
// unregisters given message service handler registrar
//
// Responses:
//    default: genericError
func (o *Operation) UnregisterMessageService(rw http.ResponseWriter, req *http.Request) {
	var request UnregisterMessageServiceRequest

	err := json.NewDecoder(req.Body).Decode(&request.Params)
	if err != nil {
		resterrors.SendHTTPBadRequest(rw, InvalidRequestErrorCode, err)
		return
	}

	if request.Params.Name == "" {
		resterrors.SendHTTPBadRequest(rw, InvalidRequestErrorCode, fmt.Errorf(errMsgSvcNameRequired))
		return
	}

	err = o.msgRegistrar.Unregister(request.Params.Name)
	if err != nil {
		resterrors.SendHTTPInternalServerError(rw, UnregisterMsgSvcError, err)
		return
	}

	rw.WriteHeader(http.StatusOK)
}

// RegisteredServices swagger:route GET /message/services message http-over-didcomm services
//
// returns list of registered service names
//
// Responses:
//    default: genericError
//    200: registeredServicesResponse
func (o *Operation) RegisteredServices(rw http.ResponseWriter, req *http.Request) {
	names := []string{}
	for _, svc := range o.msgRegistrar.Services() {
		names = append(names, svc.Name())
	}

	o.writeResponse(rw, RegisteredServicesResponse{Names: names})
}

// SendNewMessage swagger:route POST /message/send message sendNewMessage
//
// sends new message to destination provided
//
// Responses:
//    default: genericError
func (o *Operation) SendNewMessage(rw http.ResponseWriter, req *http.Request) {
	var request SendNewMessageRequest

	err := json.NewDecoder(req.Body).Decode(&request.Params)
	if err != nil {
		resterrors.SendHTTPBadRequest(rw, InvalidRequestErrorCode, err)
		return
	}

	if len(request.Params.MessageBody) == 0 {
		resterrors.SendHTTPBadRequest(rw, InvalidRequestErrorCode, fmt.Errorf(errMsgBodyEmpty))
		return
	}

	err = o.validateMessageDestination(request.Params)
	if err != nil {
		resterrors.SendHTTPBadRequest(rw, InvalidRequestErrorCode, err)
		return
	}

	if request.Params.ConnectionID != "" {
		conn, err := o.connectionLookup.GetConnectionRecord(request.Params.ConnectionID)
		if err != nil {
			resterrors.SendHTTPInternalServerError(rw, SendMsgError, err)
			return
		}

		o.sendMessageToConnection(request.Params.MessageBody, rw, conn)

		return
	}

	if request.Params.TheirDID != "" {
		conn, err := o.getConnectionByTheirDID(request.Params.TheirDID)
		if err != nil {
			resterrors.SendHTTPInternalServerError(rw, SendMsgError, err)
			return
		}

		o.sendMessageToConnection(request.Params.MessageBody, rw, conn)

		return
	}

	o.sendMessageToDestination(request.Params.MessageBody, rw, request.Params.ServiceEndpointDestination)
}

// SendReplyMessage swagger:route POST /message/reply message sendReplyMessage
//
// sends reply to existing message
//
// Responses:
//    default: genericError
func (o *Operation) SendReplyMessage(rw http.ResponseWriter, req *http.Request) {
	var request SendReplyMessageRequest

	err := json.NewDecoder(req.Body).Decode(&request.Params)
	if err != nil {
		resterrors.SendHTTPBadRequest(rw, InvalidRequestErrorCode, err)
		return
	}

	if len(request.Params.MessageBody) == 0 {
		resterrors.SendHTTPBadRequest(rw, InvalidRequestErrorCode, fmt.Errorf(errMsgBodyEmpty))
		return
	}

	if request.Params.MessageID == "" {
		resterrors.SendHTTPBadRequest(rw, InvalidRequestErrorCode, fmt.Errorf(errMsgIDEmpty))
		return
	}

	// TODO this operation will be supported once messenger API [Issue #1039] is available
	// TODO implementation for SendReply to be added as part of [Issue #1089]
	resterrors.SendHTTPStatusError(rw, SendMsgReplyError, fmt.Errorf("to be implemented"), http.StatusNotImplemented)
}

// RegisterHTTPMessageService swagger:route POST /http-over-didcomm/register http-over-didcomm registerHttpMsgSvc
//
// registers new http over didcomm service to message handler registrar
//
// Responses:
//    default: genericError
func (o *Operation) RegisterHTTPMessageService(rw http.ResponseWriter, req *http.Request) {
	var request RegisterHTTPMessageServiceRequest

	err := json.NewDecoder(req.Body).Decode(&request.Params)
	if err != nil {
		resterrors.SendHTTPBadRequest(rw, InvalidRequestErrorCode, err)
		return
	}

	o.registerMessageService(rw, &RegisterMsgSvcParams{
		Name:    request.Params.Name,
		Type:    svchttp.OverDIDCommMsgRequestType,
		Purpose: request.Params.Purpose,
	})
}

func (o *Operation) registerMessageService(rw http.ResponseWriter, params *RegisterMsgSvcParams) {
	if params.Name == "" {
		resterrors.SendHTTPBadRequest(rw, InvalidRequestErrorCode, fmt.Errorf(errMsgSvcNameRequired))
		return
	}

	if params.Type == "" {
		resterrors.SendHTTPBadRequest(rw, InvalidRequestErrorCode, fmt.Errorf(errMsgInvalidAcceptanceCrit))
		return
	}

	err := o.msgRegistrar.Register(newMessageService(params, o.notifier))
	if err != nil {
		resterrors.SendHTTPInternalServerError(rw, RegisterMsgSvcError, err)
		return
	}

	rw.WriteHeader(http.StatusOK)
}

func (o *Operation) validateMessageDestination(dest *SendNewMessageParams) error {
	var didMissing, connIDMissing, svcEPMissing = dest.TheirDID == "",
		dest.ConnectionID == "",
		dest.ServiceEndpointDestination == nil

	if didMissing && connIDMissing && svcEPMissing {
		return fmt.Errorf(errMsgDestinationMissing)
	}

	if !didMissing || !connIDMissing {
		return nil
	}

	if dest.ServiceEndpointDestination.ServiceEndpoint == "" {
		return fmt.Errorf(errMsgDestSvcEndpointMissing)
	}

	if len(dest.ServiceEndpointDestination.RecipientKeys) == 0 &&
		len(dest.ServiceEndpointDestination.RoutingKeys) == 0 {
		return fmt.Errorf(errMsgDestSvcEndpointKeysMissing)
	}

	return nil
}

func (o *Operation) getConnectionByTheirDID(theirDID string) (*connection.Record, error) {
	records, err := o.connectionLookup.QueryConnectionRecords()
	if err != nil {
		return nil, err
	}

	for _, record := range records {
		if record.State == stateNameCompleted && record.TheirDID == theirDID {
			return record, nil
		}
	}

	return nil, fmt.Errorf(errMsgConnectionMatchingDIDNotFound, theirDID)
}

func (o *Operation) sendMessageToConnection(msg json.RawMessage, rw http.ResponseWriter, conn *connection.Record) {
	err := o.ctx.OutboundDispatcher().SendToDID(msg, conn.MyDID, conn.TheirDID)
	if err != nil {
		resterrors.SendHTTPInternalServerError(rw, SendMsgError, err)
		return
	}
}

func (o *Operation) sendMessageToDestination(msg json.RawMessage, rw http.ResponseWriter,
	dest *ServiceEndpointDestinationParams) {
	_, sigPubKey, err := o.ctx.LegacyKMS().CreateKeySet()
	if err != nil {
		resterrors.SendHTTPInternalServerError(rw, SendMsgError, err)
		return
	}

	err = o.ctx.OutboundDispatcher().Send(msg, sigPubKey, &service.Destination{
		RoutingKeys:     dest.RoutingKeys,
		RecipientKeys:   dest.RecipientKeys,
		ServiceEndpoint: dest.ServiceEndpoint,
	})
	if err != nil {
		resterrors.SendHTTPInternalServerError(rw, SendMsgError, err)
		return
	}
}

// writeResponse writes interface value to response
func (o *Operation) writeResponse(rw io.Writer, v interface{}) {
	err := json.NewEncoder(rw).Encode(v)
	// as of now, just log errors for writing response
	if err != nil {
		logger.Errorf("Unable to send error response, %s", err)
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

	b, err := json.Marshal(args)
	if err != nil {
		return err
	}

	return json.Unmarshal(b, v)
}

// prepareBasicRequestBuilder is basic request builder for public DID creation
// request body format is : {"header": {raw header}, "payload": "payload"}
func getBasicRequestBuilder(header string) func(payload []byte) (io.Reader, error) {
	return func(payload []byte) (io.Reader, error) {
		request := struct {
			Header  json.RawMessage `json:"header"`
			Payload string          `json:"payload"`
		}{
			Header:  json.RawMessage(header),
			Payload: base64.URLEncoding.EncodeToString(payload),
		}

		b, err := json.Marshal(request)
		if err != nil {
			return nil, err
		}

		return bytes.NewReader(b), nil
	}
}
