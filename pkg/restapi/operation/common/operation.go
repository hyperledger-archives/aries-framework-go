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

	"github.com/hyperledger/aries-framework-go/pkg/restapi/webhook"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/internal/common/support"
	resterrors "github.com/hyperledger/aries-framework-go/pkg/restapi/errors"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/operation"
)

var logger = log.New("aries-framework/controller/common")

const (
	// vdri endpoints
	vdriOperationID     = "/vdri"
	createPublicDIDPath = vdriOperationID + "/create-public-did"

	// message service endpoints
	msgServiceOperationID = "/message"
	registerMsgService    = msgServiceOperationID + "/register-service"
	unregisterMsgService  = msgServiceOperationID + "/unregister-service"
	msgServiceList        = msgServiceOperationID + "/services"

	// error messages
	errMsgSvcNameRequired       = "service name is required"
	errMsgInvalidAcceptanceCrit = "invalid acceptance criteria"
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
)

// provider contains dependencies for the common controller operations
// and is typically created by using aries.Context()
type provider interface {
	VDRIRegistry() vdriapi.Registry
}

// Operation contains basic common operations provided by controller REST API
type Operation struct {
	ctx          provider
	handlers     []operation.Handler
	msgRegistrar operation.MessageHandler
	notifier     webhook.Notifier
}

// New returns new common operations rest client instance
func New(ctx provider, registrar operation.MessageHandler, notifier webhook.Notifier) *Operation {
	o := &Operation{
		ctx:          ctx,
		msgRegistrar: registrar,
		notifier:     notifier,
	}
	defer o.registerHandler()

	return o
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

	if request.Params.Name == "" {
		resterrors.SendHTTPBadRequest(rw, InvalidRequestErrorCode, fmt.Errorf(errMsgSvcNameRequired))
		return
	}

	if len(request.Params.Purpose) == 0 || request.Params.Type == "" {
		resterrors.SendHTTPBadRequest(rw, InvalidRequestErrorCode, fmt.Errorf(errMsgInvalidAcceptanceCrit))
		return
	}

	err = o.msgRegistrar.Register(newMessageService(request.Params, o.notifier))
	if err != nil {
		resterrors.SendHTTPInternalServerError(rw, RegisterMsgSvcError, err)
		return
	}

	rw.WriteHeader(http.StatusOK)
}

// UnregisterMessageService swagger:route POST /message/unregister-service message unregisterMsgSvc
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

// RegisteredServices swagger:route GET /message/services message services
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
