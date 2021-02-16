/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package messaging

import (
	"fmt"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/messaging"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// constants for Messaging operations.
const (
	// http over didcomm endpoints.
	httpOverDIDComm                = "/http-over-didcomm"
	RegisterHTTPOverDIDCommService = httpOverDIDComm + "/register"

	// message service endpoints.
	MsgServiceOperationID = "/message"
	RegisterMsgService    = MsgServiceOperationID + "/register-service"
	UnregisterMsgService  = MsgServiceOperationID + "/unregister-service"
	MsgServiceList        = MsgServiceOperationID + "/services"
	SendNewMsg            = MsgServiceOperationID + "/send"
	SendReplyMsg          = MsgServiceOperationID + "/reply"
)

// provider contains dependencies for the common controller operations
// and is typically created by using aries.Context().
type provider interface {
	VDRegistry() vdr.Registry
	Messenger() service.Messenger
	ProtocolStateStorageProvider() storage.Provider
	StorageProvider() storage.Provider
	KMS() kms.KeyManager
}

// Operation contains basic common operations provided by controller REST API.
type Operation struct {
	command  *messaging.Command
	handlers []rest.Handler
}

// New returns new common operations rest client instance.
func New(ctx provider, registrar command.MessageHandler, notifier command.Notifier) (*Operation, error) {
	msgcmd, err := messaging.New(ctx, registrar, notifier)
	if err != nil {
		return nil, fmt.Errorf("failed to create messaging controller command: %w", err)
	}

	o := &Operation{command: msgcmd}
	o.registerHandler()

	return o, nil
}

// GetRESTHandlers get all controller API handler available for this service.
func (o *Operation) GetRESTHandlers() []rest.Handler {
	return o.handlers
}

// registerHandler register handlers to be exposed from this protocol service as REST API endpoints.
func (o *Operation) registerHandler() {
	// Add more protocol endpoints here to expose them as controller API endpoints
	o.handlers = []rest.Handler{
		cmdutil.NewHTTPHandler(RegisterMsgService, http.MethodPost, o.RegisterService),
		cmdutil.NewHTTPHandler(UnregisterMsgService, http.MethodPost, o.UnregisterService),
		cmdutil.NewHTTPHandler(MsgServiceList, http.MethodGet, o.Services),
		cmdutil.NewHTTPHandler(SendNewMsg, http.MethodPost, o.Send),
		cmdutil.NewHTTPHandler(SendReplyMsg, http.MethodPost, o.Reply),
		cmdutil.NewHTTPHandler(RegisterHTTPOverDIDCommService, http.MethodPost, o.RegisterHTTPService),
	}
}

// RegisterService swagger:route POST /message/register-service message registerMsgSvc
//
// registers new message service to message handler registrar
//
// Responses:
//    default: genericError
func (o *Operation) RegisterService(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.RegisterService, rw, req.Body)
}

// UnregisterService swagger:route POST /message/unregister-service message http-over-didcomm unregisterMsgSvc
//
// unregisters given message service handler registrar
//
// Responses:
//    default: genericError
func (o *Operation) UnregisterService(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.UnregisterService, rw, req.Body)
}

// Services swagger:route GET /message/services message http-over-didcomm services
//
// returns list of registered service names
//
// Responses:
//    default: genericError
//    200: registeredServicesResponse
func (o *Operation) Services(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.Services, rw, req.Body)
}

// Send swagger:route POST /message/send message sendNewMessage
//
// sends new message to destination provided
//
// Responses:
//    default: genericError
//    200: sendMessageResponse
func (o *Operation) Send(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.Send, rw, req.Body)
}

// Reply swagger:route POST /message/reply message sendReplyMessage
//
// sends reply to existing message
//
// Responses:
//    default: genericError
//    200: sendMessageResponse
func (o *Operation) Reply(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.Reply, rw, req.Body)
}

// RegisterHTTPService swagger:route POST /http-over-didcomm/register http-over-didcomm registerHttpMsgSvc
//
// registers new http over didcomm service to message handler registrar
//
// Responses:
//    default: genericError
func (o *Operation) RegisterHTTPService(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.RegisterHTTPService, rw, req.Body)
}
