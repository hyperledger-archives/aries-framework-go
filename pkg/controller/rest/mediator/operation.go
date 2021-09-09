/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mediator

import (
	"fmt"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

// constants for the mediator operations.
const (
	RouteOperationID   = "/mediator"
	RegisterPath       = RouteOperationID + "/register"
	UnregisterPath     = RouteOperationID + "/unregister"
	GetConnectionsPath = RouteOperationID + "/connections"
	ReconnectPath      = RouteOperationID + "/reconnect"
	StatusPath         = RouteOperationID + "/status"
	BatchPickupPath    = RouteOperationID + "/batchpickup"
	ReconnectAllPath   = RouteOperationID + "/reconnect-all"
)

// provider contains dependencies for the route protocol and is typically created by using aries.Context().
type provider interface {
	Service(id string) (interface{}, error)
	KMS() kms.KeyManager
	ServiceEndpoint() string
	KeyType() kms.KeyType
	KeyAgreementType() kms.KeyType
	MediaTypeProfiles() []string
}

// Operation contains basic common operations provided by controller REST API.
type Operation struct {
	handlers []rest.Handler
	command  *mediator.Command
}

// New returns new common operations rest client instance.
func New(ctx provider, autoAccept bool) (*Operation, error) {
	routeCmd, err := mediator.New(ctx, autoAccept)
	if err != nil {
		return nil, fmt.Errorf("create route command : %w", err)
	}

	o := &Operation{command: routeCmd}

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
		cmdutil.NewHTTPHandler(RegisterPath, http.MethodPost, o.Register),
		cmdutil.NewHTTPHandler(UnregisterPath, http.MethodDelete, o.Unregister),
		cmdutil.NewHTTPHandler(GetConnectionsPath, http.MethodGet, o.Connections),
		cmdutil.NewHTTPHandler(ReconnectPath, http.MethodPost, o.Reconnect),
		cmdutil.NewHTTPHandler(StatusPath, http.MethodPost, o.Status),
		cmdutil.NewHTTPHandler(BatchPickupPath, http.MethodPost, o.BatchPickup),
		cmdutil.NewHTTPHandler(ReconnectAllPath, http.MethodGet, o.ReconnectAll),
	}
}

// Register swagger:route POST /mediator/register mediator registerRouteRequest
//
// Registers the agent with the router.
//
// Responses:
//    default: genericError
//    200: registerRouteRes
func (o *Operation) Register(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.Register, rw, req.Body)
}

// Unregister swagger:route DELETE /mediator/unregister mediator unregisterRouter
//
// Unregisters the agent with the router.
//
// Responses:
//    default: genericError
//    200: unregisterRouteRes
func (o *Operation) Unregister(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.Unregister, rw, req.Body)
}

// Connections swagger:route GET /mediator/connections mediator connectionsRequest
//
// Retrieves the router`s connections.
//
// Responses:
//    default: genericError
//    200: getConnectionsResponse
func (o *Operation) Connections(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.Connections, rw, req.Body)
}

// Reconnect swagger:route POST /mediator/reconnect mediator reconnectRouteRequest
//
// Reconnect the agent with the router to re-establish lost connection.
//
// Responses:
//    default: genericError
func (o *Operation) Reconnect(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.Reconnect, rw, req.Body)
}

// Status swagger:route POST /mediator/status mediator statusRequest
//
// Status returns details about pending messages for given connection.
//
// Responses:
//    default: genericError
//    200: statusResponse
func (o *Operation) Status(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.Status, rw, req.Body)
}

// BatchPickup swagger:route POST /mediator/batchpickup mediator batchPickupRequest
//
// BatchPickup dispatches pending messages for given connection.
//
// Responses:
//    default: genericError
//    200: batchPickupResponse
func (o *Operation) BatchPickup(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.BatchPickup, rw, req.Body)
}

// ReconnectAll swagger:route GET /mediator/reconnect-all mediator reconnectAll
//
// Re-establishes network connections for all mediator connections.
//
// Responses:
//    default: genericError
func (o *Operation) ReconnectAll(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.ReconnectAll, rw, req.Body)
}
