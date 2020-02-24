/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package route

import (
	"fmt"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command/route"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
)

const (
	routeOperationID  = "/route"
	registerPath      = routeOperationID + "/register"
	unregisterPath    = routeOperationID + "/unregister"
	getConnectionPath = routeOperationID + "/connection"
)

// provider contains dependencies for the route protocol and is typically created by using aries.Context().
type provider interface {
	Service(id string) (interface{}, error)
}

// Operation contains basic common operations provided by controller REST API
type Operation struct {
	handlers []rest.Handler
	command  *route.Command
}

// New returns new common operations rest client instance
func New(ctx provider) (*Operation, error) {
	routeCmd, err := route.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("create route command : %w", err)
	}

	o := &Operation{command: routeCmd}

	o.registerHandler()

	return o, nil
}

// GetRESTHandlers get all controller API handler available for this service
func (o *Operation) GetRESTHandlers() []rest.Handler {
	return o.handlers
}

// registerHandler register handlers to be exposed from this protocol service as REST API endpoints.
func (o *Operation) registerHandler() {
	// Add more protocol endpoints here to expose them as controller API endpoints
	o.handlers = []rest.Handler{
		cmdutil.NewHTTPHandler(registerPath, http.MethodPost, o.Register),
		cmdutil.NewHTTPHandler(unregisterPath, http.MethodDelete, o.Unregister),
		cmdutil.NewHTTPHandler(getConnectionPath, http.MethodGet, o.Connection),
	}
}

// Register swagger:route POST /route/register route registerRouteRequest
//
// Registers the agent with the router.
//
// Responses:
//    default: genericError
//    200: registerRouteRes
func (o *Operation) Register(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.Register, rw, req.Body)
}

// Unregister swagger:route DELETE /route/unregister route unregisterRouter
//
// Unregisters the agent with the router.
//
// Responses:
//    default: genericError
func (o *Operation) Unregister(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.Unregister, rw, req.Body)
}

// Connection swagger:route GET /route/connection route routerConnection
//
// Retrieves the router connection id.
//
// Responses:
//    default: genericError
//    200: getConnectionResponse
func (o *Operation) Connection(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.Connection, rw, req.Body)
}
