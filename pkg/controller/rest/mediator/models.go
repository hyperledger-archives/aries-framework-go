/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mediator

import "github.com/hyperledger/aries-framework-go/pkg/controller/command/mediator"

// registerRouteReq model
//
// This is used register router for the agent.
//
// swagger:parameters registerRouteRequest
type registerRouteReq struct { // nolint: unused,deadcode
	// Params for registering the route
	//
	// in: body
	Params mediator.RegisterRoute
}

// unregisterRouteRes model
//
// swagger:response unregisterRouteRes
type unregisterRouteRes struct { // nolint: unused,deadcode
	// in: body
	Body struct{}
}

// registerRouteRes model
//
// swagger:response registerRouteRes
type registerRouteRes struct {
	// in: body
	Body struct{}
}

// ConnectionsResponse model
//
// Represents a Connections response message
//
// swagger:response getConnectionsResponse
type ConnectionsResponse struct {
	// in: body
	Params mediator.ConnectionsResponse
}

// unregisterRouterReq model
//
// This is used for unregister a router for the agent.
//
// swagger:parameters unregisterRouter
type unregisterRouterReq struct { // nolint: unused,deadcode
	// Params for unregister the router
	//
	// in: body
	Params mediator.RegisterRoute
}

// reconnectRouteReq model
//
// This is used register router for the agent.
//
// swagger:parameters reconnectRouteRequest
type reconnectRouteReq struct { // nolint: unused,deadcode
	// Params for reconnecting the router
	//
	// in: body
	Params mediator.RegisterRoute
}

// statusRequest model
//
// This is used for getting details of pending messages for given connection.
//
// swagger:parameters statusRequest
type statusRequest struct { // nolint: unused,deadcode
	// Params for getting details of pending messages for given connection.
	//
	// in: body
	Params mediator.StatusRequest
}

// statusResponse model
//
// Response containing details of pending messages for given connection.
//
// swagger:response statusResponse
type statusResponse struct {
	// Details of pending messages for given connection.
	//
	// in: body
	Params mediator.StatusResponse
}

// batchPickupRequest model
//
// For dispatching pending messages for given connection.
//
// swagger:parameters batchPickupRequest
type batchPickupRequest struct { // nolint: unused,deadcode
	// Params for dispatching pending messages for given connection..
	//
	// in: body
	Params mediator.BatchPickupRequest
}

// batchPickupResponse model
//
// Response from router after pending messages dispatched for given connection.
//
// swagger:response batchPickupResponse
type batchPickupResponse struct {
	// Response after dispatching pending messages for given connection...
	//
	// in: body
	Params mediator.BatchPickupResponse
}
