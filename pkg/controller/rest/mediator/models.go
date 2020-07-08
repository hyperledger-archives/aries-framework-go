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

// registerRouteRes model
//
// swagger:response registerRouteRes
type registerRouteRes struct { // nolint: unused,deadcode
}

// ConnectionRes model
//
// response of get connection action
//
// swagger:response getConnectionResponse
type ConnectionRes struct { // nolint: unused,deadcode
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
