/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package route

import (
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/route"
)

// registerRouteReq model
//
// This is used register router for the agent.
//
// swagger:parameters registerRouteRequest
type registerRouteReq struct { // nolint: unused,deadcode
	// Params for registering the route
	//
	// in: body
	Params route.RegisterRoute
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
	Params route.RegisterRoute
}
