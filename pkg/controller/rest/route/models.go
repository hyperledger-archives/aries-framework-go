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
	Params route.RegisterRouteReq
}

// registerRouteRes model
//
// swagger:response registerRouteRes
type registerRouteRes struct { // nolint: unused,deadcode
}
