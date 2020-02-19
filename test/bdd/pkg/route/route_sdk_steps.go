/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package route

import (
	"fmt"

	"github.com/cucumber/godog"

	"github.com/hyperledger/aries-framework-go/pkg/client/route"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
)

// SDKSteps is steps for route using client SDK
type SDKSteps struct {
	bddContext *context.BDDContext
}

// NewRouteSDKSteps return steps for router using client SDK
func NewRouteSDKSteps(ctx *context.BDDContext) *SDKSteps {
	return &SDKSteps{
		bddContext: ctx,
	}
}

// CreateRouteClient creates route client
func (d *SDKSteps) CreateRouteClient(agentID string) error {
	// create new route client
	routeClient, err := route.New(d.bddContext.AgentCtx[agentID])
	if err != nil {
		return fmt.Errorf("failed to create new route client: %w", err)
	}

	d.bddContext.RouteClients[agentID] = routeClient

	return nil
}

// RegisterRoute registers the router for the agent
func (d *SDKSteps) RegisterRoute(agentID, varName string) error {
	err := d.bddContext.RouteClients[agentID].Register(d.bddContext.Args[varName])
	if err != nil {
		return fmt.Errorf("register route : %w", err)
	}

	return nil
}

// VerifyConnection verifies the router connection id has been set to the provided connection id.
func (d *SDKSteps) VerifyConnection(agentID, varName string) error {
	connectionID, err := d.bddContext.RouteClients[agentID].GetConnection()
	if err != nil {
		return fmt.Errorf("fetch router connection id : %w", err)
	}

	if connectionID != d.bddContext.Args[varName] {
		return fmt.Errorf("router connection id does not match : routerConnID=%s newConnID=%s",
			connectionID, d.bddContext.Args[varName])
	}

	return nil
}

// RegisterSteps registers router steps
func (d *SDKSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^"([^"]*)" creates a route exchange client$`, d.CreateRouteClient)
	s.Step(`^"([^"]*)" sets "([^"]*)" as the router$`, d.RegisterRoute)
	s.Step(`^"([^"]*)" verifies that the router connection id is set to "([^"]*)"$`, d.VerifyConnection)
}
