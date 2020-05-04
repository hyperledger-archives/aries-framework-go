/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package route

import (
	"fmt"

	"github.com/cucumber/godog"

	"github.com/hyperledger/aries-framework-go/pkg/client/route"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
)

// SDKSteps is steps for route using client SDK
type SDKSteps struct {
	bddContext *context.BDDContext
}

// NewRouteSDKSteps return steps for router using client SDK
func NewRouteSDKSteps() *SDKSteps {
	return &SDKSteps{}
}

// CreateRouteClient creates route client
func (d *SDKSteps) CreateRouteClient(agentID string) error {
	// create new route client
	routeClient, err := route.New(d.bddContext.AgentCtx[agentID])
	if err != nil {
		return fmt.Errorf("failed to create new route client: %w", err)
	}

	events := make(chan service.DIDCommAction)

	err = routeClient.RegisterActionEvent(events)
	if err != nil {
		return fmt.Errorf("failed to register %s for action events on their routing client : %w", agentID, err)
	}

	callbacks := make(chan interface{})

	d.bddContext.RouteClients[agentID] = routeClient
	d.bddContext.RouteCallbacks[agentID] = callbacks

	go d.handleEvents(events, callbacks)

	return nil
}

func (d *SDKSteps) handleEvents(events chan service.DIDCommAction, callbacks chan interface{}) {
	for event := range events {
		logger.Debugf("handling event: %+v", event)

		c := <-callbacks

		logger.Debugf("received callback: %+v", c)
		event.Continue(c)
	}
}

// ApproveRequest approves a routing protocol request with the given args.
func (d *SDKSteps) ApproveRequest(agentID string, args interface{}) {
	c, found := d.bddContext.RouteCallbacks[agentID]
	if !found {
		logger.Warnf("no callback channel found for %s", agentID)
		return
	}

	c <- args
}

// RegisterRoute registers the router for the agent
func (d *SDKSteps) RegisterRoute(agentID, varName, routerID string) error {
	go d.ApproveRequest(routerID, nil)

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

// SetContext is called before every scenario is run with a fresh new context
func (d *SDKSteps) SetContext(ctx *context.BDDContext) {
	d.bddContext = ctx
}

// RegisterSteps registers router steps
func (d *SDKSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^"([^"]*)" creates a route exchange client$`, d.CreateRouteClient)
	s.Step(`^"([^"]*)" sets "([^"]*)" as the router and "([^"]*)" approves$`, d.RegisterRoute)
	s.Step(`^"([^"]*)" verifies that the router connection id is set to "([^"]*)"$`, d.VerifyConnection)
}
