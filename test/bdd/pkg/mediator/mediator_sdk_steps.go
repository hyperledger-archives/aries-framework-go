/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mediator

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cucumber/godog"

	"github.com/hyperledger/aries-framework-go/pkg/client/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	routesvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
)

const sleepDuration = 2 * time.Millisecond

// SDKSteps is steps for route using client SDK.
type SDKSteps struct {
	bddContext     *context.BDDContext
	eventsReceived map[string]service.DIDCommAction
	lock           sync.RWMutex
}

// NewRouteSDKSteps return steps for router using client SDK.
func NewRouteSDKSteps() *SDKSteps {
	return &SDKSteps{
		eventsReceived: make(map[string]service.DIDCommAction),
	}
}

// CreateRouteClient creates route client.
func (d *SDKSteps) CreateRouteClient(agentID string) error {
	// create new route client
	routeClient, err := mediator.New(d.bddContext.AgentCtx[agentID])
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

		d.setEventReceived(event)

		c := <-callbacks

		logger.Debugf("received callback: %+v", c)
		event.Continue(c)
	}
}

func (d *SDKSteps) setEventReceived(event service.DIDCommAction) {
	d.lock.Lock()
	defer d.lock.Unlock()

	d.eventsReceived[event.Message.ID()] = event
}

// GetEventReceived blocks until a routing event for the given message ID is found or until the timeout is reached.
func (d *SDKSteps) GetEventReceived(msgID string, timeout time.Duration) (*service.DIDCommAction, error) {
	deadline := time.Now().Add(timeout)
	found := false

	var event service.DIDCommAction

	for !found && time.Now().Before(deadline) {
		d.lock.Lock()

		event, found = d.eventsReceived[msgID]

		d.lock.Unlock()

		if !found {
			time.Sleep(sleepDuration)
		}
	}

	if !found {
		return nil, fmt.Errorf("timeout while waiting for reception of event for msg with id=%s", msgID)
	}

	return &event, nil
}

// GetRoutingConfig blocks until it fetches the agent's routing configuration or until the timeout is reached.
func (d *SDKSteps) GetRoutingConfig(agent, connectionID string, timeout time.Duration) (*routesvc.Config, error) {
	client, found := d.bddContext.RouteClients[agent]
	if !found {
		return nil, fmt.Errorf("%s does not have a registered routing client", agent)
	}

	var (
		config *routesvc.Config
		err    error
	)

	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		config, err = client.GetConfig(connectionID)
		if err != nil {
			time.Sleep(sleepDuration)

			continue
		}

		return config, nil
	}

	return nil, err
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

// RegisterRoute registers the router for the agent.
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
	connections, err := d.bddContext.RouteClients[agentID].GetConnections()
	if err != nil {
		return fmt.Errorf("fetch router connection id : %w", err)
	}

	if len(connections) == 0 {
		return errors.New("router does not have any connections")
	}

	for _, conn := range connections {
		if conn == d.bddContext.Args[varName] {
			return nil
		}
	}

	return fmt.Errorf("router connection id does not exist: routerConnID=%s", d.bddContext.Args[varName])
}

// SetContext is called before every scenario is run with a fresh new context.
func (d *SDKSteps) SetContext(ctx *context.BDDContext) {
	d.bddContext = ctx
}

// RegisterSteps registers router steps.
func (d *SDKSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^"([^"]*)" creates a route exchange client$`, d.CreateRouteClient)
	s.Step(`^"([^"]*)" sets "([^"]*)" as the router and "([^"]*)" approves$`, d.RegisterRoute)
	s.Step(`^"([^"]*)" verifies that the router connection id is set to "([^"]*)"$`, d.VerifyConnection)
}
