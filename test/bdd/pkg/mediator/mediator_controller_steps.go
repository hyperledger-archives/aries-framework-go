/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mediator

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/cucumber/godog"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/util"
)

var logger = log.New("aries-framework/tests/messaging")

type registerRouteReq struct {
	ConnectionID string `json:"connectionID"`
}

// RESTSteps is steps for route using REST APIs.
type RESTSteps struct {
	bddContext           *context.BDDContext
	newKeyType           kms.KeyType
	newKeyAgreementType  kms.KeyType
	newMediaTypeProfiles []string
	agent                string
	agentRouter          string
	transports           string
	agentControllerURL   string
	routerControllerURL  string
	routerConnID         string
	secondRouterConnID   string
}

// NewRouteRESTSteps return steps for route using REST APIs.
func NewRouteRESTSteps() *RESTSteps {
	return &RESTSteps{}
}

func (d *RESTSteps) scenario(keyType, keyAgreementType, mediaTypeProfile, agent, agentRouter, transports,
	agentControllerURL, routerControllerURL, routerConnID, secondRouterConnID string) error {
	d.newKeyType = kms.KeyType(keyType)
	d.newKeyAgreementType = kms.KeyType(keyAgreementType)
	d.newMediaTypeProfiles = []string{mediaTypeProfile}
	d.agent = agent
	d.agentRouter = agentRouter
	d.transports = transports
	d.agentControllerURL = agentControllerURL
	d.routerControllerURL = routerControllerURL
	d.routerConnID = routerConnID
	d.secondRouterConnID = secondRouterConnID

	return nil
}

// RegisterRoute registers the router for the agent.
func (d *RESTSteps) RegisterRoute(agentID, varNames string) error {
	destination, ok := d.bddContext.GetControllerURL(agentID)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", agentID)
	}

	for _, varName := range strings.Split(varNames, ",") {
		err := postToURL(destination+"/mediator/register", registerRouteReq{ConnectionID: d.bddContext.Args[varName]})
		if err != nil {
			return fmt.Errorf("router registration: %w", err)
		}
	}

	return nil
}

// RegisterRouteForTwoConnections registers the router for the agent using conn1 and conn2 connections.
func (d *RESTSteps) RegisterRouteForTwoConnections(agentID, conn1, conn2 string) error {
	return d.RegisterRoute(agentID, fmt.Sprintf("%s,%s", conn1, conn2))
}

func postToURL(url string, payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	return util.SendHTTP(http.MethodPost, url, body, nil)
}

// UnregisterRoute unregisters the router.
func (d *RESTSteps) UnregisterRoute(agentID, varNames string) error {
	destination, ok := d.bddContext.GetControllerURL(agentID)
	if !ok {
		return fmt.Errorf(" unable to find controller URL registered for agent [%s]", agentID)
	}

	for _, varName := range strings.Split(varNames, ",") {
		body, err := json.Marshal(registerRouteReq{ConnectionID: d.bddContext.Args[varName]})
		if err != nil {
			return err
		}

		err = util.SendHTTP(http.MethodDelete, destination+"/mediator/unregister", body, nil)
		if err != nil {
			// ignore error if router is not registered (code=5003)
			if strings.Contains(err.Error(), "\"code\":5003") {
				logger.Infof("ignore unregister - router not registered")

				return nil
			}

			return fmt.Errorf("router unregistration : %w", err)
		}
	}

	return nil
}

// UnregisterRouteForTwoConnections unregisters the router for agentID using conn1 and conn2 connections.
func (d *RESTSteps) UnregisterRouteForTwoConnections(agentID, conn1, conn2 string) error {
	return d.UnregisterRoute(agentID, fmt.Sprintf("%s,%s", conn1, conn2))
}

// VerifyConnections verifies the router connections id has been set to the provided connections id.
func (d *RESTSteps) VerifyConnections(agentID, varNames string) error {
	destination, ok := d.bddContext.GetControllerURL(agentID)
	if !ok {
		return fmt.Errorf(" unable to find controller URL registered for agent [%s]", agentID)
	}

	resp := &mediator.ConnectionsResponse{}

	err := util.SendHTTP(http.MethodGet, destination+"/mediator/connections", nil, resp)
	if err != nil {
		return fmt.Errorf("fetch route connection : %w", err)
	}

	set := map[string]struct{}{}
	for _, conn := range resp.Connections {
		set[conn] = struct{}{}
	}

	for _, name := range strings.Split(varNames, ",") {
		if _, ok := set[d.bddContext.Args[name]]; !ok {
			return fmt.Errorf("router connection id does not exist: routerConnID=%s", d.bddContext.Args[name])
		}
	}

	return nil
}

// VerifyConnectionsForTwoConnections verifies the router connections id has been set to conn1 and conn2 connection IDs.
func (d *RESTSteps) VerifyConnectionsForTwoConnections(agentID, conn1, conn2 string) error {
	return d.VerifyConnections(agentID, fmt.Sprintf("%s,%s", conn1, conn2))
}

// SetContext is called before every scenario is run with a fresh new context.
func (d *RESTSteps) SetContext(ctx *context.BDDContext) {
	d.bddContext = ctx
}

// RegisterSteps registers router steps.
func (d *RESTSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^"([^"]*)" sets connection "([^"]*)" as the router$`, d.RegisterRoute)
	s.Step(`^""([^"]*)"" sets connection ""([^"]*)"" and ""([^"]*)"" as the router$`,
		d.RegisterRouteForTwoConnections)
	s.Step(`^"([^"]*)" unregisters the router with connection "([^"]*)"$`, d.UnregisterRoute)
	s.Step(`^""([^"]*)"" unregisters the router with connection ""([^"]*)"" and ""([^"]*)""$`,
		d.UnregisterRouteForTwoConnections)
	s.Step(`^"([^"]*)" verifies that the router connection is set to "([^"]*)"$`, d.VerifyConnections)
	s.Step(`^""([^"]*)"" verifies that the router connection is set to ""([^"]*)"" and ""([^"]*)""$`,
		d.VerifyConnectionsForTwoConnections)
	s.Step(`^options ""([^"]*)"" ""([^"]*)"" ""([^"]*)"" ""([^"]*)"" ""([^"]*)"" ""([^"]*)"" ""([^"]*)"" ""([^"]*)""`+
		` ""([^"]*)"" ""([^"]*)"" ""([^"]*)"" ""([^"]*)"" ""([^"]*)"" ""([^"]*)"" ""([^"]*)"" ""([^"]*)"" ""([^"]*)""$`,
		d.scenario)
}
