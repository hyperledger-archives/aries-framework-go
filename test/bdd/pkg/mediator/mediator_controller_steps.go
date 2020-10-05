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
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/util"
)

var logger = log.New("aries-framework/tests/messaging")

type registerRouteReq struct {
	ConnectionID string `json:"connectionID"`
}

// RESTSteps is steps for route using REST APIs.
type RESTSteps struct {
	bddContext *context.BDDContext
}

// NewRouteRESTSteps return steps for route using REST APIs.
func NewRouteRESTSteps() *RESTSteps {
	return &RESTSteps{}
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

// SetContext is called before every scenario is run with a fresh new context.
func (d *RESTSteps) SetContext(ctx *context.BDDContext) {
	d.bddContext = ctx
}

// RegisterSteps registers router steps.
func (d *RESTSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^"([^"]*)" sets connection "([^"]*)" as the router$`, d.RegisterRoute)
	s.Step(`^"([^"]*)" unregisters the router with connection "([^"]*)"$`, d.UnregisterRoute)
	s.Step(`^"([^"]*)" verifies that the router connection is set to "([^"]*)"$`, d.VerifyConnections)
}
