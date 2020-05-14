/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mediator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/cucumber/godog"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/mediator"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
)

var logger = log.New("aries-framework/tests/messaging")

type registerRouteReq struct {
	ConnectionID string `json:"connectionID"`
}

// RESTSteps is steps for route using REST APIs
type RESTSteps struct {
	bddContext *context.BDDContext
}

// NewRouteRESTSteps return steps for route using REST APIs
func NewRouteRESTSteps() *RESTSteps {
	return &RESTSteps{}
}

// RegisterRoute registers the router for the agent.
func (d *RESTSteps) RegisterRoute(agentID, varName string) error {
	connectionID := d.bddContext.Args[varName]

	destination, ok := d.bddContext.GetControllerURL(agentID)
	if !ok {
		return fmt.Errorf(" unable to find controller URL registered for agent [%s]", agentID)
	}

	err := sendHTTP(http.MethodPost, destination+"/mediator/register", registerRouteReq{ConnectionID: connectionID}, nil)
	if err != nil {
		return fmt.Errorf("router registration : %w", err)
	}

	return nil
}

// UnregisterRoute unregisters the router.
func (d *RESTSteps) UnregisterRoute(agentID string) error {
	destination, ok := d.bddContext.GetControllerURL(agentID)
	if !ok {
		return fmt.Errorf(" unable to find controller URL registered for agent [%s]", agentID)
	}

	err := sendHTTP(http.MethodDelete, destination+"/mediator/unregister", nil, nil)
	if err != nil {
		// ignore error if router is not registered (code=5003)
		if strings.Contains(err.Error(), "\"code\":5003") {
			logger.Infof("ignore unregister - router not registered")

			return nil
		}

		return fmt.Errorf("router unregistration : %w", err)
	}

	return nil
}

// VerifyConnection verifies the router connection id has been set to the provided connection id.
func (d *RESTSteps) VerifyConnection(agentID, varName string) error {
	destination, ok := d.bddContext.GetControllerURL(agentID)
	if !ok {
		return fmt.Errorf(" unable to find controller URL registered for agent [%s]", agentID)
	}

	resp := &mediator.RegisterRoute{}

	err := sendHTTP(http.MethodGet, destination+"/mediator/connection", nil, resp)
	if err != nil {
		return fmt.Errorf("fetch route connection : %w", err)
	}

	if resp.ConnectionID != d.bddContext.Args[varName] {
		return fmt.Errorf("router connection id does not match : routerConnID=%s newConnID=%s",
			resp.ConnectionID, d.bddContext.Args[varName])
	}

	return nil
}

// SetContext is called before every scenario is run with a fresh new context
func (d *RESTSteps) SetContext(ctx *context.BDDContext) {
	d.bddContext = ctx
}

// RegisterSteps registers router steps
func (d *RESTSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^"([^"]*)" sets connection "([^"]*)" as the router$`, d.RegisterRoute)
	s.Step(`^"([^"]*)" unregisters the router$`, d.UnregisterRoute)
	s.Step(`^"([^"]*)" verifies that the router connection is set to "([^"]*)"$`, d.VerifyConnection)
}

func sendHTTP(method, destination string, reqMsg, respMsg interface{}) error {
	message, err := json.Marshal(reqMsg)
	if err != nil {
		return fmt.Errorf("failed to prepare params : %w", err)
	}

	// create request
	req, err := http.NewRequest(method, destination, bytes.NewBuffer(message))
	if err != nil {
		return fmt.Errorf("failed to create new http '%s' request for '%s', cause: %s", method, destination, err)
	}

	// set headers
	req.Header.Set("Content-Type", "application/json")

	// send http request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to get response from '%s', cause :%s", destination, err)
	}

	defer closeResponse(resp.Body)

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read response from '%s', cause :%s", destination, err)
	}

	logger.Debugf("Got response from '%s' [method: %s], response payload: %s", destination, method, string(data))

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to get successful response from '%s', unexpected status code [%d], "+
			"and message [%s]", destination, resp.StatusCode, string(data))
	}

	if respMsg == nil {
		return nil
	}

	return json.Unmarshal(data, respMsg)
}

func closeResponse(c io.Closer) {
	err := c.Close()
	if err != nil {
		logger.Errorf("Failed to close response body : %s", err)
	}
}
