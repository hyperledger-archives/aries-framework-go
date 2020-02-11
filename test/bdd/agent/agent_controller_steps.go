/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package agent

import (
	goctx "context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/cucumber/godog"
	"nhooyr.io/websocket"

	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
)

// ControllerSteps contains steps for controller based agent
type ControllerSteps struct {
	bddContext *context.BDDContext
}

// NewControllerSteps creates steps for agent with controller
func NewControllerSteps(ctx *context.BDDContext) *ControllerSteps {
	return &ControllerSteps{
		bddContext: ctx,
	}
}

// RegisterSteps registers agent steps
func (a *ControllerSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^"([^"]*)" agent is running on "([^"]*)" port "([^"]*)" with controller "([^"]*)" and webhook "([^"]*)"$`,
		a.checkAgentIsRunningWithHTTPInbound)
	s.Step(`^"([^"]*)" agent is running on "([^"]*)" port "([^"]*)" with controller "([^"]*)" and webhook "([^"]*)" `+
		`with http-binding did resolver url "([^"]*)" which accepts did method "([^"]*)"$`,
		a.checkAgentWithHTTPResolverIsRunning)
	s.Step(`^"([^"]*)" agent is running with controller "([^"]*)" and webhook "([^"]*)" and "([^"]*)" `+
		`as the transport return route option$`, a.checkEdgeAgent)
	s.Step(`^"([^"]*)" agent is running on "([^"]*)" with controller "([^"]*)" `+
		`and webhook "([^"]*)"$`, a.checkAgentWithMultipleInbound)
}

func (a *ControllerSteps) checkAgentWithHTTPResolverIsRunning(
	agentID, inboundHost, inboundPort, controllerURL, webhookURL, resolverURL, didMethod string) error {
	httpBindingURL := a.bddContext.Args[resolverURL]

	err := a.healthCheck(httpBindingURL)
	if err != nil {
		logger.Debugf("Unable to reach http-binding '%s' for agent '%s', cause : %s", httpBindingURL, agentID, err)
		return err
	}

	logger.Debugf("HTTP-Binding for DID method '%s' running on '%s' for agent '%s'", didMethod, httpBindingURL, agentID)

	return a.checkAgentIsRunningWithHTTPInbound(agentID, inboundHost, inboundPort, controllerURL, webhookURL)
}

func (a *ControllerSteps) checkEdgeAgent(agentID, controllerURL, webhookURL string) error {
	return a.checkAgentIsRunning(agentID, controllerURL, webhookURL)
}

func (a *ControllerSteps) checkAgentWithMultipleInbound(agentID, inboundURL, controllerURL, webhookURL string) error {
	if err := a.checkAgentIsRunning(agentID, controllerURL, webhookURL); err != nil {
		return err
	}

	urls := strings.Split(inboundURL, ",")

	for _, url := range urls {
		// verify inbound
		if err := a.healthCheck(url); err != nil {
			logger.Debugf("Unable to reach inbound '%s' for agent '%s', cause : %s", controllerURL, agentID, err)
			return err
		}

		logger.Debugf("Agent '%s' running inbound on '%s'", agentID, url)
	}

	return nil
}

func (a *ControllerSteps) checkAgentIsRunning(agentID, controllerURL, webhookURL string) error {
	// verify controller
	err := a.healthCheck(controllerURL)
	if err != nil {
		logger.Debugf("Unable to reach controller '%s' for agent '%s', cause : %s", controllerURL, agentID, err)
		return err
	}

	logger.Debugf("Agent '%s' running controller '%s'", agentID, controllerURL)

	a.bddContext.RegisterControllerURL(agentID, controllerURL)

	// verify webhook
	err = a.healthCheck(webhookURL)
	if err != nil {
		logger.Debugf("Unable to reach webhook '%s' for agent '%s', cause : %s", webhookURL, agentID, err)
		return err
	}

	logger.Debugf("Webhook for agent '%s' is running on '%s''", agentID, webhookURL)

	a.bddContext.RegisterWebhookURL(agentID, webhookURL)

	return nil
}

func (a *ControllerSteps) checkAgentIsRunningWithHTTPInbound(agentID, inboundHost,
	inboundPort, controllerURL, webhookURL string) error {
	if err := a.checkAgentIsRunning(agentID, controllerURL, webhookURL); err != nil {
		return err
	}

	// verify inbound
	if err := a.healthCheck(fmt.Sprintf("http://%s:%s", inboundHost, inboundPort)); err != nil {
		logger.Debugf("Unable to reach inbound '%s' for agent '%s', cause : %s", controllerURL, agentID, err)
		return err
	}

	logger.Debugf("Agent '%s' running inbound on '%s' and port '%s'", agentID, inboundHost, inboundPort)

	return nil
}

func (a *ControllerSteps) healthCheck(url string) error {
	if strings.HasPrefix(url, "http") {
		resp, err := http.Get(url) //nolint: gosec
		if err != nil {
			return err
		}

		err = resp.Body.Close()
		if err != nil {
			logger.Errorf("Failed to close response body : %s", err)
		}

		return nil
	} else if strings.HasPrefix(url, "ws") {
		_, resp, err := websocket.Dial(goctx.Background(), url, nil)
		if err != nil {
			return err
		}

		if err := resp.Body.Close(); err != nil {
			return err
		}

		return nil
	}

	return errors.New("url scheme is not supported for url = " + url)
}
