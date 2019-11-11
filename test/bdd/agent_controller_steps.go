/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd

import (
	"fmt"
	"net/http"

	"github.com/DATA-DOG/godog"

	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
)

// AgentWithControllerSteps contains steps for controller based agent
type AgentWithControllerSteps struct {
	bddContext *context.BDDContext
}

// NewAgentControllerSteps creates steps for agent with controller
func NewAgentControllerSteps(ctx *context.BDDContext) *AgentWithControllerSteps {
	return &AgentWithControllerSteps{
		bddContext: ctx,
	}
}

// RegisterSteps registers agent steps
func (a *AgentWithControllerSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^"([^"]*)" agent is running on "([^"]*)" port "([^"]*)" with controller "([^"]*)" and webhook "([^"]*)"$`,
		a.checkAgentIsRunning)
}

func (a *AgentWithControllerSteps) checkAgentIsRunning(
	agentID, inboundHost, inboundPort, controllerURL, webhookURL string) error {
	// verify controller
	err := a.healthCheck(controllerURL)
	if err != nil {
		logger.Debugf("Unable to reach controller '%s' for agent '%s', cause : %s", controllerURL, agentID, err)
		return err
	}

	logger.Debugf("Agent '%s' running controller '%s'", agentID, controllerURL)

	a.bddContext.RegisterControllerURL(agentID, controllerURL)

	// verify inbound
	err = a.healthCheck(fmt.Sprintf("http://%s:%s", inboundHost, inboundPort))
	if err != nil {
		logger.Debugf("Unable to reach inbound '%s' for agent '%s', cause : %s", controllerURL, agentID, err)
		return err
	}

	logger.Debugf("Agent '%s' running inbound on '%s' and port '%s'", agentID, inboundHost, inboundPort)

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

func (a *AgentWithControllerSteps) healthCheck(url string) error {
	resp, err := http.Get(url) //nolint: gosec
	if err != nil {
		return err
	}

	err = resp.Body.Close()
	if err != nil {
		logger.Errorf("Failed to close response body : %s", err)
	}

	return nil
}
