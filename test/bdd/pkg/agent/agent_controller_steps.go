/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package agent

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"nhooyr.io/websocket"

	bddcontext "github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/util"
)

const timeoutWebSocketDial = 5 * time.Second

// ControllerSteps contains steps for controller based agent.
type ControllerSteps struct {
	bddContext *bddcontext.BDDContext
}

// NewControllerSteps creates steps for agent with controller.
func NewControllerSteps() *ControllerSteps {
	return &ControllerSteps{}
}

// SetContext is called before every scenario is run with a fresh new context.
func (a *ControllerSteps) SetContext(ctx *bddcontext.BDDContext) {
	a.bddContext = ctx
}

// RegisterSteps registers agent steps.
func (a *ControllerSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^"([^"]*)" agent is running on "([^"]*)" port "([^"]*)" with controller "([^"]*)"$`,
		a.checkAgentIsRunningWithHTTPInbound)
	s.Step(`^"([^"]*)" agent is running on "([^"]*)" port "([^"]*)" with controller "([^"]*)" `+
		`with http-binding did resolver url "([^"]*)" which accepts did method "([^"]*)"$`,
		a.checkAgentWithHTTPResolverIsRunning)
	s.Step(`^"([^"]*)" agent is running with controller "([^"]*)" and "([^"]*)" `+
		`as the transport return route option$`, a.checkEdgeAgent)
	s.Step(`^"([^"]*)" agent is running on "([^"]*)" with controller "([^"]*)"$`, a.checkAgentWithMultipleInbound)
	s.Step(`^"([^"]*)" agent is running on "([^"]*)" port "([^"]*)" with webhook "([^"]*)" and controller "([^"]*)"$`,
		a.checkAgentIsRunningWithHTTPInboundAndWebhook)
}

func (a *ControllerSteps) checkAgentWithHTTPResolverIsRunning(
	agentID, inboundHost, inboundPort, controllerURL, resolverURL, didMethod string) error {
	httpBindingURL := a.bddContext.Args[resolverURL]

	err := a.healthCheck(httpBindingURL)
	if err != nil {
		logger.Debugf("Unable to reach http-binding '%s' for agent '%s', cause : %s", httpBindingURL, agentID, err)
		return err
	}

	logger.Debugf("HTTP-Binding for DID method '%s' running on '%s' for agent '%s'", didMethod, httpBindingURL, agentID)

	return a.checkAgentIsRunningWithHTTPInbound(agentID, inboundHost, inboundPort, controllerURL)
}

func (a *ControllerSteps) checkEdgeAgent(agentID, controllerURL string) error {
	return a.checkAgentIsRunning(agentID, controllerURL, "")
}

func (a *ControllerSteps) checkAgentWithMultipleInbound(agentID, inboundURL, controllerURL string) error {
	if err := a.checkAgentIsRunning(agentID, controllerURL, ""); err != nil {
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

	// create and register websocket connection for notifications
	u, err := url.Parse(controllerURL)
	if err != nil {
		return fmt.Errorf("invalid controller URL [%s]", controllerURL)
	}

	wsURL := fmt.Sprintf("wss://%s%s/ws", u.Host, u.Path)

	ctx, cancel := context.WithTimeout(context.Background(), timeoutWebSocketDial)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPClient: util.DefaultClient,
	})
	if err != nil {
		return fmt.Errorf("failed to dial connection from '%s' : %w", wsURL, err)
	}

	a.bddContext.RegisterWebSocketConn(agentID, conn)

	if webhookURL != "" {
		// verify webhook
		err = a.healthCheck(webhookURL)
		if err != nil {
			logger.Debugf("Unable to reach webhook '%s' for agent '%s', cause : %s", webhookURL, agentID, err)
			return err
		}

		logger.Debugf("Webhook for agent '%s' is running on '%s''", agentID, webhookURL)

		a.bddContext.RegisterWebhookURL(agentID, webhookURL)
	}

	return nil
}

func (a *ControllerSteps) checkAgentIsRunningWithHTTPInboundAndWebhook(agentID, inboundHost,
	inboundPort, webhookURL, controllerURL string) error {
	if err := a.checkAgentIsRunning(agentID, controllerURL, webhookURL); err != nil {
		return err
	}

	// verify inbound
	if err := a.healthCheck(fmt.Sprintf("https://%s:%s", inboundHost, inboundPort)); err != nil {
		logger.Debugf("Unable to reach inbound '%s' for agent '%s', cause : %s", controllerURL, agentID, err)
		return err
	}

	logger.Debugf("Agent '%s' running inbound on '%s' and port '%s'", agentID, inboundHost, inboundPort)

	return nil
}

func (a *ControllerSteps) checkAgentIsRunningWithHTTPInbound(agentID, inboundHost,
	inboundPort, controllerURL string) error {
	return a.checkAgentIsRunningWithHTTPInboundAndWebhook(agentID, inboundHost,
		inboundPort, "", controllerURL)
}

func (a *ControllerSteps) healthCheck(endpoint string) error {
	if strings.HasPrefix(endpoint, "http") {
		resp, err := util.DefaultClient.Get(endpoint)
		if err != nil {
			return err
		}

		err = resp.Body.Close()
		if err != nil {
			logger.Errorf("Failed to close response body : %s", err)
		}

		return nil
	} else if strings.HasPrefix(endpoint, "ws") {
		_, _, err := websocket.Dial(context.Background(), endpoint, &websocket.DialOptions{
			HTTPClient: util.DefaultClient,
		})
		if err != nil {
			return err
		}

		return nil
	}

	return errors.New("url scheme is not supported for url = " + endpoint)
}
