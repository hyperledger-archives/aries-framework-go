/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/DATA-DOG/godog"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/operation/didexchange/models"
)

const (
	operationID           = "/connections"
	createInvitationPath  = operationID + "/create-invitation"
	receiveInvtiationPath = operationID + "/receive-invitation"
	acceptInvitationPath  = operationID + "/{id}/accept-invitation"
	connections           = operationID
	connectionsByID       = operationID + "/{id}"
	acceptExchangeRequest = operationID + "/{id}/accept-request"
	removeConnection      = operationID + "/{id}/remove"

	AliceAgentHost       = "${ALICE_AGENT_HOST}"
	AliceAgentPort       = "${ALICE_AGENT_PORT}"
	AliceAgentController = "${ALICE_CONTROLLER_URL}"
	AliceAgentWebhook    = "${ALICE_WEBHOOK_URL}"
	BobAgentHost         = "${BOB_AGENT_HOST}"
	BobAgentPort         = "${BOB_AGENT_PORT}"
	BobAgentController   = "${BOB_CONTROLLER_URL}"
	BobAgentWebhook      = "${BOB_WEBHOOK_URL}"
)

// AgentWithControllerSteps
// TODO all steps in this package needs to be placed in different packages instead of sharing same package [Issue #584]
type AgentWithControllerSteps struct {
	bddContext     *Context
	controllerURLs map[string]string
	webhookURLs    map[string]string
	invitations    map[string]*didexchange.Invitation
}

// NewAgentControllerSteps creates steps for agent with controller
func NewAgentControllerSteps(context *Context) *AgentWithControllerSteps {
	return &AgentWithControllerSteps{bddContext: context,
		controllerURLs: make(map[string]string),
		webhookURLs:    make(map[string]string),
		invitations:    make(map[string]*didexchange.Invitation)}
}

// RegisterSteps registers agent steps
func (a *AgentWithControllerSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^"([^"]*)" agent is running on "([^"]*)" port "([^"]*)" with controller "([^"]*)" and webhook "([^"]*)"$`, a.checkAgentIsRunning)
	s.Step(`^"([^"]*)" creates invitation through controller$`, a.createInvitation)
	s.Step(`^"([^"]*)" receives invitation from "([^"]*)" through controller$`, a.receiveInvitation)
	s.Step(`^"([^"]*)" waits for post state event "([^"]*)" to webhook`, a.waitForPostEvent)
	s.Step(`^"([^"]*)" retrieves connection record through controller and validates that connection state is "([^"]*)"$`, a.validateConnection)
}

func (a *AgentWithControllerSteps) checkAgentIsRunning(agentID, inboundHost, inboundPortEnv, controllerURLEnv, webhookURLEnv string) error {
	// read actual values form environment variables
	controllerURL := a.bddContext.Args[controllerURLEnv]
	inboundPort := a.bddContext.Args[inboundPortEnv]
	webhookURL := a.bddContext.Args[webhookURLEnv]

	// verify controller
	err := a.healthCheck(controllerURL)
	if err != nil {
		logger.Debugf("Unable to reach controller '%s' for agent '%s', cause : %s", controllerURL, agentID, err)
		return err
	}
	a.controllerURLs[agentID] = controllerURL
	logger.Debugf("Agent '%s' running controller '%s'", agentID, controllerURL)

	// verify inbound
	err = a.healthCheck(fmt.Sprintf("http://%s:%s", inboundHost, inboundPort))
	if err != nil {
		logger.Debugf("Unable to reach inbound '%s' for agent '%s', cause : %s", controllerURL, agentID, err)
		return err
	}

	logger.Debugf("Agent '%s' running inbound on '%s' and port '%s'", agentID, inboundHost, inboundPort)

	// TODO health check webhook URL (Issue #542)
	a.webhookURLs[agentID] = webhookURL

	return nil
}

func (a *AgentWithControllerSteps) createInvitation(inviterAgentID string) error {
	destination, ok := a.controllerURLs[inviterAgentID]
	if !ok {
		return fmt.Errorf(" unable to find controller URL registered for agent [%s]", inviterAgentID)
	}

	// call controller
	var result models.CreateInvitationResponse
	err := sendHTTP(http.MethodPost, destination+createInvitationPath, nil, &result)
	if err != nil {
		logger.Errorf("Failed to create invitation, cause : %s", err)
		return err
	}

	// validate payload
	if result.Payload == nil {
		return fmt.Errorf("failed to get valid payload from create invitation for agent [%s]", inviterAgentID)
	}

	// save invitation for later use
	if strings.Contains(result.Payload.ServiceEndpoint, "0.0.0.0") {
		//TODO need a task to fix using local address in service endpoint of invitation object [issue #572]
		result.Payload.ServiceEndpoint = strings.Replace(result.Payload.ServiceEndpoint, "0.0.0.0", a.bddContext.Args[AliceAgentHost], 1)
		logger.Debugf("service endpoint host in invitation changed to %s", result.Payload.ServiceEndpoint)
	}
	a.invitations[inviterAgentID] = result.Payload

	return nil
}

func (a *AgentWithControllerSteps) receiveInvitation(inviteeAgentID, inviterAgentID string) error {
	destination, ok := a.controllerURLs[inviteeAgentID]
	if !ok {
		return fmt.Errorf(" unable to find controller URL registered for agent [%s]", inviterAgentID)
	}

	invitation, ok := a.invitations[inviterAgentID]
	if !ok {
		return fmt.Errorf(" unable to find invitation for inviter [%s]", inviterAgentID)
	}

	message, err := json.Marshal(&models.ReceiveInvitationRequest{Params: invitation})
	if err != nil {
		logger.Errorf("Failed to create receiver invitation message, cause : %s", err)
		return err
	}

	logger.Debugf("mesage::-->>", string(message))
	// call controller
	var result models.ReceiveInvitationResponse
	err = sendHTTP(http.MethodPost, destination+receiveInvtiationPath, message, &result)
	if err != nil {
		logger.Errorf("Failed to perform receive invitation, cause : %s", err)
		return err
	}

	// validate payload
	if result.ConnectionID == "" {
		return fmt.Errorf("failed to get valid payload from receive invitation call for agent [%s]", inviteeAgentID)
	}

	return nil
}

func (a *AgentWithControllerSteps) waitForPostEvent(agentID, statesValue string) error {
	// TODO integrate with webhooks here validate post event (Issue #545)
	return nil
}

func (a *AgentWithControllerSteps) validateConnection(agentID, stateValue string) error {
	// TODO use connection ID from `waitForPostEvent` to query connection (Issue #545)
	return nil
}

func (a *AgentWithControllerSteps) healthCheck(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	closeResponse(resp.Body)
	return nil
}

func sendHTTP(method, destination string, message []byte, result interface{}) error {
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

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to get response from '%s', unexpected status code [%d]", destination, resp.StatusCode)
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read response from '%s', cause :%s", destination, err)
	}

	logger.Debugf(" Got response from '%s' [method: %s], response payload: %s", destination, method, string(data))

	return json.Unmarshal(data, result)
}
