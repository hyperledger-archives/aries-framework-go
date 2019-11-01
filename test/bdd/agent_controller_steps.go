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
	"time"

	"github.com/DATA-DOG/godog"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	didexchrsapi "github.com/hyperledger/aries-framework-go/pkg/restapi/operation/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/operation/didexchange/models"
)

const (
	operationID           = "/connections"
	createInvitationPath  = operationID + "/create-invitation"
	receiveInvtiationPath = operationID + "/receive-invitation"
	connectionsByID       = operationID + "/{id}"
	checkForTopics        = "/checktopics"

	// retry options to pull topics from webhook
	pullTopicsAttempts       = 10
	pullTopicsWaitInMilliSec = 50
)

// AgentWithControllerSteps
// TODO all steps in this package needs to be placed in different packages instead of sharing same package [Issue #584]
type AgentWithControllerSteps struct {
	bddContext     *Context
	controllerURLs map[string]string
	webhookURLs    map[string]string
	invitations    map[string]*didexchange.Invitation
	connectionIDs  map[string]string
}

// NewAgentControllerSteps creates steps for agent with controller
func NewAgentControllerSteps(context *Context) *AgentWithControllerSteps {
	return &AgentWithControllerSteps{
		bddContext:     context,
		controllerURLs: make(map[string]string),
		webhookURLs:    make(map[string]string),
		invitations:    make(map[string]*didexchange.Invitation),
		connectionIDs:  make(map[string]string),
	}
}

// RegisterSteps registers agent steps
func (a *AgentWithControllerSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^"([^"]*)" agent is running on "([^"]*)" port "([^"]*)" with controller "([^"]*)" and webhook "([^"]*)"$`, a.checkAgentIsRunning)
	s.Step(`^"([^"]*)" creates invitation through controller with label "([^"]*)"$`, a.createInvitation)
	s.Step(`^"([^"]*)" receives invitation from "([^"]*)" through controller$`, a.receiveInvitation)
	s.Step(`^"([^"]*)" waits for post state event "([^"]*)" to webhook`, a.waitForPostEvent)
	s.Step(`^"([^"]*)" retrieves connection record through controller and validates that connection state is "([^"]*)"$`, a.validateConnection)
}

func (a *AgentWithControllerSteps) checkAgentIsRunning(agentID, inboundHost, inboundPort, controllerURL, webhookURL string) error {
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
	err = a.healthCheck(webhookURL)
	if err != nil {
		logger.Debugf("Unable to reach webhook '%s' for agent '%s', cause : %s", webhookURL, agentID, err)
		return err
	}
	logger.Infof("Webhook for agent '%s' is running on '%s''", agentID, webhookURL)
	a.webhookURLs[agentID] = webhookURL

	return nil
}

func (a *AgentWithControllerSteps) createInvitation(inviterAgentID, label string) error {
	destination, ok := a.controllerURLs[inviterAgentID]
	if !ok {
		return fmt.Errorf(" unable to find controller URL registered for agent [%s]", inviterAgentID)
	}

	// call controller
	path := fmt.Sprintf("%s%s?alias=%s", destination, createInvitationPath, label)
	var result models.CreateInvitationResponse
	err := sendHTTP(http.MethodPost, path, nil, &result)
	if err != nil {
		logger.Errorf("Failed to create invitation, cause : %s", err)
		return err
	}

	// validate payload
	if result.Invitation == nil {
		return fmt.Errorf("failed to get valid payload from create invitation for agent [%s]", inviterAgentID)
	}

	// verify result
	if result.Invitation.Label != label {
		return fmt.Errorf("invitation label mismatch, expected[%s] but got [%s]", label, result.Invitation.Label)
	}

	// save invitation for later use
	a.invitations[inviterAgentID] = result.Invitation

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

	message, err := json.Marshal(invitation)
	if err != nil {
		logger.Errorf("Failed to create receiver invitation message, cause : %s", err)
		return err
	}

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
	webhookURL, ok := a.webhookURLs[agentID]
	if !ok {
		return fmt.Errorf("unable to find webhook URL for agent [%s]", webhookURL)
	}

	controllerURL, ok := a.controllerURLs[agentID]
	if !ok {
		return fmt.Errorf("unable to find contoller URL for agent [%s]", controllerURL)
	}

	// try to pull recently pushed topics from webhook
	var result didexchrsapi.ConnectionMsg
	for i := 0; i < pullTopicsAttempts; i++ {
		err := sendHTTP(http.MethodGet, webhookURL+checkForTopics, nil, &result)
		if err != nil {
			logger.Errorf("Failed pull topics from webhook, cause : %s", err)
			return err
		}
		// TODO https://github.com/hyperledger/aries-framework-go/issues/660 - Extract this to a BDD step
		if result.State == "null" {
			err = sendHTTP(http.MethodPost, controllerURL+"/connections/"+result.ConnectionID+"/accept-request",
				nil, &result)
			continue
		}
		if result.State == statesValue {
			break
		}
		time.Sleep(pullTopicsWaitInMilliSec * time.Millisecond)
	}

	logger.Debugf("Got topic from webhook server, %s", result)

	if result.State != statesValue {
		return fmt.Errorf("expected post event with state[%s], but got[%s]", statesValue, result.State)
	}

	if result.ConnectionID == "" {
		return fmt.Errorf("invalid connection ID found in webhook topic")
	}

	a.connectionIDs[agentID] = result.ConnectionID
	return nil
}

func (a *AgentWithControllerSteps) validateConnection(agentID, stateValue string) error {
	connectionID, ok := a.connectionIDs[agentID]
	if !ok {
		return fmt.Errorf(" unable to find valid connection ID for agent [%s]", connectionID)
	}

	destination, ok := a.controllerURLs[agentID]
	if !ok {
		return fmt.Errorf(" unable to find controller URL registered for agent [%s]", agentID)
	}

	logger.Debugf(" Getting connection by ID %s from %s", connectionID, destination)
	// call controller
	var response models.QueryConnectionResponse
	err := sendHTTP(http.MethodGet, destination+strings.Replace(connectionsByID, "{id}", connectionID, 1), nil, &response)
	if err != nil {
		logger.Errorf("Failed to perform receive invitation, cause : %s", err)
		return err
	}
	logger.Debugf("Got connection by ID, result %s", response)

	// Verify state
	if response.Result.State != stateValue {
		return fmt.Errorf("Expected state[%s] for agent[%s], but got[%s]", stateValue, agentID, response.Result.State)
	}

	// Also make sure new connection is available in list of connections for given agent
	return a.verifyConnectionList(agentID, stateValue, connectionID)
}

func (a *AgentWithControllerSteps) verifyConnectionList(agentID, queryState, verifyID string) error {
	destination, ok := a.controllerURLs[agentID]
	if !ok {
		return fmt.Errorf(" unable to find controller URL registered for agent [%s]", agentID)
	}

	logger.Debugf(" Getting connections by state %s from %s", queryState, destination)

	// call controller
	var response models.QueryConnectionsResponse
	err := sendHTTP(http.MethodGet, destination+operationID+"?state="+queryState, nil, &response)
	if err != nil {
		logger.Errorf("Failed to perform receive invitation, cause : %s", err)
		return err
	}
	logger.Debugf("Got %d connections for state `%s`", len(response.Results), queryState)

	if len(response.Results) == 0 {
		return fmt.Errorf("no connections found with state '%s' in connections list", queryState)
	}

	var found bool
	for _, connection := range response.Results {
		if connection.State == queryState && connection.ConnectionID == verifyID {
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("no connections found with state '%s' and connection ID '%s' in connections list", queryState, verifyID)
	}

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
