/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/DATA-DOG/godog"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	didexchrsapi "github.com/hyperledger/aries-framework-go/pkg/restapi/operation/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/operation/didexchange/models"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
)

const (
	operationID           = "/connections"
	createInvitationPath  = operationID + "/create-invitation"
	receiveInvtiationPath = operationID + "/receive-invitation"
	connectionsByID       = operationID + "/{id}"
	checkForTopics        = "/checktopics"

	// retry options to pull topics from webhook
	// pullTopicsWaitInMilliSec is time in milliseconds to wait before retry
	pullTopicsWaitInMilliSec = 200
	// pullTopicsAttemptsBeforeFail total number of retries where
	// total time shouldn't exceed 5 seconds
	pullTopicsAttemptsBeforeFail = 5000 / pullTopicsWaitInMilliSec
)

var logger = log.New("aries-framework/didexchange-tests")

// ControllerSteps is steps for didexchange with controller
type ControllerSteps struct {
	bddContext    *context.BDDContext
	invitations   map[string]*didexchange.Invitation
	connectionIDs map[string]string
}

// NewDIDExchangeControllerSteps creates steps for didexchange with controller
func NewDIDExchangeControllerSteps(ctx *context.BDDContext) *ControllerSteps {
	return &ControllerSteps{
		bddContext:    ctx,
		invitations:   make(map[string]*didexchange.Invitation),
		connectionIDs: make(map[string]string),
	}
}

// RegisterSteps registers agent steps
func (a *ControllerSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^"([^"]*)" creates invitation through controller with label "([^"]*)"$`, a.createInvitation)
	s.Step(`^"([^"]*)" receives invitation from "([^"]*)" through controller$`, a.receiveInvitation)
	s.Step(`^"([^"]*)" approves exchange invitation`, a.approveInvitation)
	s.Step(`^"([^"]*)" approves exchange request`, a.approveRequest)
	s.Step(`^"([^"]*)" waits for post state event "([^"]*)" to webhook`, a.waitForPostEvent)
	s.Step(`^"([^"]*)" retrieves connection record through controller and validates that connection state is "([^"]*)"$`,
		a.validateConnection)
}

func (a *ControllerSteps) pullWebhookEvents(agentID, state string) (string, error) {
	webhookURL, ok := a.bddContext.GetWebhookURL(agentID)
	if !ok {
		return "", fmt.Errorf("unable to find webhook URL for agent [%s]", agentID)
	}

	// try to pull recently pushed topics from webhook
	for i := 0; i < pullTopicsAttemptsBeforeFail; i++ {
		var connectionMsg didexchrsapi.ConnectionMsg

		err := sendHTTP(http.MethodGet, webhookURL+checkForTopics, nil, &connectionMsg)
		if err != nil {
			return "", fmt.Errorf("failed pull topics from webhook, cause : %s", err)
		}

		if strings.EqualFold(state, connectionMsg.State) {
			return connectionMsg.ConnectionID, nil
		}

		time.Sleep(pullTopicsWaitInMilliSec * time.Millisecond)
	}

	return "", fmt.Errorf("exhausted all [%d] attempts to pull topics from webhook", pullTopicsAttemptsBeforeFail)
}

func (a *ControllerSteps) createInvitation(inviterAgentID, label string) error {
	destination, ok := a.bddContext.GetControllerURL(inviterAgentID)
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

func (a *ControllerSteps) receiveInvitation(inviteeAgentID, inviterAgentID string) error {
	destination, ok := a.bddContext.GetControllerURL(inviteeAgentID)
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

	// invitee connectionID
	a.connectionIDs[inviteeAgentID] = result.ConnectionID

	return nil
}

func (a *ControllerSteps) approveInvitation(agentID string) error {
	connectionID, err := a.pullWebhookEvents(agentID, "invited")
	if err != nil {
		return fmt.Errorf("aprove exchange invitation : %w", err)
	}

	// invitee connectionID
	a.connectionIDs[agentID] = connectionID

	controllerURL, ok := a.bddContext.GetControllerURL(agentID)
	if !ok {
		return fmt.Errorf("unable to find contoller URL for agent [%s]", controllerURL)
	}

	var response models.AcceptInvitationResponse

	err = sendHTTP(http.MethodPost, controllerURL+"/connections/"+connectionID+"/accept-invitation",
		nil, &response)
	if err != nil {
		logger.Errorf("Failed to perform accept invitation, cause : %s", err)
		return fmt.Errorf("failed to perform accept inviation : %w", err)
	}

	if response.ConnectionID == "" {
		logger.Errorf("Failed to perform accept invitation, cause : %s", err)
		return fmt.Errorf("failed to perform accept inviation, invalid response")
	}

	return nil
}

func (a *ControllerSteps) approveRequest(agentID string) error {
	connectionID, err := a.pullWebhookEvents(agentID, "requested")
	if err != nil {
		return fmt.Errorf("failed to get connection ID from webhook, %w", err)
	}

	// inviter connectionID
	a.connectionIDs[agentID] = connectionID

	controllerURL, ok := a.bddContext.GetControllerURL(agentID)
	if !ok {
		return fmt.Errorf("unable to find contoller URL for agent [%s]", controllerURL)
	}

	var response models.AcceptExchangeResult

	err = sendHTTP(http.MethodPost, controllerURL+"/connections/"+connectionID+"/accept-request",
		nil, &response)
	if err != nil {
		logger.Errorf("Failed to perform approve request, cause : %s", err)
		return fmt.Errorf("failed to perform approve request : %w", err)
	}

	if response.Result == nil || response.Result.ConnectionID == "" {
		logger.Errorf("Failed to perform approve request, cause : %s", err)
		return fmt.Errorf("failed to perform approve request, invalid response")
	}

	return nil
}

func (a *ControllerSteps) waitForPostEvent(agentID, statesValue string) error {
	_, err := a.pullWebhookEvents(agentID, statesValue)
	if err != nil {
		return fmt.Errorf("failed to get notification from webhook, %w", err)
	}

	return nil
}

func (a *ControllerSteps) validateConnection(agentID, stateValue string) error {
	connectionID, ok := a.connectionIDs[agentID]
	if !ok {
		return fmt.Errorf(" unable to find valid connection ID for agent [%s]", connectionID)
	}

	destination, ok := a.bddContext.GetControllerURL(agentID)
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
		return fmt.Errorf("expected state[%s] for agent[%s], but got[%s]", stateValue, agentID, response.Result.State)
	}

	// Also make sure new connection is available in list of connections for given agent
	return a.verifyConnectionList(agentID, stateValue, connectionID)
}

func (a *ControllerSteps) verifyConnectionList(agentID, queryState, verifyID string) error {
	destination, ok := a.bddContext.GetControllerURL(agentID)
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
		return fmt.Errorf("no connections found with state '%s' and connection ID '%s' in connections list",
			queryState, verifyID)
	}

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

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read response from '%s', cause :%s", destination, err)
	}

	logger.Debugf(" Got response from '%s' [method: %s], response payload: %s", destination, method, string(data))

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to get successful response from '%s', unexpected status code [%d], "+
			"and message [%s]", destination, resp.StatusCode, string(data))
	}

	return json.Unmarshal(data, result)
}

func closeResponse(c io.Closer) {
	err := c.Close()
	if err != nil {
		logger.Errorf("Failed to close response body : %s", err)
	}
}
