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

	"github.com/hyperledger/aries-framework-go/pkg/restapi/operation/common"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	didexchrsapi "github.com/hyperledger/aries-framework-go/pkg/restapi/operation/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/operation/didexchange/models"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
)

const (
	connOperationID              = "/connections"
	vdriOperationID              = "/vdri"
	createInvitationPath         = connOperationID + "/create-invitation"
	createImplicitInvitationPath = connOperationID + "/create-implicit-invitation"
	receiveInvtiationPath        = connOperationID + "/receive-invitation"
	acceptInvitationPath         = connOperationID + "/%s/accept-invitation?public=%s"
	acceptRequestPath            = connOperationID + "/%s/accept-request?public=%s"
	connectionsByID              = connOperationID + "/{id}"
	createPublicDIDPath          = vdriOperationID + "/create-public-did"
	checkForTopics               = "/checktopics"
	publicDIDCreateHeader        = `{"alg":"","kid":"","operation":"create"}`
	sideTreeURL                  = "${SIDETREE_URL}"
	timeoutWaitForDID            = 10 * time.Second

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
	publicDIDs    map[string]string
}

// NewDIDExchangeControllerSteps creates steps for didexchange with controller
func NewDIDExchangeControllerSteps(ctx *context.BDDContext) *ControllerSteps {
	return &ControllerSteps{
		bddContext:    ctx,
		invitations:   make(map[string]*didexchange.Invitation),
		connectionIDs: make(map[string]string),
		publicDIDs:    make(map[string]string),
	}
}

// RegisterSteps registers agent steps
func (a *ControllerSteps) RegisterSteps(s *godog.Suite) { //nolint dupl
	s.Step(`^"([^"]*)" creates invitation through controller with label "([^"]*)"$`, a.createInvitation)
	s.Step(`^"([^"]*)" receives invitation from "([^"]*)" through controller$`, a.receiveInvitation)
	s.Step(`^"([^"]*)" approves exchange invitation through controller`, a.approveInvitation)
	s.Step(`^"([^"]*)" approves exchange request through controller`, a.approveRequest)
	s.Step(`^"([^"]*)" waits for post state event "([^"]*)" to webhook`, a.waitForPostEvent)
	s.Step(`^"([^"]*)" retrieves connection record through controller and validates that connection state is "([^"]*)"$`,
		a.validateConnection)
	// public DID steps
	s.Step(`^"([^"]*)" creates "([^"]*)" public DID through controller`, a.createPublicDID)
	s.Step(`^"([^"]*)" creates invitation through controller using public DID and label "([^"]*)"$`,
		a.createInvitationWithDID)
	s.Step(`^"([^"]*)" approves exchange invitation with public DID through controller`,
		a.approveInvitationWithPublicDID)
	s.Step(`^"([^"]*)" approves exchange request with public DID through controller`,
		a.approveRequestWithPublicDID)
	s.Step(`^"([^"]*)" initiates connection through controller with "([^"]*)" using peer DID$`,
		a.createImplicitInvitation)
	s.Step(`^"([^"]*)" initiates connection through controller with "([^"]*)" using public DID$`,
		a.createImplicitInvitationWithDID)
	s.Step(`^"([^"]*)" has established connection with "([^"]*)" through did exchange using controller$`,
		a.performDIDExchange)
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
			logger.Debugf("Able to find webhook topic with expected state[%s] for agent[%s] and connection[%s]",
				connectionMsg.State, agentID, connectionMsg.ConnectionID)
			return connectionMsg.ConnectionID, nil
		}

		time.Sleep(pullTopicsWaitInMilliSec * time.Millisecond)
	}

	return "", fmt.Errorf("exhausted all [%d] attempts to pull topics from webhook", pullTopicsAttemptsBeforeFail)
}

func (a *ControllerSteps) createInvitation(inviterAgentID, label string) error {
	return a.performCreateInvitation(inviterAgentID, label, false)
}

func (a *ControllerSteps) createInvitationWithDID(inviterAgentID, label string) error {
	return a.performCreateInvitation(inviterAgentID, label, true)
}

func (a *ControllerSteps) createImplicitInvitation(inviteeAgentID, inviterAgentID string) error {
	return a.performCreateImplicitInvitation(inviteeAgentID, inviterAgentID, false)
}

func (a *ControllerSteps) createImplicitInvitationWithDID(inviteeAgentID, inviterAgentID string) error {
	return a.performCreateImplicitInvitation(inviteeAgentID, inviterAgentID, true)
}

func (a *ControllerSteps) performCreateInvitation(inviterAgentID, label string, useDID bool) error {
	destination, ok := a.bddContext.GetControllerURL(inviterAgentID)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]",
			inviterAgentID)
	}

	var publicDID string
	if useDID {
		publicDID, ok = a.publicDIDs[inviterAgentID]
		if !ok {
			return fmt.Errorf("unable to find public DID for agent [%s]", inviterAgentID)
		}
	}

	logger.Debugf("Creating invitation from controller for agent[%s], label[%s], did[%s]",
		inviterAgentID, publicDID, label)

	// call controller
	path := fmt.Sprintf("%s%s?alias=%s&public=%s", destination, createInvitationPath, label, publicDID)

	var result models.CreateInvitationResponse

	err := sendHTTP(http.MethodPost, path, nil, &result)
	if err != nil {
		logger.Errorf("Failed to create invitation, cause : %s", err)
		return err
	}

	err = a.verifyCreateInvitationResult(&result, label, useDID)
	if err != nil {
		return fmt.Errorf("failed to get valid payload from create invitation for agent [%s], reason: %w",
			inviterAgentID, err)
	}

	// save invitation for later use
	a.invitations[inviterAgentID] = result.Invitation

	return nil
}

func (a *ControllerSteps) performCreateImplicitInvitation(inviteeAgentID, inviterAgentID string, usePublic bool) error {
	destination, ok := a.bddContext.GetControllerURL(inviteeAgentID)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]",
			inviterAgentID)
	}

	inviterDID, ok := a.publicDIDs[inviterAgentID]
	if !ok {
		return fmt.Errorf("unable to find public DID for agent [%s]", inviterAgentID)
	}

	var inviteeDID string
	if usePublic {
		inviteeDID, ok = a.publicDIDs[inviteeAgentID]
		if !ok {
			return fmt.Errorf("unable to find public DID for agent [%s]", inviteeAgentID)
		}
	}

	logger.Debugf("Creating implicit invitation from controller for agent[%s]: inviterDID[%s], inviteeDID[%s]",
		inviteeAgentID, inviterDID, inviteeDID)

	// call controller
	path := fmt.Sprintf("%s%s?their_did=%s&their_label=%s&my_did=%s&my_label=%s",
		destination, createImplicitInvitationPath, inviterDID, inviterAgentID, inviteeDID, inviteeAgentID)

	var result models.ImplicitInvitationResponse

	err := sendHTTP(http.MethodPost, path, nil, &result)
	if err != nil {
		logger.Errorf("Failed to create implicit invitation, cause : %s", err)
		return err
	}

	// validate payload
	if result.ConnectionID == "" {
		return fmt.Errorf("connection id is empty for create implicit invitation for agent [%s]", inviteeAgentID)
	}

	// invitee connectionID
	a.connectionIDs[inviteeAgentID] = result.ConnectionID

	return nil
}

func (a *ControllerSteps) verifyCreateInvitationResult(result *models.CreateInvitationResponse,
	label string, useDID bool) error {
	// validate payload
	if result.Invitation == nil {
		return fmt.Errorf("empty invitation")
	}

	// verify result
	if result.Alias != label {
		return fmt.Errorf("invitation label mismatch, expected[%s] but got [%s]", label, result.Alias)
	}

	if useDID && result.Invitation.DID == "" {
		return fmt.Errorf("did ID not found in created invitation")
	}

	if !useDID && len(result.Invitation.RecipientKeys) == 0 {
		return fmt.Errorf("recipient keys not found in invitation")
	}

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
	return a.performApproveInvitation(agentID, false)
}

func (a *ControllerSteps) approveInvitationWithPublicDID(agentID string) error {
	return a.performApproveInvitation(agentID, true)
}

func (a *ControllerSteps) performApproveInvitation(agentID string, useDID bool) error {
	connectionID, err := a.pullWebhookEvents(agentID, "invited")
	if err != nil {
		return fmt.Errorf("aprove exchange invitation : %w", err)
	}

	// invitee connectionID
	a.connectionIDs[agentID] = connectionID

	destination, ok := a.bddContext.GetControllerURL(agentID)
	if !ok {
		return fmt.Errorf("unable to find contoller URL for agent [%s]", destination)
	}

	var publicDID string
	if useDID {
		publicDID, ok = a.publicDIDs[agentID]
		if !ok {
			return fmt.Errorf("unable to find public DID for agent [%s]", agentID)
		}
	}

	logger.Debugf("Accepting invitation from controller for agent[%s], did[%s]",
		agentID, publicDID)

	var response models.AcceptInvitationResponse

	path := destination + fmt.Sprintf(acceptInvitationPath, connectionID, publicDID)

	err = sendHTTP(http.MethodPost, path, nil, &response)
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
	return a.performApproveRequest(agentID, false)
}

func (a *ControllerSteps) approveRequestWithPublicDID(agentID string) error {
	return a.performApproveRequest(agentID, true)
}

func (a *ControllerSteps) performApproveRequest(agentID string, useDID bool) error {
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

	var publicDID string
	if useDID {
		publicDID, ok = a.publicDIDs[agentID]
		if !ok {
			return fmt.Errorf("unable to find public DID for agent [%s]", agentID)
		}
	}

	logger.Debugf("Accepting invitation from controller for agent[%s], did[%s]",
		agentID, publicDID)

	var response models.AcceptExchangeResult

	path := controllerURL + fmt.Sprintf(acceptRequestPath, connectionID, publicDID)

	err = sendHTTP(http.MethodPost, path, nil, &response)
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

	logger.Debugf("Getting connections by state %s from %s", queryState, destination)

	// call controller
	var response models.QueryConnectionsResponse

	err := sendHTTP(http.MethodGet, destination+connOperationID+"?state="+queryState, nil, &response)
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
		logger.Debugf("Connection[%s] found for agent[%s] with state[%s]", connection.ConnectionID, agentID, connection.State)

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

func (a *ControllerSteps) createPublicDID(agentID, didMethod string) error {
	destination, ok := a.bddContext.GetControllerURL(agentID)
	if !ok {
		return fmt.Errorf(" unable to find controller URL registered for agent [%s]", agentID)
	}

	// call controller
	path := fmt.Sprintf("%s%s?method=%s&header=%s", destination, createPublicDIDPath, didMethod, publicDIDCreateHeader)

	var result common.CreatePublicDIDResponse

	err := sendHTTP(http.MethodPost, path, nil, &result)
	if err != nil {
		logger.Errorf("Failed to create public DID, cause : %s", err)
		return err
	}

	// validate response
	if result.DID == nil || result.DID.ID == "" {
		return fmt.Errorf("failed to get valid public DID for agent [%s]", agentID)
	}

	logger.Debugf("Created public DID '%s' for agent '%s'", result.DID.ID, agentID)

	err = a.waitForPublicDID(result.DID.ID)
	if err != nil {
		logger.Errorf("Failed to resolve public DID created, cause : %s", err)
		return fmt.Errorf("failed to resolve public DID created, %w", err)
	}

	// save public DID for later use
	a.publicDIDs[agentID] = result.DID.ID

	return nil
}

// waitForPublicDID wait for public DID to be available before throw error after timeout
func (a *ControllerSteps) waitForPublicDID(id string) error {
	const retryDelay = 500 * time.Millisecond

	endpointURL, ok := a.bddContext.Args[sideTreeURL]
	if !ok {
		return fmt.Errorf("failed to find sidetree URL to resolve sidetree public DID")
	}

	start := time.Now()

	for {
		if time.Since(start) > timeoutWaitForDID {
			break
		}

		err := sendHTTP(http.MethodGet, endpointURL+"/"+id, nil, nil)
		if err != nil {
			logger.Warnf("Failed to resolve public DID, due to error [%s] will retry", err)
			time.Sleep(retryDelay)

			continue
		}

		return nil
	}

	return fmt.Errorf("unable to resolve public DID [%s]", id)
}

func (a *ControllerSteps) performDIDExchange(inviter, invitee string) error {
	err := a.createInvitation(inviter, inviter)
	if err != nil {
		return err
	}

	err = a.receiveInvitation(invitee, inviter)
	if err != nil {
		return err
	}

	err = a.approveInvitation(invitee)
	if err != nil {
		return err
	}

	err = a.approveRequest(inviter)
	if err != nil {
		return err
	}

	const expectedState = "completed"

	agentIDs := []string{inviter, invitee}
	for _, agentID := range agentIDs {
		err = a.waitForPostEvent(agentID, expectedState)
		if err != nil {
			return err
		}

		err = a.validateConnection(agentID, expectedState)
		if err != nil {
			return err
		}
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

	logger.Debugf("Got response from '%s' [method: %s], response payload: %s", destination, method, string(data))

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to get successful response from '%s', unexpected status code [%d], "+
			"and message [%s]", destination, resp.StatusCode, string(data))
	}

	if result == nil {
		return nil
	}

	return json.Unmarshal(data, result)
}

func closeResponse(c io.Closer) {
	err := c.Close()
	if err != nil {
		logger.Errorf("Failed to close response body : %s", err)
	}
}
