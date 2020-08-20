/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cucumber/godog"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	didexcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/didexchange"
	cmdkms "github.com/hyperledger/aries-framework-go/pkg/controller/command/kms"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/sidetree"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/util"
)

const (
	connOperationID = "/connections"
	// TODO Remove it after switching packer to use new kms https://github.com/hyperledger/aries-framework-go/issues/1828
	kmsOperationID               = "/kms"
	createInvitationPath         = connOperationID + "/create-invitation"
	createImplicitInvitationPath = connOperationID + "/create-implicit-invitation"
	receiveInvtiationPath        = connOperationID + "/receive-invitation"
	acceptInvitationPath         = connOperationID + "/%s/accept-invitation?public=%s"
	acceptRequestPath            = connOperationID + "/%s/accept-request?public=%s"
	connectionsByID              = connOperationID + "/{id}"
	createKeySetPath             = kmsOperationID + "/keyset"
	timeoutWaitForDID            = 10 * time.Second
	sideTreeURL                  = "${SIDETREE_URL}"
)

var logger = log.New("aries-framework/didexchange-tests")

// ControllerSteps is steps for didexchange with controller.
type ControllerSteps struct {
	bddContext            *context.BDDContext
	invitations           map[string]*didexchange.Invitation
	connectionIDs         map[string]string
	agentServiceEndpoints map[string]string
}

// NewDIDExchangeControllerSteps creates steps for didexchange with controller.
func NewDIDExchangeControllerSteps() *ControllerSteps {
	return &ControllerSteps{
		invitations:   make(map[string]*didexchange.Invitation),
		connectionIDs: make(map[string]string),
		agentServiceEndpoints: map[string]string{
			"http://localhost:8082": "http://alice.aries.example.com:8081",
			"http://localhost:9082": "http://bob.agent.example.com:9081",
		},
	}
}

// SetContext is called before every scenario is run with a fresh new context.
func (a *ControllerSteps) SetContext(ctx *context.BDDContext) {
	a.bddContext = ctx
}

// RegisterSteps registers agent steps.
func (a *ControllerSteps) RegisterSteps(s *godog.Suite) { //nolint dupl
	s.Step(`^"([^"]*)" creates invitation through controller with label "([^"]*)"$`, a.createInvitation)
	s.Step(`^"([^"]*)" receives invitation from "([^"]*)" through controller$`, a.receiveInvitation)
	s.Step(`^"([^"]*)" approves exchange invitation through controller`, a.approveInvitation)
	s.Step(`^"([^"]*)" approves exchange request through controller`, a.ApproveRequest)
	s.Step(`^"([^"]*)" waits for post state event "([^"]*)" to web notifier`, a.WaitForPostEvent)
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
	s.Step(`^"([^"]*)" saves the connectionID to variable "([^"]*)"$`, a.saveConnectionID)
}

// EstablishConnection establishes connection between two agents through did exchange protocol.
func (a *ControllerSteps) EstablishConnection(inviter, invitee string) error {
	return a.performDIDExchange(inviter, invitee)
}

// ConnectionIDs gets connection IDs.
func (a *ControllerSteps) ConnectionIDs() map[string]string {
	return a.connectionIDs
}

func (a *ControllerSteps) pullEventsFromWebSocket(agentID, state string) (string, error) {
	msg, err := util.PullEventsFromWebSocket(a.bddContext, agentID,
		util.FilterTopic("didexchange_states"),
		util.FilterStateID(state),
		util.FilterType("post_state"),
	)
	if err != nil {
		return "", fmt.Errorf("pull events from WebSocket: %w", err)
	}

	return msg.Message.Properties["connectionID"].(string), nil
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
		publicDID, ok = a.bddContext.PublicDIDs[inviterAgentID]
		if !ok {
			return fmt.Errorf("unable to find public DID for agent [%s]", inviterAgentID)
		}
	}

	logger.Debugf("Creating invitation from controller for agent[%s], label[%s], did[%s]",
		inviterAgentID, publicDID, label)

	// call controller
	path := fmt.Sprintf("%s%s?alias=%s&public=%s", destination, createInvitationPath, label, publicDID)

	var result didexcmd.CreateInvitationResponse

	err := util.SendHTTP(http.MethodPost, path, nil, &result)
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

	inviterDID, ok := a.bddContext.PublicDIDs[inviterAgentID]
	if !ok {
		return fmt.Errorf("unable to find public DID for agent [%s]", inviterAgentID)
	}

	var inviteeDID string
	if usePublic {
		inviteeDID, ok = a.bddContext.PublicDIDs[inviteeAgentID]
		if !ok {
			return fmt.Errorf("unable to find public DID for agent [%s]", inviteeAgentID)
		}
	}

	logger.Debugf("Creating implicit invitation from controller for agent[%s]: inviterDID[%s], inviteeDID[%s]",
		inviteeAgentID, inviterDID, inviteeDID)

	// call controller
	path := fmt.Sprintf("%s%s?their_did=%s&their_label=%s&my_did=%s&my_label=%s",
		destination, createImplicitInvitationPath, inviterDID, inviterAgentID, inviteeDID, inviteeAgentID)

	var result didexcmd.ImplicitInvitationResponse

	err := util.SendHTTP(http.MethodPost, path, nil, &result)
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

func (a *ControllerSteps) verifyCreateInvitationResult(result *didexcmd.CreateInvitationResponse,
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
	var result didexcmd.ReceiveInvitationResponse

	err = util.SendHTTP(http.MethodPost, destination+receiveInvtiationPath, message, &result)
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

func (a *ControllerSteps) saveConnectionID(agentID, varName string) error {
	a.bddContext.Args[varName] = a.connectionIDs[agentID]

	return nil
}

func (a *ControllerSteps) approveInvitation(agentID string) error {
	return a.performApproveInvitation(agentID, false)
}

func (a *ControllerSteps) approveInvitationWithPublicDID(agentID string) error {
	return a.performApproveInvitation(agentID, true)
}

func (a *ControllerSteps) performApproveInvitation(agentID string, useDID bool) error {
	connectionID, err := a.pullEventsFromWebSocket(agentID, "invited")
	if err != nil {
		return fmt.Errorf("approve exchange invitation : %w", err)
	}

	// invitee connectionID
	a.connectionIDs[agentID] = connectionID

	var response didexcmd.AcceptInvitationResponse

	err = a.performApprove(agentID, useDID, connectionID, acceptInvitationPath, &response)
	if err != nil {
		return err
	}

	if response.ConnectionID == "" {
		logger.Errorf("Failed to perform approve invitation, cause : %s", err)
		return fmt.Errorf("failed to perform approve invitation, invalid response")
	}

	return nil
}

// ApproveRequest approves a request.
func (a *ControllerSteps) ApproveRequest(agentID string) error {
	return a.performApproveRequest(agentID, false)
}

func (a *ControllerSteps) approveRequestWithPublicDID(agentID string) error {
	return a.performApproveRequest(agentID, true)
}

func (a *ControllerSteps) performApprove(agentID string, useDID bool, connectionID, operationPath string,
	response interface{}) error {
	controllerURL, ok := a.bddContext.GetControllerURL(agentID)
	if !ok {
		return fmt.Errorf("unable to find contoller URL for agent [%s]", controllerURL)
	}

	var publicDID string
	if useDID {
		publicDID, ok = a.bddContext.PublicDIDs[agentID]
		if !ok {
			return fmt.Errorf("unable to find public DID for agent [%s]", agentID)
		}
	}

	logger.Debugf("Accepting invitation from controller for agent[%s], did[%s]",
		agentID, publicDID)

	path := controllerURL + fmt.Sprintf(operationPath, connectionID, publicDID)

	err := util.SendHTTP(http.MethodPost, path, nil, &response)
	if err != nil {
		logger.Errorf("Failed to perform approve request, cause : %s", err)
		return fmt.Errorf("failed to perform approve request : %w", err)
	}

	return nil
}

func (a *ControllerSteps) performApproveRequest(agentID string, useDID bool) error {
	connectionID, err := a.pullEventsFromWebSocket(agentID, "requested")
	if err != nil {
		return fmt.Errorf("failed to get connection ID from webhook, %w", err)
	}

	// inviter connectionID
	a.connectionIDs[agentID] = connectionID

	var response didexcmd.ExchangeResponse

	err = a.performApprove(agentID, useDID, connectionID, acceptRequestPath, &response)
	if err != nil {
		return err
	}

	if response.ConnectionID == "" {
		logger.Errorf("Failed to perform approve request, cause : %s", err)
		return fmt.Errorf("failed to perform approve request, invalid response")
	}

	return nil
}

// WaitForPostEvent waits for the specific post event state.
func (a *ControllerSteps) WaitForPostEvent(agentID, statesValue string) error {
	_, err := a.pullEventsFromWebSocket(agentID, statesValue)
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
	var response didexcmd.QueryConnectionResponse

	err := util.SendHTTP(http.MethodGet,
		destination+strings.Replace(connectionsByID, "{id}", connectionID, 1), nil, &response)
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
	var response didexcmd.QueryConnectionsResponse

	err := util.SendHTTP(http.MethodGet, destination+connOperationID+"?state="+queryState, nil, &response)
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

func (a *ControllerSteps) createPublicDID(agentID, _ string) error {
	destination, ok := a.bddContext.GetControllerURL(agentID)
	if !ok {
		return fmt.Errorf(" unable to find controller URL registered for agent [%s]", agentID)
	}

	path := fmt.Sprintf("%s%s", destination, createKeySetPath)

	reqBytes, err := json.Marshal(cmdkms.CreateKeySetRequest{KeyType: "ED25519"})
	if err != nil {
		return err
	}

	var result cmdkms.CreateKeySetResponse

	err = util.SendHTTP(http.MethodPost, path, reqBytes, &result)
	if err != nil {
		return err
	}

	// keys received from controller kms command are base64 RawURL encoded
	verKey, err := base64.RawURLEncoding.DecodeString(result.PublicKey)
	if err != nil {
		return err
	}

	pubKeyEd25519 := ed25519.PublicKey(verKey)

	jwk, err := jose.JWKFromPublicKey(pubKeyEd25519)
	if err != nil {
		return err
	}

	jwk.KeyID = result.KeyID

	doc, err := sidetree.CreateDID(
		&sidetree.CreateDIDParams{
			URL:             a.bddContext.Args[sideTreeURL] + "operations",
			KeyID:           result.KeyID,
			JWK:             jwk,
			ServiceEndpoint: a.agentServiceEndpoints[destination],
		})
	if err != nil {
		return err
	}

	err = a.waitForPublicDID(doc.ID)
	if err != nil {
		logger.Errorf("Failed to resolve public DID created, cause : %s", err)
		return fmt.Errorf("failed to resolve public DID created, %w", err)
	}

	// save public DID for later use
	a.bddContext.PublicDIDs[agentID] = doc.ID

	return nil
}

// waitForPublicDID wait for public DID to be available before throw error after timeout.
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

		err := util.SendHTTP(http.MethodGet, endpointURL+"/identifiers/"+id, nil, nil)
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

	err = a.ApproveRequest(inviter)
	if err != nil {
		return err
	}

	const expectedState = "completed"

	agentIDs := []string{inviter, invitee}
	for _, agentID := range agentIDs {
		err = a.WaitForPostEvent(agentID, expectedState)
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
