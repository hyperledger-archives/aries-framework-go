/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"crypto/ed25519"
	"crypto/rand"
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
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk/jwksupport"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
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
	acceptInvitationPath         = connOperationID + "/%s/accept-invitation?public=%s" // router_connections
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
			"https://localhost:8082": "https://alice.aries.example.com:8081",
			"https://localhost:9082": "https://bob.agent.example.com:9081",
		},
	}
}

// SetContext is called before every scenario is run with a fresh new context.
func (a *ControllerSteps) SetContext(ctx *context.BDDContext) {
	a.bddContext = ctx
}

// RegisterSteps registers agent steps.
func (a *ControllerSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^"([^"]*)" creates invitation through controller with label "([^"]*)"$`, a.createInvitation)
	s.Step(`^"([^"]*)" creates invitation through controller with label "([^"]*)" and router "([^"]*)"$`,
		a.createInvitationWithRouter)
	s.Step(`^"([^"]*)" receives invitation from "([^"]*)" through controller$`, a.receiveInvitation)
	s.Step(`^"([^"]*)" approves exchange invitation through controller$`, a.approveInvitation)
	s.Step(`^"([^"]*)" approves exchange invitation with router "([^"]*)" through controller$`,
		a.approveInvitationWithRouter)
	s.Step(`^"([^"]*)" approves exchange request through controller`, a.ApproveRequest)
	s.Step(`^"([^"]*)" approves exchange request with router "([^"]*)" through controller$`,
		a.ApproveRequestWithRouter)
	s.Step(`^"([^"]*)" waits for post state event "([^"]*)" to web notifier`, a.WaitForPostEvent)
	s.Step(`^"([^"]*)" retrieves connection record through controller and validates that connection state is "([^"]*)"$`,
		a.validateConnections)
	// public DID steps
	s.Step(`^"([^"]*)" creates "([^"]*)" public DID through controller`, a.CreatePublicDID)
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
	return a.performCreateInvitation(inviterAgentID, label, "", false)
}

func (a *ControllerSteps) createInvitationWithRouter(inviterAgentID, label, router string) error {
	routerID, ok := a.bddContext.Args[router]
	if !ok {
		return fmt.Errorf("create invitation with router: connection %q was not found", router)
	}

	return a.performCreateInvitation(inviterAgentID, label, routerID, false)
}

func (a *ControllerSteps) createInvitationWithDID(inviterAgentID, label string) error {
	return a.performCreateInvitation(inviterAgentID, label, "", true)
}

func (a *ControllerSteps) createImplicitInvitation(inviteeAgentID, inviterAgentID string) error {
	return a.performCreateImplicitInvitation(inviteeAgentID, inviterAgentID, false)
}

func (a *ControllerSteps) createImplicitInvitationWithDID(inviteeAgentID, inviterAgentID string) error {
	return a.performCreateImplicitInvitation(inviteeAgentID, inviterAgentID, true)
}

func chooseConnection(url string) (string, error) {
	connections := struct{ Connections []string }{}

	err := util.SendHTTP(http.MethodGet, url+"/mediator/connections", nil, &connections)
	if err != nil {
		return "", fmt.Errorf("mediator connections: %w", err)
	}

	if len(connections.Connections) == 0 {
		return "", nil
	}

	return connections.Connections[0], nil
}

func (a *ControllerSteps) performCreateInvitation(inviterAgentID, label, routerID string, useDID bool) error {
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

	if routerID == "" {
		var err error

		routerID, err = chooseConnection(destination)
		if err != nil {
			return err
		}
	}

	// call controller
	path := fmt.Sprintf("%s%s?alias=%s&public=%s&router_connection_id=%s",
		destination, createInvitationPath, label, publicDID, routerID)

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
	a.bddContext.SaveConnectionID(inviteeAgentID, inviterAgentID, result.ConnectionID)

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
	a.bddContext.SaveConnectionID(inviteeAgentID, inviterAgentID, result.ConnectionID)

	return nil
}

func (a *ControllerSteps) saveConnectionID(agentID, varName string) error {
	a.bddContext.Args[varName] = a.connectionIDs[agentID]

	return nil
}

func (a *ControllerSteps) approveInvitation(agentID string) error {
	_, err := a.performApproveInvitation(agentID, "", false)

	return err
}

func (a *ControllerSteps) approveInvitationWithRouter(agentID, router string) error {
	routerID, ok := a.bddContext.Args[router]
	if !ok {
		return fmt.Errorf("approve invitation with router: connection %q was not found", router)
	}

	_, err := a.performApproveInvitation(agentID, routerID, false)

	return err
}

func (a *ControllerSteps) approveInvitationWithPublicDID(agentID string) error {
	_, err := a.performApproveInvitation(agentID, "", true)

	return err
}

func (a *ControllerSteps) performApproveInvitation(agentID, routerID string, useDID bool) (string, error) {
	connectionID, err := a.pullEventsFromWebSocket(agentID, "invited")
	if err != nil {
		return "", fmt.Errorf("approve exchange invitation : %w", err)
	}

	// invitee connectionID
	a.connectionIDs[agentID] = connectionID

	var response didexcmd.AcceptInvitationResponse

	err = a.performApprove(agentID, useDID, connectionID, routerID, acceptInvitationPath, &response)
	if err != nil {
		return "", err
	}

	if response.ConnectionID == "" {
		logger.Errorf("Failed to perform approve invitation, cause : %s", err)
		return "", fmt.Errorf("failed to perform approve invitation, invalid response")
	}

	return response.ConnectionID, nil
}

// ApproveRequest approves a request.
func (a *ControllerSteps) ApproveRequest(agentID string) error {
	_, err := a.performApproveRequest(agentID, "", false)

	return err
}

// ApproveRequestWithRouter approves a request.
func (a *ControllerSteps) ApproveRequestWithRouter(agentID, router string) error {
	routerID, ok := a.bddContext.Args[router]
	if !ok {
		return fmt.Errorf("create invitation with router: connection %q was not found", router)
	}

	_, err := a.performApproveRequest(agentID, routerID, false)

	return err
}

func (a *ControllerSteps) approveRequestWithPublicDID(agentID string) error {
	_, err := a.performApproveRequest(agentID, "", true)

	return err
}

func (a *ControllerSteps) performApprove(agentID string, useDID bool, connectionID, routerID, operationPath string,
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

	if routerID == "" {
		var err error

		routerID, err = chooseConnection(controllerURL)
		if err != nil {
			return err
		}
	}

	path := controllerURL + fmt.Sprintf(operationPath, connectionID, publicDID)
	path += "&router_connections=" + routerID

	err := util.SendHTTP(http.MethodPost, path, nil, &response)
	if err != nil {
		logger.Errorf("Failed to perform approve request, cause : %s", err)
		return fmt.Errorf("failed to perform approve request : %w", err)
	}

	return nil
}

func (a *ControllerSteps) performApproveRequest(agentID, routerID string, useDID bool) (string, error) {
	connectionID, err := a.pullEventsFromWebSocket(agentID, "requested")
	if err != nil {
		return "", fmt.Errorf("failed to get connection ID for agent: '%v', router: '%v' from webhook, %w",
			agentID, routerID, err)
	}

	// inviter connectionID
	a.connectionIDs[agentID] = connectionID

	var response didexcmd.ExchangeResponse

	err = a.performApprove(agentID, useDID, connectionID, routerID, acceptRequestPath, &response)
	if err != nil {
		return "", err
	}

	if response.ConnectionID == "" {
		logger.Errorf("Failed to perform approve request, cause : %s", err)
		return "", fmt.Errorf("failed to perform approve request, invalid response")
	}

	return response.ConnectionID, nil
}

// WaitForPostEvent waits for the specific post event state.
func (a *ControllerSteps) WaitForPostEvent(agents, statesValue string) error {
	for _, agent := range strings.Split(agents, ",") {
		_, err := a.pullEventsFromWebSocket(agent, statesValue)
		if err != nil {
			return fmt.Errorf("failed to get notification from webhook, %w", err)
		}
	}

	return nil
}

func (a *ControllerSteps) validateConnections(agents, stateValue string) error {
	for _, agent := range strings.Split(agents, ",") {
		if err := a.validateConnection(agent, stateValue); err != nil {
			return fmt.Errorf("validate connections: %w", err)
		}
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

// CreatePublicDID step creates a public sidetree DID for the given agent. Second parameter is ignored.
func (a *ControllerSteps) CreatePublicDID(agentID, _ string) error {
	_, err := a.CreatePublicDIDWithKeyType(agentID, "ED25519", "")

	return err
}

// CreatePublicDIDWithKeyType creates a public sidetree DID with the given key type, returning the DID.
func (a *ControllerSteps) CreatePublicDIDWithKeyType( // nolint:funlen,gocyclo
	agentID, keyType, encKeyType string) (string, error) {
	isDIDCommV2 := encKeyType != ""

	destination, ok := a.bddContext.GetControllerURL(agentID)
	if !ok {
		return "", fmt.Errorf(" unable to find controller URL registered for agent [%s]", agentID)
	}

	path := fmt.Sprintf("%s%s", destination, createKeySetPath)

	reqBytes, err := json.Marshal(cmdkms.CreateKeySetRequest{KeyType: keyType})
	if err != nil {
		return "", err
	}

	var result cmdkms.CreateKeySetResponse

	err = util.SendHTTP(http.MethodPost, path, reqBytes, &result)
	if err != nil {
		return "", err
	}

	// keys received from controller kms command are base64 RawURL encoded
	verKey, err := base64.RawURLEncoding.DecodeString(result.PublicKey)
	if err != nil {
		return "", err
	}

	j, err := jwksupport.PubKeyBytesToJWK(verKey, kms.KeyType(keyType))
	if err != nil {
		return "", err
	}

	j.KeyID = result.KeyID

	var encKey []byte

	if isDIDCommV2 {
		reqBytes, err = json.Marshal(cmdkms.CreateKeySetRequest{KeyType: encKeyType})
		if err != nil {
			return "", err
		}

		err = util.SendHTTP(http.MethodPost, path, reqBytes, &result)
		if err != nil {
			return "", err
		}

		// keys received from controller kms command are base64 RawURL encoded
		encKey, err = base64.RawURLEncoding.DecodeString(result.PublicKey)
		if err != nil {
			return "", err
		}
	}

	publicKeyRecovery, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}

	recoveryJWK, err := jwksupport.JWKFromKey(publicKeyRecovery)
	if err != nil {
		return "", err
	}

	publicKeyUpdate, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}

	updateJWK, err := jwksupport.JWKFromKey(publicKeyUpdate)
	if err != nil {
		return "", err
	}

	params := sidetree.CreateDIDParams{
		URL:             a.bddContext.Args[sideTreeURL] + "operations",
		KeyID:           result.KeyID,
		JWK:             j,
		RecoveryJWK:     recoveryJWK,
		UpdateJWK:       updateJWK,
		ServiceEndpoint: a.agentServiceEndpoints[destination],
	}

	if isDIDCommV2 {
		params.ServiceType = vdr.DIDCommV2ServiceType
		params.EncryptionKey = encKey
		params.EncKeyType = kms.KeyType(encKeyType)
	}

	doc, err := sidetree.CreateDID(&params)
	if err != nil {
		return "", err
	}

	err = a.waitForPublicDID(doc.ID)
	if err != nil {
		logger.Errorf("Failed to resolve public DID created, cause : %s", err)
		return "", fmt.Errorf("failed to resolve public DID created, %w", err)
	}

	// save public DID for later use
	a.bddContext.PublicDIDs[agentID] = doc.ID
	a.bddContext.PublicDIDDocs[agentID] = doc

	return doc.ID, nil
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

	inviteeConnID, err := a.performApproveInvitation(invitee, "", false)
	if err != nil {
		return err
	}

	inviterConnID, err := a.performApproveRequest(inviter, "", false)
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

	a.bddContext.SaveConnectionID(invitee, inviter, inviteeConnID)
	a.bddContext.SaveConnectionID(inviter, invitee, inviterConnID)

	return nil
}
