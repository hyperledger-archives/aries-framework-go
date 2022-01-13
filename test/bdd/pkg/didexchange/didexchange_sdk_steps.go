/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cucumber/godog"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	diddoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
)

// SDKSteps is steps for didexchange using client SDK.
type SDKSteps struct {
	bddContext     *context.BDDContext
	nextAction     map[string]chan struct{ connections []string }
	connectionID   map[string]string
	invitations    map[string]*didexchange.Invitation
	postStatesFlag map[string]map[string]chan bool
}

// NewDIDExchangeSDKSteps return new steps for didexchange using client SDK.
func NewDIDExchangeSDKSteps() *SDKSteps {
	return &SDKSteps{
		nextAction:     make(map[string]chan struct{ connections []string }),
		connectionID:   make(map[string]string),
		invitations:    make(map[string]*didexchange.Invitation),
		postStatesFlag: make(map[string]map[string]chan bool),
	}
}

func (d *SDKSteps) createInvitationWithRouter(inviterAgentID, router string) error {
	return d.createInvitationWithRouterAndKeyType(inviterAgentID, router, "")
}

func (d *SDKSteps) createInvitationWithoutRouter(inviterAgentID string) error {
	return d.CreateInvitation(inviterAgentID, "", "")
}

func (d *SDKSteps) createInvitationWithRouterAndKeyType(inviterAgentID, router, keyType string) error {
	connection, ok := d.bddContext.Args[router]
	if !ok {
		return fmt.Errorf("no connection for %s", router)
	}

	return d.CreateInvitation(inviterAgentID, connection, keyType)
}

// CreateInvitation creates an invitation.
func (d *SDKSteps) CreateInvitation(inviterAgentID, connection, keyType string) error {
	invitation, err := d.bddContext.DIDExchangeClients[inviterAgentID].CreateInvitation(inviterAgentID,
		didexchange.WithRouterConnectionID(connection), didexchange.WithKeyType(kms.KeyType(keyType)))
	if err != nil {
		return fmt.Errorf("create invitation: %w", err)
	}

	d.invitations[inviterAgentID] = invitation

	invitationBytes, err := json.Marshal(invitation)
	if err != nil {
		return fmt.Errorf("marshal invitation: %w", err)
	}

	logger.Debugf("Agent %s create invitation %s", inviterAgentID, invitationBytes)

	return nil
}

func (d *SDKSteps) validateInvitationEndpointScheme(inviterAgentID, scheme string) error {
	invitation := d.invitations[inviterAgentID]

	if !strings.HasPrefix(invitation.ServiceEndpoint, scheme) {
		return errors.New("invitation service endpoint - invalid transport type")
	}

	return nil
}

// CreateInvitationWithDID creates invitation with DID.
func (d *SDKSteps) CreateInvitationWithDID(inviterAgentID string) error {
	invitation, err := d.bddContext.DIDExchangeClients[inviterAgentID].CreateInvitationWithDID(inviterAgentID,
		d.bddContext.PublicDIDDocs[inviterAgentID].ID)
	if err != nil {
		return fmt.Errorf("failed to create invitation: %w", err)
	}

	d.invitations[inviterAgentID] = invitation

	invitationBytes, err := json.Marshal(invitation)
	if err != nil {
		return fmt.Errorf("failed to marshal invitation: %w", err)
	}

	logger.Debugf("Agent %s create invitation %s", inviterAgentID, invitationBytes)

	return nil
}

func (d *SDKSteps) createImplicitInvitation(inviteeAgentID, inviterAgentID string) error {
	connectionID, err := d.bddContext.DIDExchangeClients[inviteeAgentID].CreateImplicitInvitation(inviterAgentID,
		d.bddContext.PublicDIDDocs[inviterAgentID].ID)
	if err != nil {
		return fmt.Errorf("failed to create invitation: %w", err)
	}

	d.connectionID[inviteeAgentID] = connectionID

	return nil
}

func (d *SDKSteps) createImplicitInvitationWithDID(inviteeAgentID, inviterAgentID string) error {
	inviter := &didexchange.DIDInfo{
		DID:   d.bddContext.PublicDIDDocs[inviterAgentID].ID,
		Label: inviterAgentID,
	}

	invitee := &didexchange.DIDInfo{
		DID:   d.bddContext.PublicDIDDocs[inviteeAgentID].ID,
		Label: inviteeAgentID,
	}

	connID, err := d.bddContext.DIDExchangeClients[inviteeAgentID].CreateImplicitInvitationWithDID(inviter, invitee)
	if err != nil {
		return fmt.Errorf("failed to create invitation: %w", err)
	}

	d.connectionID[inviteeAgentID] = connID

	return nil
}

// WaitForPublicDID waits for public DID.
func (d *SDKSteps) WaitForPublicDID(agents string, maxSeconds int) error {
	for _, agentID := range strings.Split(agents, ",") {
		vdr := d.bddContext.AgentCtx[agentID].VDRegistry()
		if _, err := resolveDID(vdr, d.bddContext.PublicDIDDocs[agentID].ID, maxSeconds); err != nil {
			return err
		}
	}

	return nil
}

// ReceiveInvitation receives invitation.
func (d *SDKSteps) ReceiveInvitation(inviteeAgentID, inviterAgentID string) error {
	connectionID, err := d.bddContext.DIDExchangeClients[inviteeAgentID].HandleInvitation(d.invitations[inviterAgentID])
	if err != nil {
		return fmt.Errorf("failed to handle invitation: %w", err)
	}

	d.connectionID[inviteeAgentID] = connectionID

	return nil
}

// WaitForPostEvent waits for post event.
func (d *SDKSteps) WaitForPostEvent(agents, statesValue string) error {
	const timeout = 5 * time.Second

	for _, agentID := range strings.Split(agents, ",") {
		for _, state := range strings.Split(statesValue, ",") {
			select {
			case <-d.postStatesFlag[agentID][state]:
			case <-time.After(timeout):
				return fmt.Errorf("timeout waiting for %s's post state event '%s'", agentID, state)
			}
		}
	}

	return nil
}

// ValidateConnection checks the agents connection status against the given value.
func (d *SDKSteps) ValidateConnection(agents, stateValue string) error {
	for _, agentID := range strings.Split(agents, ",") {
		err := d.validateConnection(agentID, d.connectionID[agentID], stateValue)
		if err != nil {
			return err
		}
	}

	return nil
}

func (d *SDKSteps) validateConnToAgent(agent, other, stateValue string) error {
	connID := d.bddContext.GetConnectionID(agent, other)

	d.connectionID[agent] = connID

	return d.validateConnection(agent, connID, stateValue)
}

func (d *SDKSteps) validateConnection(agentID, connID, stateValue string) error {
	conn, err := d.bddContext.DIDExchangeClients[agentID].GetConnection(connID)
	if err != nil {
		return fmt.Errorf("failed to query connection by id: %w", err)
	}

	prettyConn, err := json.MarshalIndent(conn, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal connection: %w", err)
	}

	logger.Debugf("Agent[%s] state[%s] connection: \n %s", agentID, stateValue, string(prettyConn))

	if conn.State != stateValue {
		return fmt.Errorf("state from connection %s not equal %s", conn.State, stateValue)
	}

	if stateValue == "completed" {
		if err = d.validateResolveDID(agentID, conn.TheirDID); err != nil {
			return fmt.Errorf("validate resolve DID: %w", err)
		}
	}

	return nil
}

// validateResolveDID verifies if given agent is able to resolve their DID.
func (d *SDKSteps) validateResolveDID(agentID, theirDID string) error {
	doc, err := d.bddContext.AgentCtx[agentID].VDRegistry().Resolve(theirDID)
	if err != nil {
		return fmt.Errorf("failed to resolve theirDID [%s] after successful DIDExchange : %w", theirDID, err)
	}

	if doc == nil || doc.DIDDocument.ID != theirDID {
		return fmt.Errorf("failed to resolve theirDID [%s] after successful DIDExchange", theirDID)
	}

	return nil
}

// ApproveRequestWithRouter approves request.
func (d *SDKSteps) ApproveRequestWithRouter(agentID, router string) error {
	c, found := d.nextAction[agentID]
	if !found {
		return fmt.Errorf("%s is not registered for request approval", agentID)
	}

	connection, ok := d.bddContext.Args[router]
	if !ok {
		return fmt.Errorf("no connection for %s", router)
	}

	// sends the signal which automatically handles events
	c <- struct{ connections []string }{connections: []string{connection}}

	return nil
}

// ApproveRequest approves request.
func (d *SDKSteps) ApproveRequest(agentID string) error {
	c, found := d.nextAction[agentID]
	if !found {
		return fmt.Errorf("%s is not registered for request approval", agentID)
	}

	// sends the signal which automatically handles events
	c <- struct{ connections []string }{connections: nil}

	return nil
}

func (d *SDKSteps) getClientOptions(agentID string, connections []string) interface{} {
	clientOpts := &clientOptions{label: agentID, routerConnections: connections}

	pubDID, ok := d.bddContext.PublicDIDDocs[agentID]
	if ok {
		clientOpts.publicDID = pubDID.ID

		logger.Debugf("Agent %s will use public DID %s:", agentID, pubDID.ID)
	}

	return clientOpts
}

type clientOptions struct {
	publicDID         string
	label             string
	routerConnections []string
}

func (copts *clientOptions) PublicDID() string {
	return copts.publicDID
}

func (copts *clientOptions) Label() string {
	return copts.label
}

func (copts *clientOptions) RouterConnections() []string {
	return copts.routerConnections
}

// CreateDIDExchangeClient creates DIDExchangeClient.
func (d *SDKSteps) CreateDIDExchangeClient(agents string) error {
	for _, agentID := range strings.Split(agents, ",") {
		if _, exists := d.bddContext.DIDExchangeClients[agentID]; exists {
			continue
		}

		// create new did exchange client
		didexchangeClient, err := didexchange.New(d.bddContext.AgentCtx[agentID])
		if err != nil {
			return fmt.Errorf("failed to create new didexchange client: %w", err)
		}

		actionCh := make(chan service.DIDCommAction)
		if err = didexchangeClient.RegisterActionEvent(actionCh); err != nil {
			return fmt.Errorf("%s failed to register action event: %w", agentID, err)
		}

		d.bddContext.DIDExchangeClients[agentID] = didexchangeClient
		// initializes the channel for the agent
		d.nextAction[agentID] = make(chan struct{ connections []string })

		go d.autoExecuteActionEvent(agentID, actionCh)
	}

	return nil
}

func (d *SDKSteps) autoExecuteActionEvent(agentID string, ch <-chan service.DIDCommAction) {
	for e := range ch {
		// waits for the signal to allows this code to be executed
		res := <-d.nextAction[agentID]

		switch v := e.Properties.(type) {
		case didexchange.Event:
			d.connectionID[agentID] = v.ConnectionID()
		case error:
			panic(fmt.Sprintf("Service processing failed: %s", v))
		}

		clientOpts := d.getClientOptions(agentID, res.connections)
		e.Continue(clientOpts)
	}
}

// RegisterPostMsgEvent registers PostMsgEvent.
func (d *SDKSteps) RegisterPostMsgEvent(agents, statesValue string) error {
	for _, agentID := range strings.Split(agents, ",") {
		statusCh := make(chan service.StateMsg)
		if err := d.bddContext.DIDExchangeClients[agentID].RegisterMsgEvent(statusCh); err != nil {
			return fmt.Errorf("failed to register msg event: %w", err)
		}

		states := strings.Split(statesValue, ",")
		d.initializeStates(agentID, states)

		go d.eventListener(statusCh, agentID, states)
	}

	return nil
}

func (d *SDKSteps) performDIDExchange(inviter, invitee string) error {
	const completedStateValue = "completed"

	agentIDS := []string{invitee, inviter}

	for _, agentID := range agentIDS {
		err := d.RegisterPostMsgEvent(agentID, completedStateValue)
		if err != nil {
			return err
		}
	}

	// create invitation
	err := d.createInvitationWithoutRouter(inviter)
	if err != nil {
		return err
	}

	// receive invitation
	err = d.ReceiveInvitation(invitee, inviter)
	if err != nil {
		return err
	}

	err = d.ApproveRequest(invitee)
	if err != nil {
		return err
	}

	err = d.ApproveRequest(inviter)
	if err != nil {
		return err
	}

	for _, agentID := range agentIDS {
		err = d.WaitForPostEvent(agentID, completedStateValue)
		if err != nil {
			return err
		}

		err = d.ValidateConnection(agentID, completedStateValue)
		if err != nil {
			return err
		}
	}

	return d.checkThread(invitee, inviter)
}

func (d *SDKSteps) checkThread(invitee, inviter string) error {
	inviteeConn, err := d.bddContext.DIDExchangeClients[invitee].GetConnection(d.connectionID[invitee])
	if err != nil {
		return fmt.Errorf("failed to query connection by id: %w", err)
	}

	inviterConn, err := d.bddContext.DIDExchangeClients[inviter].GetConnection(d.connectionID[inviter])
	if err != nil {
		return fmt.Errorf("failed to query connection by id: %w", err)
	}

	if inviteeConn.ThreadID != inviterConn.ThreadID {
		return errors.New("threadIDs are different")
	}

	if inviteeConn.ThreadID != d.invitations[inviter].ID {
		return errors.New("threadID is not equal to the invitation ID")
	}

	return nil
}

func (d *SDKSteps) initializeStates(agentID string, states []string) {
	d.postStatesFlag[agentID] = make(map[string]chan bool)
	for _, state := range states {
		d.postStatesFlag[agentID][state] = make(chan bool)
	}
}

func (d *SDKSteps) eventListener(statusCh chan service.StateMsg, agentID string, states []string) {
	for e := range statusCh {
		err, ok := e.Properties.(error)
		if ok {
			panic(fmt.Sprintf("Service processing failed: %s : %s", agentID, err))
		}

		if e.Type == service.PostState {
			logger.Debugf("%s has received state event: %+v", agentID, e)

			if e.StateID != "invited" {
				logger.Debugf("Agent %s done processing %s message \n%s\n*****", agentID, e.Msg.Type(), e.Msg)
			}

			for _, state := range states {
				// receive the events
				if e.StateID == state {
					d.postStatesFlag[agentID][state] <- true
				}
			}
		}
	}
}

func (d *SDKSteps) saveConnectionID(agentID, varName string) error {
	d.bddContext.Args[varName] = d.connectionID[agentID]

	return nil
}

func resolveDID(vdr vdrapi.Registry, did string, maxRetry int) (*diddoc.Doc, error) {
	var doc *diddoc.DocResolution

	var err error
	for i := 1; i <= maxRetry; i++ {
		doc, err = vdr.Resolve(did)
		if err == nil {
			return doc.DIDDocument, nil
		} else if !errors.Is(err, vdrapi.ErrNotFound) {
			return nil, err
		}

		time.Sleep(1 * time.Second)
		logger.Debugf("Waiting for public did to be published in sidtree: %d second(s)\n", i)
	}

	return doc.DIDDocument, err
}

// SetContext is called before every scenario is run with a fresh new context.
func (d *SDKSteps) SetContext(ctx *context.BDDContext) {
	d.bddContext = ctx
}

// RegisterSteps registers did exchange steps.
func (d *SDKSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^"([^"]*)" creates invitation$`, d.createInvitationWithoutRouter)
	s.Step(`^"([^"]*)" creates invitation with router "([^"]*)" using key type "([^"]*)"$`,
		d.createInvitationWithRouterAndKeyType)
	s.Step(`^"([^"]*)" creates invitation with router "([^"]*)"$`, d.createInvitationWithRouter)
	s.Step(`^"([^"]*)" validates that invitation service endpoint of type "([^"]*)"$`, d.validateInvitationEndpointScheme)
	s.Step(`^"([^"]*)" creates invitation with public DID$`, d.CreateInvitationWithDID)
	s.Step(`^"([^"]*)" waits for public did to become available in sidetree for up to (\d+) seconds$`,
		d.WaitForPublicDID)
	s.Step(`^"([^"]*)" receives invitation from "([^"]*)"$`, d.ReceiveInvitation)
	s.Step(`^"([^"]*)" initiates connection with "([^"]*)" using peer DID$`, d.createImplicitInvitation)
	s.Step(`^"([^"]*)" initiates connection with "([^"]*)" using public DID$`, d.createImplicitInvitationWithDID)
	s.Step(`^"([^"]*)" waits for post state event "([^"]*)"$`, d.WaitForPostEvent)
	s.Step(`^"([^"]*)" retrieves connection record and validates that connection state is "([^"]*)"$`,
		d.ValidateConnection)
	s.Step(`^"([^"]*)" validates that connection to "([^"]*)" has state "([^"]*)"$`,
		d.validateConnToAgent)
	s.Step(`^"([^"]*)" creates did exchange client$`, d.CreateDIDExchangeClient)
	s.Step(`^"([^"]*)" approves did exchange request$`, d.ApproveRequest)
	s.Step(`^"([^"]*)" approves invitation request$`, d.ApproveRequest)
	s.Step(`^"([^"]*)" approves invitation request with router "([^"]*)"$`, d.ApproveRequestWithRouter)
	s.Step(`^"([^"]*)" approves did exchange request with router "([^"]*)"$`, d.ApproveRequestWithRouter)
	s.Step(`^"([^"]*)" registers to receive notification for post state event "([^"]*)"$`, d.RegisterPostMsgEvent)
	s.Step(`^"([^"]*)" has established connection with "([^"]*)" through did exchange$`, d.performDIDExchange)
	s.Step(`^"([^"]*)" saves connectionID to variable "([^"]*)"$`, d.saveConnectionID)
}
