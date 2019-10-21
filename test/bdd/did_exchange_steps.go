/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/DATA-DOG/godog"
)

// DIDExchangeSteps
type DIDExchangeSteps struct {
	bddContext *Context
}

// NewDIDExchangeSteps
func NewDIDExchangeSteps(context *Context) *DIDExchangeSteps {
	return &DIDExchangeSteps{bddContext: context}
}

func (d *DIDExchangeSteps) createInvitation(inviterAgentID string) error {
	invitation, err := d.bddContext.DIDExchangeClients[inviterAgentID].CreateInvitation(inviterAgentID)
	if err != nil {
		return fmt.Errorf("failed to create invitation: %w", err)
	}
	d.bddContext.Invitations[inviterAgentID] = invitation
	invitationBytes, err := json.Marshal(invitation)
	if err != nil {
		return fmt.Errorf("failed to marshal invitation: %w", err)
	}
	logger.Infof("Agent %s create invitation %s", inviterAgentID, invitationBytes)
	return nil
}

func (d *DIDExchangeSteps) receiveInvitation(inviteeAgentID, inviterAgentID string) error {
	err := d.bddContext.DIDExchangeClients[inviteeAgentID].HandleInvitation(d.bddContext.Invitations[inviterAgentID])
	if err != nil {
		return fmt.Errorf("failed to handle invitation: %w", err)
	}
	logger.Infof("Agent %s receive invitation from Agent %s", inviteeAgentID, inviterAgentID)
	return nil
}

func (d *DIDExchangeSteps) waitForPostEvent(agentID, statesValue string) error {
	states := strings.Split(statesValue, ",")
	for _, state := range states {
		select {
		case <-d.bddContext.PostStatesFlag[agentID][state]:
		case <-time.After(5 * time.Second):
			return fmt.Errorf("timeout waiting for post state event %s", state)
		}
	}
	return nil
}

func (d *DIDExchangeSteps) validateConnection(agentID, stateValue string) error {
	conn, err := d.bddContext.DIDExchangeClients[agentID].GetConnectionRecord(d.bddContext.ConnectionID[agentID])
	if err != nil {
		return fmt.Errorf("failed to query connection by id: %w", err)
	}
	if conn.State != stateValue {
		return fmt.Errorf("state from connection %s not equal %s", conn.State, stateValue)
	}
	return nil
}

// RegisterSteps registers did exchange steps
func (d *DIDExchangeSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^"([^"]*)" creates invitation$`, d.createInvitation)
	s.Step(`^"([^"]*)" receives invitation from "([^"]*)"$`, d.receiveInvitation)
	s.Step(`^"([^"]*)" waits for post state event "([^"]*)"$`, d.waitForPostEvent)
	s.Step(`^"([^"]*)" retrieves connection record and validates that connection state is "([^"]*)"$`, d.validateConnection)

}
