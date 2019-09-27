/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd

import (
	"encoding/json"
	"fmt"
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
	// TODO remove it after have the ability to register for events
	time.Sleep(2 * time.Second)
	logger.Infof("Agent %s receive invitation from Agent %s", inviteeAgentID, inviterAgentID)
	return nil
}

// RegisterSteps registers did exchange steps
func (d *DIDExchangeSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^"([^"]*)" creates invitation$`, d.createInvitation)
	s.Step(`^"([^"]*)" receives invitation from "([^"]*)"$`, d.receiveInvitation)

}
