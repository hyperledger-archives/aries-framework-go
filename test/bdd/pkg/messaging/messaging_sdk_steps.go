/*
 *
 * Copyright SecureKey Technologies Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 *
 */

package messaging

import (
	"fmt"
	"strings"

	"github.com/DATA-DOG/godog"
	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
)

var logger = log.New("aries-framework/tests/messaging")

// SDKSteps is steps for messaging using client SDK
type SDKSteps struct {
	bddContext  *context.BDDContext
	msgServices map[string]*msgService
}

// NewMessagingSDKSteps return new steps for messaging using client SDK
func NewMessagingSDKSteps(ctx *context.BDDContext) *SDKSteps {
	return &SDKSteps{
		bddContext:  ctx,
		msgServices: make(map[string]*msgService),
	}
}

func (d *SDKSteps) registerMsgService(agentID, name, msgType, purpose string) error {
	registrar, ok := d.bddContext.MessageRegistrar[agentID]
	if !ok {
		return fmt.Errorf("unable to find message registrar for agent `%s`", agentID)
	}

	msgSvc := newMessageService(name, msgType, strings.Split(purpose, ","))

	err := registrar.Register(msgSvc)
	if err != nil {
		return fmt.Errorf("unable to register message service '%s' for type/purpose [%s/%s] : %w",
			name, msgType, purpose, err)
	}

	d.msgServices[agentID] = msgSvc

	logger.Debugf("Agent[%s] registered message service '%s' for type[%s] and purpose[%s]",
		agentID, name, msgType, purpose)

	return nil
}

func (d *SDKSteps) sendMessage(fromAgentID, msg, msgType, purpose, toAgentID string) error {
	messenger, ok := d.bddContext.Messengers[fromAgentID]
	if !ok {
		return fmt.Errorf("unable to find messenger for agent `%s`", fromAgentID)
	}

	ctx, ok := d.bddContext.AgentCtx[fromAgentID]
	if !ok {
		return fmt.Errorf("unable to find context for agent `%s`", fromAgentID)
	}

	// find connection matching destination
	lookup, err := connection.NewLookup(ctx)
	if err != nil {
		return fmt.Errorf("failed to get connection lookup")
	}

	connections, err := lookup.QueryConnectionRecords()
	if err != nil {
		return fmt.Errorf("failed to query connections")
	}

	var target *connection.Record

	for _, conn := range connections {
		if conn.State == "completed" && conn.TheirLabel == toAgentID {
			target = conn
			break
		}
	}

	message := &genericInviteMsg{
		ID:      uuid.New().String(),
		Type:    msgType,
		Purpose: strings.Split(purpose, ","),
		Message: msg,
		From:    fromAgentID,
	}

	// send message
	err = messenger.SendToDID(message, target.MyDID, target.TheirDID)
	if err != nil {
		return fmt.Errorf("failed to send message to agent[%s] : %w", toAgentID, err)
	}

	return nil
}

func (d *SDKSteps) receiveMessage(agentID, expectedMsg, expectedMsgType, from string) error {
	msgService, ok := d.msgServices[agentID]
	if !ok {
		return fmt.Errorf("unable to find message service queue for agent[%s]", agentID)
	}

	invite, err := msgService.popMessage()
	if err != nil {
		return fmt.Errorf("failed to receive message for agent[%s]", agentID)
	}

	if invite.Type != expectedMsgType {
		return fmt.Errorf("incorrect message received, expected type `%s` but got `%s`",
			invite.Type, expectedMsgType)
	}

	if invite.Message != expectedMsg {
		return fmt.Errorf("incorrect message received, expected msg body `%s` but got `%s`",
			invite.Type, expectedMsgType)
	}

	if invite.From != from {
		return fmt.Errorf("incorrect message received, expected msg from `%s` but got from `%s`",
			invite.Type, expectedMsgType)
	}

	_, err = msgService.popMessage()
	if err == nil || err.Error() != errTimeoutWaitingForMsg {
		return fmt.Errorf("expected only one incoming message for agent [%s]", agentID)
	}

	return nil
}

// RegisterSteps registers messaging steps
func (d *SDKSteps) RegisterSteps(s *godog.Suite) { //nolint dupl
	s.Step(`^"([^"]*)" registers a message service with name "([^"]*)" for type "([^"]*)" and purpose "([^"]*)"$`,
		d.registerMsgService)
	s.Step(`^"([^"]*)" sends meeting invite message "([^"]*)" with type "([^"]*)" and purpose "([^"]*)" to "([^"]*)"$`,
		d.sendMessage)
	s.Step(`^"([^"]*)" message service receives meeting invite message "([^"]*)" with type "([^"]*)" from "([^"]*)"$`,
		d.receiveMessage)
}
