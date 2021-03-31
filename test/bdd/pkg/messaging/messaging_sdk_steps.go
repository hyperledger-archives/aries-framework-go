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
	"time"

	"github.com/cucumber/godog"
	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/service/basic"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
)

const (
	locale = "en"
)

var logger = log.New("aries-framework/tests/messaging")

// SDKSteps is steps for messaging using client SDK.
type SDKSteps struct {
	steps           *messagingSDKSteps
	genericMessages map[string]*msgService
	basicMessages   map[string]basic.Message
	msgIDsBySender  map[string]string
}

// NewMessagingSDKSteps return new steps for messaging using client SDK.
func NewMessagingSDKSteps() *SDKSteps {
	return &SDKSteps{
		genericMessages: make(map[string]*msgService),
		basicMessages:   make(map[string]basic.Message),
		msgIDsBySender:  make(map[string]string),
	}
}

func (d *SDKSteps) registerGenericMsgService(agentID, name, msgType, purpose string) error {
	msgSvc := newMessageService(name, msgType, strings.Split(purpose, ","))
	d.genericMessages[agentID] = msgSvc

	return d.steps.registerMsgService(agentID, msgSvc)
}

func (d *SDKSteps) sendGenericMessage(fromAgentID, msg, msgType, purpose, toAgentID string) error {
	msgMap := service.NewDIDCommMsgMap(&genericInviteMsg{
		ID:      uuid.New().String(),
		Type:    msgType,
		Purpose: strings.Split(purpose, ","),
		Message: msg,
		From:    fromAgentID,
	})

	return d.steps.sendMessage(fromAgentID, toAgentID, msgMap)
}

func (d *SDKSteps) sendGenericMessageToDID(fromAgentID, msg, msgType, purpose, toAgentID string) error {
	msgMap := service.NewDIDCommMsgMap(&genericInviteMsg{
		ID:      uuid.New().String(),
		Type:    msgType,
		Purpose: strings.Split(purpose, ","),
		Message: msg,
		From:    fromAgentID,
	})

	return d.steps.sendMessageToPublicDID(fromAgentID, toAgentID, msgMap)
}

func (d *SDKSteps) receiveGenericMessage(agentID, expectedMsg, expectedMsgType, from string) error {
	msgSvc, ok := d.genericMessages[agentID]
	if !ok {
		return fmt.Errorf("unable to find message service queue for agent[%s]", agentID)
	}

	invite, err := msgSvc.popMessage()
	if err != nil {
		return fmt.Errorf("failed to receive message for agent[%s]", agentID)
	}

	if invite.Type != expectedMsgType {
		return fmt.Errorf("incorrect message received, expected type `%s` but got `%s`",
			invite.Type, expectedMsgType)
	}

	if invite.Message != expectedMsg {
		return fmt.Errorf("incorrect message received, expected msg body `%s` but got `%s`",
			invite.Message, expectedMsg)
	}

	if invite.From != from {
		return fmt.Errorf("incorrect message received, expected msg from `%s` but got from `%s`",
			invite.Type, expectedMsgType)
	}

	_, err = msgSvc.popMessage()
	if err == nil || err.Error() != errTimeoutWaitingForMsg {
		return fmt.Errorf("expected only one incoming message for agent [%s]", agentID)
	}

	d.msgIDsBySender[from] = invite.ID

	return nil
}

func (d *SDKSteps) sendGenericMessageReply(fromAgentID, toAgentID, msg, msgType, purpose string) error {
	msgMap := service.NewDIDCommMsgMap(&genericInviteMsg{
		ID:      uuid.New().String(),
		Type:    msgType,
		Purpose: strings.Split(purpose, ","),
		Message: msg,
		From:    fromAgentID,
	})

	msgID, ok := d.msgIDsBySender[toAgentID]
	if !ok {
		return fmt.Errorf("unable to find message ID for agent `%s`", toAgentID)
	}

	return d.steps.sendMessageReply(fromAgentID, toAgentID, msgID, msgMap)
}

func (d *SDKSteps) registerBasicMsgService(agentID, name string) error {
	messageHandle := func(message basic.Message, _ service.DIDCommContext) error {
		d.basicMessages[agentID] = message
		return nil
	}

	msgSvc, err := basic.NewMessageService(name, messageHandle)
	if err != nil {
		return fmt.Errorf("failed to register basic message service")
	}

	return d.steps.registerMsgService(agentID, msgSvc)
}

func (d *SDKSteps) sendBasicMsg(fromAgentID, msg, toAgentID string) error {
	msgMap := service.NewDIDCommMsgMap(&basic.Message{
		ID:      uuid.New().String(),
		Type:    basic.MessageRequestType,
		Content: msg,
		I10n: struct {
			Locale string `json:"locale"`
		}{
			Locale: "en",
		},
		SentTime: time.Now(),
	})

	return d.steps.sendMessage(fromAgentID, toAgentID, msgMap)
}

func (d *SDKSteps) receiveBasicMsg(agentID, msg, from string) error {
	basicMsg, ok := d.basicMessages[agentID]
	if !ok {
		return fmt.Errorf("didn't receive any basic message for agent[%s]", agentID)
	}

	if basicMsg.Content != msg {
		return fmt.Errorf(" expected basic message content [%s], but got [%s]", msg, basicMsg.Content)
	}

	if basicMsg.I10n.Locale != locale {
		return fmt.Errorf(" expected basic message locale [%s], but got [%s]", locale, basicMsg.I10n.Locale)
	}

	return nil
}

// SetContext is called before every scenario is run with a fresh new context.
func (d *SDKSteps) SetContext(ctx *context.BDDContext) {
	d.steps = &messagingSDKSteps{
		bddContext: ctx,
	}
}

// RegisterSteps registers messaging steps.
func (d *SDKSteps) RegisterSteps(s *godog.Suite) {
	// generic message
	s.Step(`^"([^"]*)" registers a message service with name "([^"]*)" for type "([^"]*)" and purpose "([^"]*)"$`,
		d.registerGenericMsgService)
	s.Step(`^"([^"]*)" sends meeting invite message "([^"]*)" with type "([^"]*)" and purpose "([^"]*)" to "([^"]*)"$`,
		d.sendGenericMessage)
	s.Step(`^"([^"]*)" sends out of band meeting invite message "([^"]*)" with type "([^"]*)" `+
		`and purpose "([^"]*)" to "([^"]*)"$`, d.sendGenericMessageToDID)
	s.Step(`^"([^"]*)" message service receives meeting invite message "([^"]*)" with type "([^"]*)" from "([^"]*)"$`,
		d.receiveGenericMessage)
	s.Step(`^"([^"]*)" replies to "([^"]*)" with message "([^"]*)" with type "([^"]*)" and purpose "([^"]*)"$`,
		d.sendGenericMessageReply)

	// basic message
	s.Step(`^"([^"]*)" registers a message service with name "([^"]*)" for basic message type$`,
		d.registerBasicMsgService)
	s.Step(`^"([^"]*)" sends basic message "([^"]*)" to "([^"]*)"$`, d.sendBasicMsg)
	s.Step(`^"([^"]*)" receives basic message "([^"]*)" from "([^"]*)"$`, d.receiveBasicMsg)
}
