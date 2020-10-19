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
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/messaging"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/service/basic"
	bddcontext "github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/util"
)

const (
	// message service endpoints.
	msgServiceOperationID = "/message"
	registerMsgService    = msgServiceOperationID + "/register-service"
	unregisterMsgService  = msgServiceOperationID + "/unregister-service"
	msgServiceList        = msgServiceOperationID + "/services"
	sendNewMsg            = msgServiceOperationID + "/send"
	sendReplyMsg          = msgServiceOperationID + "/reply"
	// query connections endpoint.
	queryConnections = "/connections"
	// webhook checktopics.
	checkForTopics = "/checktopics"
	// retry options to pull topics from webhook
	// pullTopicsWaitInMilliSec is time in milliseconds to wait before retry.
	pullTopicsWaitInMilliSec = 200
	// pullTopicsAttemptsBeforeFail total number of retries where
	// total time shouldn't exceed 5 seconds.
	pullTopicsAttemptsBeforeFail = 5000 / pullTopicsWaitInMilliSec
)

// ControllerSteps is steps for messaging using controller/REST binding.
type ControllerSteps struct {
	bddContext     *bddcontext.BDDContext
	msgIDsBySender map[string]string
}

// NewMessagingControllerSteps return new steps for messaging using controller/REST binding.
func NewMessagingControllerSteps() *ControllerSteps {
	return &ControllerSteps{
		msgIDsBySender: make(map[string]string),
	}
}

func (d *ControllerSteps) registerMsgService(agentID, name, msgType, purpose string) error {
	destination, ok := d.bddContext.GetControllerURL(agentID)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", agentID)
	}

	// unregister already registered message services, to avoid 'service already registered' error
	// due to previous test runs
	err := d.unregisterAllMsgServices(agentID, destination)
	if err != nil {
		return fmt.Errorf("failed to cleanup already registered services list : %w", err)
	}

	params := messaging.RegisterMsgSvcArgs{
		Type: msgType,
		Name: name,
	}

	if purpose != "" {
		params.Purpose = strings.Split(purpose, ",")
	}

	logger.Debugf("Registering message service for agent[%s],  params : %s", params)

	// call controller
	err = postToURL(destination+registerMsgService, params)
	if err != nil {
		return fmt.Errorf("failed to register message service[%s] : %w", name, err)
	}

	// verify if service just registered exists in registered services list
	svcNames, err := d.getServicesList(destination + msgServiceList)
	if err != nil {
		return fmt.Errorf("failed to get registered services list : %w", err)
	}

	var found bool

	for _, svcName := range svcNames {
		if svcName == name {
			found = true

			break
		}
	}

	if !found {
		return fmt.Errorf("failed to find registered service '%s' in registered services list", name)
	}

	return nil
}

func (d *ControllerSteps) unregisterAllMsgServices(agentID, destination string) error {
	svcNames, err := d.getServicesList(destination + msgServiceList)
	if err != nil {
		return fmt.Errorf("failed to get registered services list : %w", err)
	}

	for _, svcName := range svcNames {
		params := messaging.UnregisterMsgSvcArgs{
			Name: svcName,
		}

		logger.Debugf("Unregistering message service[%s] for agent[%s]: %w", svcName, agentID)

		// call controller
		err := postToURL(destination+unregisterMsgService, params)
		if err != nil {
			return fmt.Errorf("failed to unregister message service[%s] for agent[%s]: %w", svcName, agentID, err)
		}
	}

	return nil
}

func (d *ControllerSteps) getServicesList(url string) ([]string, error) {
	result := messaging.RegisteredServicesResponse{}
	// call controller
	err := util.SendHTTP(http.MethodGet, url, nil, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to get service list, cause : %w", err)
	}

	return result.Names, nil
}

func (d *ControllerSteps) sendMessage(fromAgentID, toAgentID string, msg interface{}) error {
	destination, ok := d.bddContext.GetControllerURL(fromAgentID)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", fromAgentID)
	}

	// get connection ID
	connID, err := d.findConnection(fromAgentID)
	if err != nil {
		return fmt.Errorf("failed to get existing connection:  %w", err)
	}

	// prepare message
	rawBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to get raw message bytes:  %w", err)
	}

	logger.Debugf("Sending message to agent[%s], connection ID[%s], message:[%s]", toAgentID, connID, string(rawBytes))

	request := &messaging.SendNewMessageArgs{
		ConnectionID: connID,
		MessageBody:  rawBytes,
	}

	// call controller to send message
	err = postToURL(destination+sendNewMsg, request)
	if err != nil {
		return fmt.Errorf("failed to send message : %w", err)
	}

	return nil
}

func (d *ControllerSteps) sendMessageReply(fromAgentID, toAgentID, msgID string, msg interface{}) error {
	destination, ok := d.bddContext.GetControllerURL(fromAgentID)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", fromAgentID)
	}

	// prepare message
	rawBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to get raw message bytes:  %w", err)
	}

	logger.Debugf("Sending message from [%s] to [%s], message ID[%s], message:[%s]",
		fromAgentID, toAgentID, msgID, string(rawBytes))

	request := &messaging.SendReplyMessageArgs{
		MessageID:   msgID,
		MessageBody: rawBytes,
	}

	// call controller to send message
	err = postToURL(destination+sendReplyMsg, request)
	if err != nil {
		return fmt.Errorf("failed to send message : %w", err)
	}

	return nil
}

func (d *ControllerSteps) sendMessageToDID(fromAgentID, toAgentID string, msg interface{}) error {
	destination, ok := d.bddContext.GetControllerURL(fromAgentID)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", fromAgentID)
	}

	// get public DID
	did, ok := d.bddContext.PublicDIDs[toAgentID]
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", fromAgentID)
	}

	// prepare message
	rawBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to get raw message bytes:  %w", err)
	}

	logger.Debugf("Sending message to agent[%s],  DID[%s], message:[%s]", toAgentID, did, string(rawBytes))

	request := &messaging.SendNewMessageArgs{
		TheirDID:    did,
		MessageBody: rawBytes,
	}

	// call controller to send message
	err = postToURL(destination+sendNewMsg, request)
	if err != nil {
		return fmt.Errorf("failed to send message : %w", err)
	}

	return nil
}

func (d *ControllerSteps) findConnection(agentID string) (string, error) {
	destination, ok := d.bddContext.GetControllerURL(agentID)
	if !ok {
		return "", fmt.Errorf(" unable to find controller URL registered for agent [%s]", agentID)
	}

	// call controller
	var response didexchange.QueryConnectionsResponse

	err := util.SendHTTP(http.MethodGet, destination+queryConnections+"?state=completed", nil, &response)
	if err != nil {
		return "", fmt.Errorf("failed to query connections : %w", err)
	}

	for _, conn := range response.Results {
		if conn.ConnectionID == d.bddContext.Args[agentID] {
			return conn.ConnectionID, nil
		}
	}

	return "", fmt.Errorf("no connection found, for agents '%s'", agentID)
}

func (d *ControllerSteps) pullMsgFromWebhookSocket(agentID, topic string) (service.DIDCommMsgMap, error) {
	msg, err := util.PullEventsFromWebSocket(d.bddContext, agentID,
		util.FilterTopic(topic),
		util.NotEmptyMessage(),
	)
	if err != nil {
		return nil, err
	}

	return msg.Message.Message, nil
}

func postToURL(url string, payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	return util.SendHTTP(http.MethodPost, url, body, nil)
}

func (d *ControllerSteps) pullMsgFromWebhookURL(agentID, topic string) (*service.DIDCommMsgMap, error) {
	webhookURL, ok := d.bddContext.GetWebhookURL(agentID)
	if !ok {
		return nil, fmt.Errorf("unable to find webhook URL for agent [%s]", agentID)
	}

	var incoming struct {
		ID      string                `json:"id"`
		Topic   string                `json:"topic"`
		Message service.DIDCommMsgMap `json:"message"`
	}

	// try to pull recently pushed topics from webhook
	for i := 0; i < pullTopicsAttemptsBeforeFail; {
		err := util.SendHTTP(http.MethodGet, webhookURL+checkForTopics, nil, &incoming)
		if err != nil {
			return nil, fmt.Errorf("failed pull topics from webhook, cause : %w", err)
		}

		if incoming.Topic != topic {
			continue
		}

		if len(incoming.Message) > 0 {
			return &incoming.Message, nil
		}

		i++

		time.Sleep(pullTopicsWaitInMilliSec * time.Millisecond)
	}

	return nil, fmt.Errorf("exhausted all [%d] attempts to pull topics from webhook", pullTopicsAttemptsBeforeFail)
}

func (d *ControllerSteps) registerBasicMsgService(agentID, name string) error {
	return d.registerMsgService(agentID, name, basic.MessageRequestType, "")
}

func (d *ControllerSteps) sendInviteMessage(fromAgentID, msg, msgType, purpose, toAgentID string) error {
	genericMsg := &genericInviteMsg{
		ID:      uuid.New().String(),
		Type:    msgType,
		Purpose: strings.Split(purpose, ","),
		Message: msg,
		From:    fromAgentID,
	}

	return d.sendMessage(fromAgentID, toAgentID, genericMsg)
}

func (d *ControllerSteps) sendInviteMessageReply(fromAgentID, toAgentID, msg, msgType, purpose string) error {
	genericMsg := &genericInviteMsg{
		ID:      uuid.New().String(),
		Type:    msgType,
		Purpose: strings.Split(purpose, ","),
		Message: msg,
		From:    fromAgentID,
	}

	msgID, ok := d.msgIDsBySender[toAgentID]
	if !ok {
		return fmt.Errorf("unable to find message ID for agent `%s`", toAgentID)
	}

	return d.sendMessageReply(fromAgentID, toAgentID, msgID, genericMsg)
}

func (d *ControllerSteps) sendBasicMessage(fromAgentID, msg, toAgentID string) error {
	basicMsg := &basic.Message{
		ID:      uuid.New().String(),
		Type:    basic.MessageRequestType,
		Content: msg,
		I10n: struct {
			Locale string `json:"locale"`
		}{
			Locale: "en",
		},
		SentTime: time.Now(),
	}

	return d.sendMessage(fromAgentID, toAgentID, basicMsg)
}

func (d *ControllerSteps) sendBasicMessageToDID(fromAgentID, msg, toAgentID string) error {
	basicMsg := &basic.Message{
		ID:      uuid.New().String(),
		Type:    basic.MessageRequestType,
		Content: msg,
		I10n: struct {
			Locale string `json:"locale"`
		}{
			Locale: "en",
		},
		SentTime: time.Now(),
	}

	return d.sendMessageToDID(fromAgentID, toAgentID, basicMsg)
}

func (d *ControllerSteps) receiveInviteMessage(agentID, expectedMsg, expectedMsgType, topic, from string) error {
	msg, err := d.pullMsgFromWebhookURL(agentID, topic)
	if err != nil {
		return fmt.Errorf("failed to pull incoming message from webhook : %w", err)
	}

	incomingMsg := struct {
		Message  service.DIDCommMsgMap `json:"message"`
		MyDID    string                `json:"mydid"`
		TheirDID string                `json:"theirdid"`
	}{}

	err = msg.Decode(&incomingMsg)
	if err != nil {
		return fmt.Errorf("failed to read message: %w", err)
	}

	if incomingMsg.Message.Type() != expectedMsgType {
		return fmt.Errorf("expected incoming message of type [%s], but got [%s]", expectedMsgType,
			incomingMsg.Message.Type())
	}

	invite := genericInviteMsg{}

	err = incomingMsg.Message.Decode(&invite)
	if err != nil {
		return fmt.Errorf("failed to read incoming invite message: %w", err)
	}

	if invite.Message != expectedMsg {
		return fmt.Errorf("expected message [%s], but got [%s]", expectedMsg, invite.Message)
	}

	if invite.From != from {
		return fmt.Errorf("expected message from [%s], but got from[%s]", from, invite.From)
	}

	d.msgIDsBySender[from] = invite.ID

	return nil
}

func (d *ControllerSteps) receiveBasicMessage(agentID, expectedMsg, topic, from string) error {
	msg, err := d.pullMsgFromWebhookSocket(agentID, topic)
	if err != nil {
		return fmt.Errorf("failed to pull incoming message from webhook : %w", err)
	}

	incomingMsg := struct {
		Message  service.DIDCommMsgMap `json:"message"`
		MyDID    string                `json:"mydid"`
		TheirDID string                `json:"theirdid"`
	}{}

	err = msg.Decode(&incomingMsg)
	if err != nil {
		return fmt.Errorf("failed to read message: %w", err)
	}

	if incomingMsg.Message.Type() != basic.MessageRequestType {
		return fmt.Errorf("expected incoming message of type [%s], but got [%s]", basic.MessageRequestType,
			incomingMsg.Message.Type())
	}

	basicMsg := basic.Message{}

	err = incomingMsg.Message.Decode(&basicMsg)
	if err != nil {
		return fmt.Errorf("failed to read incoming basic message: %w", err)
	}

	if basicMsg.Content != expectedMsg {
		return fmt.Errorf("expected basic message content [%s], but got [%s]", expectedMsg, basicMsg.Content)
	}

	if basicMsg.I10n.Locale != locale {
		return fmt.Errorf("expected basic message locale [%s], but got from[%s]", locale, basicMsg.I10n.Locale)
	}

	return nil
}

// SetContext is called before every scenario is run with a fresh new context.
func (d *ControllerSteps) SetContext(ctx *bddcontext.BDDContext) {
	d.bddContext = ctx
}

// RegisterSteps registers messaging steps.
func (d *ControllerSteps) RegisterSteps(s *godog.Suite) {
	// generic messaging
	s.Step(`^"([^"]*)" registers a message service through controller with name "([^"]*)" for type "([^"]*)"`+
		` and purpose "([^"]*)"$`, d.registerMsgService)
	s.Step(`^"([^"]*)" sends meeting invite message "([^"]*)" through controller with type "([^"]*)" `+
		`and purpose "([^"]*)" to "([^"]*)"$`, d.sendInviteMessage)
	s.Step(`^"([^"]*)" receives invite message "([^"]*)" with type "([^"]*)" to webhook`+
		` for topic "([^"]*)" from "([^"]*)"$`, d.receiveInviteMessage)
	s.Step(`^"([^"]*)" replies to "([^"]*)" with message "([^"]*)" through controller with type "([^"]*)" `+
		`and purpose "([^"]*)"$`, d.sendInviteMessageReply)

	// basic messaging
	s.Step(`^"([^"]*)" registers a message service through controller with name "([^"]*)" for basic message type$`,
		d.registerBasicMsgService)
	s.Step(`^"([^"]*)" sends basic message "([^"]*)" through controller to "([^"]*)"$`, d.sendBasicMessage)
	s.Step(`^"([^"]*)" sends out of band basic message "([^"]*)" through controller to "([^"]*)"$`,
		d.sendBasicMessageToDID)
	s.Step(`^"([^"]*)" receives basic message "([^"]*)" for topic "([^"]*)" from "([^"]*)"$`, d.receiveBasicMessage)
}
