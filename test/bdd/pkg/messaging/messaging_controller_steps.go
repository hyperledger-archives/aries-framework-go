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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/DATA-DOG/godog"
	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command/messaging"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/service/basic"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/operation/didexchange/models"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
)

const (
	// message service endpoints
	msgServiceOperationID = "/message"
	registerMsgService    = msgServiceOperationID + "/register-service"
	unregisterMsgService  = msgServiceOperationID + "/unregister-service"
	msgServiceList        = msgServiceOperationID + "/services"
	sendNewMsg            = msgServiceOperationID + "/send"
	// query connections endpoint
	queryConnections = "/connections"
	// webhook checktopis
	checkForTopics = "/checktopics"
	// retry options to pull topics from webhook
	// pullTopicsWaitInMilliSec is time in milliseconds to wait before retry
	pullTopicsWaitInMilliSec = 200
	// pullTopicsAttemptsBeforeFail total number of retries where
	// total time shouldn't exceed 5 seconds
	pullTopicsAttemptsBeforeFail = 5000 / pullTopicsWaitInMilliSec
)

// ControllerSteps is steps for messaging using controller/REST binding
type ControllerSteps struct {
	bddContext *context.BDDContext
}

// NewMessagingControllerSteps return new steps for messaging using controller/REST binding
func NewMessagingControllerSteps(ctx *context.BDDContext) *ControllerSteps {
	return &ControllerSteps{
		bddContext: ctx,
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
	err = sendHTTP(http.MethodPost, destination+registerMsgService, params, nil)
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
		err := sendHTTP(http.MethodPost, destination+unregisterMsgService, params, nil)
		if err != nil {
			return fmt.Errorf("failed to unregister message service[%s] for agent[%s]: %w", svcName, agentID, err)
		}
	}

	return nil
}

func (d *ControllerSteps) getServicesList(url string) ([]string, error) {
	result := messaging.RegisteredServicesResponse{}
	// call controller
	err := sendHTTP(http.MethodGet, url, nil, &result)
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

	logger.Debugf("Sending message to agent[%s], message:[%s]", toAgentID, string(rawBytes))

	request := &messaging.SendNewMessageArgs{
		ConnectionID: connID,
		MessageBody:  rawBytes,
	}

	// call controller to send message
	err = sendHTTP(http.MethodPost, destination+sendNewMsg, request, nil)
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
	var response models.QueryConnectionsResponse

	err := sendHTTP(http.MethodGet, destination+queryConnections+"?state=completed", nil, &response)
	if err != nil {
		return "", fmt.Errorf("failed to query connections : %w", err)
	}

	if len(response.Results) == 0 {
		return "", fmt.Errorf("no connection found, for agents '%s'", agentID)
	}

	return response.Results[0].ConnectionID, nil
}

func (d *ControllerSteps) receiveMessage(
	agentID, expectedMsgType string) (*service.DIDCommMsgMap, error) {
	msg, err := d.pullMsgFromWebhook(agentID)
	if err != nil {
		return nil, fmt.Errorf("failed to pull incoming message from webhook : %w", err)
	}

	incomingMsg := struct {
		Message  service.DIDCommMsgMap `json:"message"`
		MyDID    string                `json:"mydid"`
		TheirDID string                `json:"theirdid"`
	}{}

	err = msg.Decode(&incomingMsg)
	if err != nil {
		return nil, fmt.Errorf("failed to read message: %w", err)
	}

	if incomingMsg.Message.Type() != expectedMsgType {
		return nil, fmt.Errorf("expected incoming message of type [%s], but got [%s]", expectedMsgType,
			incomingMsg.Message.Type())
	}

	return &incomingMsg.Message, nil
}

func (d *ControllerSteps) pullMsgFromWebhook(agentID string) (*service.DIDCommMsgMap, error) {
	webhookURL, ok := d.bddContext.GetWebhookURL(agentID)
	if !ok {
		return nil, fmt.Errorf("unable to find webhook URL for agent [%s]", agentID)
	}

	msg := service.DIDCommMsgMap{}

	// try to pull recently pushed topics from webhook
	for i := 0; i < pullTopicsAttemptsBeforeFail; i++ {
		err := sendHTTP(http.MethodGet, webhookURL+checkForTopics, nil, &msg)
		if err != nil {
			return nil, fmt.Errorf("failed pull topics from webhook, cause : %w", err)
		}

		if len(msg) > 0 {
			return &msg, nil
		}

		time.Sleep(pullTopicsWaitInMilliSec * time.Millisecond)
	}

	return nil, fmt.Errorf("exhausted all [%d] attempts to pull topics from webhook", pullTopicsAttemptsBeforeFail)
}

func sendHTTP(method, destination string, param, result interface{}) error {
	message, err := json.Marshal(param)
	if err != nil {
		return fmt.Errorf("failed to prepare params : %w", err)
	}

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

func (d *ControllerSteps) receiveInviteMessage(agentID, expectedMsg, expectedMsgType, from string) error {
	msg, err := d.receiveMessage(agentID, expectedMsgType)
	if err != nil {
		return err
	}

	invite := genericInviteMsg{}

	err = msg.Decode(&invite)
	if err != nil {
		return fmt.Errorf("failed to read incoming invite message: %w", err)
	}

	if invite.Message != expectedMsg {
		return fmt.Errorf("expected message [%s], but got [%s]", expectedMsg, invite.Message)
	}

	if invite.From != from {
		return fmt.Errorf("expected message from [%s], but got from[%s]", from, invite.From)
	}

	return nil
}

func (d *ControllerSteps) receiveBasicMessage(agentID, expectedMsg, from string) error {
	msg, err := d.receiveMessage(agentID, basic.MessageRequestType)
	if err != nil {
		return err
	}

	basicMsg := basic.Message{}

	err = msg.Decode(&basicMsg)
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

func closeResponse(c io.Closer) {
	err := c.Close()
	if err != nil {
		logger.Errorf("Failed to close response body : %s", err)
	}
}

// RegisterSteps registers messaging steps
func (d *ControllerSteps) RegisterSteps(s *godog.Suite) { //nolint dupl
	// generic messaging
	s.Step(`^"([^"]*)" registers a message service through controller with name "([^"]*)" for type "([^"]*)"`+
		` and purpose "([^"]*)"$`, d.registerMsgService)
	s.Step(`^"([^"]*)" sends meeting invite message "([^"]*)" through controller with type "([^"]*)" `+
		`and purpose "([^"]*)" to "([^"]*)"$`, d.sendInviteMessage)
	s.Step(`^"([^"]*)" message service receives meeting invite message to webhook "([^"]*)" with type "([^"]*)"`+
		` from "([^"]*)"$`, d.receiveInviteMessage)

	// basic messaging
	s.Step(`^"([^"]*)" registers a message service through controller with name "([^"]*)" for basic message type$`,
		d.registerBasicMsgService)
	s.Step(`^"([^"]*)" sends basic message "([^"]*)" through controller to "([^"]*)"$`, d.sendBasicMessage)
	s.Step(`^"([^"]*)" receives basic message to webhook "([^"]*)" from "([^"]*)"$`, d.receiveBasicMessage)
}
