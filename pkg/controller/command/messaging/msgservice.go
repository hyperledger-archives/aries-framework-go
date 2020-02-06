/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package messaging

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/controller/webhook"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
)

const (
	errMsgSvcHandleFailed = "failed to handle inbound : %w"
	errTopicNotFound      = "failed to get topic to send notification"
)

// handleFunc converts incoming message to topic bytes to be sent.
type handleFunc func(msg service.DIDCommMsg, myDID, theirDID string) ([]byte, error)

// newMessageService returns new message service instance.
func newMessageService(params *RegisterMsgSvcArgs, notifier webhook.Notifier) *msgService {
	return newCustomMessageService(params.Name, params.Type, params.Purpose, notifier, genericHandleFunc())
}

// newCustomMessageService returns new message service instance with custom topic handle for
// handling incoming messages.
func newCustomMessageService(name, msgType string, purpose []string, notifier webhook.Notifier,
	handle handleFunc) *msgService {
	svc := &msgService{
		name:        name,
		msgType:     msgType,
		purpose:     purpose,
		notifier:    notifier,
		topicHandle: handle,
	}

	return svc
}

// msgService is basic message service implementation
// which delegates handling to registered webhook notifier
type msgService struct {
	name        string
	purpose     []string
	msgType     string
	notifier    webhook.Notifier
	topicHandle handleFunc
}

func (m *msgService) Name() string {
	return m.name
}

func (m *msgService) Accept(msgType string, purpose []string) bool {
	var purposeMatched, typeMatched = len(m.purpose) == 0, m.msgType == ""

	if purposeMatched && typeMatched {
		return false
	}

	for _, purposeCriteria := range m.purpose {
		for _, msgPurpose := range purpose {
			if purposeCriteria == msgPurpose {
				purposeMatched = true
				break
			}
		}
	}

	if m.msgType == msgType {
		typeMatched = true
	}

	return purposeMatched && typeMatched
}

func (m *msgService) HandleInbound(msg service.DIDCommMsg, myDID, theirDID string) (string, error) {
	if m.name == "" || m.topicHandle == nil {
		return "", fmt.Errorf(errTopicNotFound)
	}

	bytes, err := m.topicHandle(msg, myDID, theirDID)
	if err != nil {
		return "", fmt.Errorf(errMsgSvcHandleFailed, err)
	}

	return "", m.notifier.Notify(m.name, bytes)
}

// genericHandleFunc handle function for converting incoming messages to generic topic.
func genericHandleFunc() handleFunc {
	return func(msg service.DIDCommMsg, myDID, theirDID string) ([]byte, error) {
		topic := struct {
			Message  interface{} `json:"message"`
			MyDID    string      `json:"mydid"`
			TheirDID string      `json:"theirdid"`
		}{
			msg,
			myDID,
			theirDID,
		}

		return json.Marshal(topic)
	}
}
