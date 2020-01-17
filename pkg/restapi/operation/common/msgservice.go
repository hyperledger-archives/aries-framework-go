/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/webhook"
)

const (
	errMsgSvcHandleFailed = "failed to handle inbound : %w"
	errTopicNotFound      = "failed to get topic to send notification"
)

// inboundMsg is the message to be sent to message service webhook
type inboundMsg struct {
	Message  service.DIDCommMsgMap `json:"message"`
	MyDID    string                `json:"mydid"`
	TheirDID string                `json:"theirdid"`
}

// newMessageService returns new message service instance
func newMessageService(params *RegisterMsgSvcParams, notifier webhook.Notifier) *msgService {
	return &msgService{
		name:     params.Name,
		purpose:  params.Purpose,
		msgType:  params.Type,
		notifier: notifier,
	}
}

// msgService is basic message service implementation
// which delegates handling to registered webhook notifier
type msgService struct {
	name     string
	purpose  []string
	msgType  string
	notifier webhook.Notifier
}

func (m *msgService) Name() string {
	return m.name
}

func (m *msgService) Accept(header *service.Header) bool {
	var purposeMatched, typeMatched = len(m.purpose) == 0, m.msgType == ""

	if purposeMatched && typeMatched {
		return false
	}

	for _, purposeCriteria := range m.purpose {
		for _, msgPurpose := range header.Purpose {
			if purposeCriteria == msgPurpose {
				purposeMatched = true
				break
			}
		}
	}

	if m.msgType == header.Type {
		typeMatched = true
	}

	return purposeMatched && typeMatched
}

func (m *msgService) HandleInbound(msg service.DIDCommMsg, myDID, theirDID string) (string, error) {
	if m.name == "" {
		return "", fmt.Errorf(errTopicNotFound)
	}

	bytes, err := json.Marshal(&inboundMsg{Message: msg.(service.DIDCommMsgMap), MyDID: myDID, TheirDID: theirDID})
	if err != nil {
		return "", fmt.Errorf(errMsgSvcHandleFailed, err)
	}

	return "", m.notifier.Notify(m.name, bytes)
}
