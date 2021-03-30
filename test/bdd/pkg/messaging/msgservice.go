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
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
)

const (
	errTimeoutWaitingForMsg = "timeout waiting for incoming message"
)

// genericInviteMsg is the sample generic invite message.
type genericInviteMsg struct {
	ID      string   `json:"@id"`
	Type    string   `json:"@type"`
	Purpose []string `json:"~purpose"`
	Message string   `json:"message"`
	From    string   `json:"from"`
}

// newMessageService returns new message service instance.
func newMessageService(name, msgType string, purpose []string) *msgService {
	return &msgService{
		name:     name,
		msgType:  msgType,
		purpose:  purpose,
		msgQueue: make(chan service.DIDCommMsg),
	}
}

// msgService is basic message service implementation.
type msgService struct {
	name     string
	purpose  []string
	msgType  string
	msgQueue chan service.DIDCommMsg
}

func (m *msgService) Name() string {
	return m.name
}

func (m *msgService) Accept(msgType string, purpose []string) bool {
	purposeMatched, typeMatched := len(m.purpose) == 0, m.msgType == ""

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

func (m *msgService) HandleInbound(msg service.DIDCommMsg, ctx service.DIDCommContext) (string, error) {
	go m.pushMessage(msg)
	return "", nil
}

func (m *msgService) pushMessage(msg service.DIDCommMsg) {
	m.msgQueue <- msg
}

func (m *msgService) popMessage() (*genericInviteMsg, error) {
	const timeout = 5 * time.Second

	select {
	case msg := <-m.msgQueue:
		inviteMsg := genericInviteMsg{}
		err := msg.Decode(&inviteMsg)

		return &inviteMsg, err
	case <-time.After(timeout):
		return nil, fmt.Errorf(errTimeoutWaitingForMsg)
	}
}
