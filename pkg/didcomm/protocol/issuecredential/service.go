/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import (
	"fmt"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	// IssueCredential protocol name
	IssueCredential = "issueCredential"
	// IssueCredentialSpec defines the issue credential spec
	IssueCredentialSpec = "https://didcomm.org/issue-credential/1.0/"
	// RequestMsgType defines the issue-credential request message type.
	RequestMsgType = IssueCredentialSpec + "request"
	// IssueMsgType  defines the issue-credential issue credential message type.
	IssueMsgType = IssueCredentialSpec + "issue"

	// common states
	stateNameNull = "null"

	// issue-credential states
	stateNameRequest = "requested"
	stateNameIssued  = "issued"
)

var logger = log.New("aries-framework/issue-credential/service")

// Service for Issue-credential protocol
type Service struct {
	store              storage.Store
	outboundDispatcher dispatcher.Outbound
}

// Provider contains dependencies for the issue-credential protocol and is typically created by using aries.Context()
type Provider interface {
	OutboundDispatcher() dispatcher.Outbound
	StorageProvider() storage.Provider
}

// New returns issue-credential service
func New(prov Provider) (*Service, error) {
	store, err := prov.StorageProvider().OpenStore(IssueCredential)
	if err != nil {
		return nil, err
	}

	svc := &Service{
		outboundDispatcher: prov.OutboundDispatcher(),
		store:              store,
	}

	return svc, nil
}

// HandleInbound handles inbound message (issue-credential protocol)
func (s *Service) HandleInbound(msg *service.DIDCommMsg) error {
	thID, err := msg.ThreadID()
	if err != nil {
		return err
	}
	current, err := s.currentState(thID)
	if err != nil {
		return err
	}

	next, err := stateFromMsgType(msg.Header.Type)
	if err != nil {
		return err
	}

	if current == stateNameIssued {
		return fmt.Errorf("invalid state transition: %s -> %s", current, next)
	}
	// TODO: Issue-874 call pre-transition listeners and trigger action event based on message type for inbound messages
	err = s.update(thID, next)
	if err != nil {
		return err
	}
	// TODO call post-transition listeners -  Issue: https://github.com/hyperledger/aries-framework-go/issues/874
	return nil
}

func (s *Service) currentState(thid string) (string, error) {
	name, err := s.store.Get(thid)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return stateNameNull, nil
		}
		return "", fmt.Errorf("cannot fetch state from store: thid=%s err=%s", thid, err)
	}
	return string(name), nil
}

func (s *Service) update(thid string, state string) error {
	err := s.store.Put(thid, []byte(state))
	if err != nil {
		return fmt.Errorf("failed to write to store: %s", err)
	}
	return nil
}

// Name returns service name
func (s *Service) Name() string {
	return IssueCredential
}

// Accept msg checks the msg type
func (s *Service) Accept(msgType string) bool {
	switch msgType {
	case RequestMsgType, IssueMsgType:
		return true
	}

	return false
}

// stateFromMsgType returns the state by given name.
func stateFromMsgType(msgType string) (string, error) {
	var s string
	switch msgType {
	case RequestMsgType:
		s = stateNameRequest
	case IssueMsgType:
		s = stateNameIssued
	default:
		return stateNameNull, fmt.Errorf("unrecognized msgType: %s", msgType)
	}
	return s, nil
}
