/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	// Name defines the protocol name
	Name = "issue-credential"
	// Spec defines the protocol spec
	Spec = "https://didcomm.org/issue-credential/1.0/"
	// ProposeCredentialMsgType defines the protocol propose-credential message type.
	ProposeCredentialMsgType = Spec + "propose-credential"
	// OfferCredentialMsgType defines the protocol offer-credential message type.
	OfferCredentialMsgType = Spec + "offer-credential"
	// RequestCredentialMsgType defines the protocol request-credential message type.
	RequestCredentialMsgType = Spec + "request-credential"
	// IssueCredentialMsgType defines the protocol issue-credential message type.
	IssueCredentialMsgType = Spec + "issue-credential"
	// AckMsgType defines the protocol ack message type.
	AckMsgType = Spec + "ack"
	// ProblemReportMsgType defines the protocol problem-report message type.
	ProblemReportMsgType = Spec + "problem-report"
	// CredentialPreviewMsgType defines the protocol credential-preview inner object type.
	CredentialPreviewMsgType = Spec + "credential-preview"
)

// Provider contains dependencies for the protocol and is typically created by using aries.Context()
type Provider interface {
	Messenger() service.Messenger
	StorageProvider() storage.Provider
}
