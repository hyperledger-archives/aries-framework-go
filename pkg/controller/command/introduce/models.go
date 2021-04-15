/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"github.com/hyperledger/aries-framework-go/pkg/client/introduce"
	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
)

// ActionsResponse model
//
// Represents Actions response message.
//
type ActionsResponse struct {
	Actions []introduce.Action `json:"actions"`
}

// SendProposalArgs model
//
// This is used for sending a proposal.
//
type SendProposalArgs struct {
	// Recipients specifies to whom proposal will be sent
	Recipients []*introduce.Recipient `json:"recipients"`
}

// SendProposalResponse model
//
// Represents a SendProposal response message.
//
type SendProposalResponse struct {
	// PIID Protocol instance ID. It can be used as a correlation ID
	PIID string `json:"piid"`
}

// SendProposalWithOOBInvitationArgs model
//
// This is used for sending a proposal with OOBRequest.
//
type SendProposalWithOOBInvitationArgs struct {
	// Invitation is the out-of-band protocol's 'invitation' message.
	Invitation *outofband.Invitation `json:"invitation"`
	// Recipient specifies to whom proposal will be sent
	Recipient *introduce.Recipient `json:"recipient"`
}

// SendProposalWithOOBRequestResponse model
//
// Represents a SendProposalWithOOBInvitation response message.
//
type SendProposalWithOOBRequestResponse struct {
	// PIID Protocol instance ID. It can be used as a correlation ID
	PIID string `json:"piid"`
}

// SendRequestArgs model
//
// This is used for sending a request.
//
type SendRequestArgs struct {
	// PleaseIntroduceTo keeps information about the introduction
	PleaseIntroduceTo *introduce.PleaseIntroduceTo `json:"please_introduce_to"`
	// MyDID sender's did
	MyDID string `json:"my_did"`
	// TheirDID receiver's did
	TheirDID string `json:"their_did"`
}

// SendRequestResponse model
//
// Represents a SendRequest response message.
//
type SendRequestResponse struct {
	// PIID Protocol instance ID. It can be used as a correlation ID
	PIID string `json:"piid"`
}

// AcceptProposalWithOOBInvitationArgs model
//
// This is used for accepting a proposal with public OOBRequest.
//
type AcceptProposalWithOOBInvitationArgs struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// Invitation is the out-of-band protocol's 'request' message.
	Invitation *outofband.Invitation `json:"invitation"`
}

// AcceptProposalWithOOBInvitationResponse model
//
// Represents a AcceptProposalWithOOBInvitation response message.
//
type AcceptProposalWithOOBInvitationResponse struct{}

// AcceptRequestWithPublicOOBInvitationArgs model
//
// This is used for accepting a request with public OOBRequest.
//
type AcceptRequestWithPublicOOBInvitationArgs struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// Invitation is the out-of-band protocol's 'request' message.
	Invitation *outofband.Invitation `json:"invitation"`
	// To keeps information about the introduction
	To *introduce.To `json:"to"`
}

// AcceptRequestWithPublicOOBInvitationResponse model
//
// Represents a AcceptRequestWithPublicOOBInvitation response message.
//
type AcceptRequestWithPublicOOBInvitationResponse struct{}

// AcceptRequestWithRecipientsArgs model
//
// This is used for accepting a request with recipients.
//
type AcceptRequestWithRecipientsArgs struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// Recipient specifies to whom proposal will be sent
	Recipient *introduce.Recipient `json:"recipient"`
	// To keeps information about the introduction
	To *introduce.To `json:"to"`
}

// AcceptRequestWithRecipientsResponse model
//
// Represents a AcceptRequestWithRecipients response message.
//
type AcceptRequestWithRecipientsResponse struct{}

// DeclineProposalArgs model
//
// This is used when proposal needs to be rejected.
//
type DeclineProposalArgs struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// Reason why proposal is declined
	Reason string `json:"reason"`
}

// DeclineProposalResponse model
//
// Represents a DeclineProposal response message.
//
type DeclineProposalResponse struct{}

// DeclineRequestArgs model
//
// This is used when request needs to be rejected.
//
type DeclineRequestArgs struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// Reason why request is declined
	Reason string `json:"reason"`
}

// DeclineRequestResponse model
//
// Represents a DeclineRequest response message.
//
type DeclineRequestResponse struct{}

// AcceptProposalArgs model
//
// This is used for accepting a proposal.
//
type AcceptProposalArgs struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
}

// AcceptProposalResponse model
//
// Represents a AcceptProposal response message.
//
type AcceptProposalResponse struct{}

// AcceptProblemReportArgs model
//
// This is used for accepting a problem report.
//
type AcceptProblemReportArgs struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
}

// AcceptProblemReportResponse model
//
// Represents a AcceptProblemReport response message.
//
type AcceptProblemReportResponse struct{}
