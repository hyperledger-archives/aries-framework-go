/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	protocol "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/introduce"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"
)

// introduceActionsRequest model
//
// Returns pending actions that have not yet to be executed or cancelled.
//
// swagger:parameters introduceActions
type introduceActionsRequest struct{} // nolint: unused,deadcode

// introduceActionsResponse model
//
// Represents Actions response message.
//
// swagger:response introduceActionsResponse
type introduceActionsResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		Actions []protocol.Action `json:"actions"`
	}
}

// introduceSendProposalRequest model
//
// This is used for operation to send a proposal.
//
// swagger:parameters introduceSendProposal
type introduceSendProposalRequest struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		Recipients []*protocol.Recipient `json:"recipients"`
	}
}

// introduceSendProposalResponse model
//
// Represents a SendProposal response message.
//
// swagger:response introduceSendProposalResponse
type introduceSendProposalResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct{}
}

// introduceSendProposalWithOOBRequest model
//
// This is used for operation to send a proposal with OOBRequest.
//
// swagger:parameters introduceSendProposalWithOOBRequest
type introduceSendProposalWithOOBRequest struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		// Request is the out-of-band protocol's 'request' message.
		// required: true
		Request *outofband.Request `json:"request"`
		// Recipient specifies to whom proposal will be sent
		// required: true
		Recipient *protocol.Recipient `json:"recipient"`
	}
}

// introduceSendProposalWithOOBRequestResponse model
//
// Represents a SendProposalWithOOBRequest response message.
//
// swagger:response introduceSendProposalWithOOBRequestResponse
type introduceSendProposalWithOOBRequestResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct{}
}

// introduceAcceptProposalWithOOBRequest model
//
// This is used for operation to accept a proposal with OOBRequest.
//
// swagger:parameters introduceAcceptProposalWithOOBRequest
type introduceAcceptProposalWithOOBRequest struct { // nolint: unused,deadcode
	// Protocol instance ID
	//
	// in: path
	// required: true
	PIID string `json:"piid"`
	// in: body
	Body struct {
		// Request is the out-of-band protocol's 'request' message.
		Request *outofband.Request `json:"request"`
	}
}

// introduceAcceptProposalWithOOBRequestResponse model
//
// Represents a AcceptProposalWithOOBRequest response message.
//
// swagger:response introduceAcceptProposalWithOOBRequestResponse
type introduceAcceptProposalWithOOBRequestResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct{}
}

// introduceAcceptRequestWithPublicOOBRequest model
//
// This is used for operation to accept a request with public OOBRequest.
//
// swagger:parameters introduceAcceptRequestWithPublicOOBRequest
type introduceAcceptRequestWithPublicOOBRequest struct { // nolint: unused,deadcode
	// Protocol instance ID
	//
	// in: path
	// required: true
	PIID string `json:"piid"`
	// in: body
	Body struct {
		// Request is the out-of-band protocol's 'request' message.
		Request *outofband.Request `json:"request"`
		// To keeps information about the introduction
		To *protocol.To `json:"to"`
	}
}

// introduceAcceptRequestWithPublicOOBRequestResponse model
//
// Represents a AcceptRequestWithPublicOOBRequest response message.
//
// swagger:response introduceAcceptRequestWithPublicOOBRequestResponse
type introduceAcceptRequestWithPublicOOBRequestResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct{}
}

// introduceAcceptRequestWithRecipients model
//
// This is used for operation to accept a request with recipients.
//
// swagger:parameters introduceAcceptRequestWithRecipients
type introduceAcceptRequestWithRecipients struct { // nolint: unused,deadcode
	// Protocol instance ID
	//
	// in: path
	// required: true
	PIID string `json:"piid"`
	// in: body
	Body struct {
		// Recipient specifies to whom proposal will be sent
		Recipient *protocol.Recipient `json:"recipient"`
		// To keeps information about the introduction
		To *protocol.To `json:"to"`
	}
}

// introduceAcceptRequestWithRecipientsResponse model
//
// Represents a AcceptRequestWithRecipients response message.
//
// swagger:response introduceAcceptRequestWithRecipientsResponse
type introduceAcceptRequestWithRecipientsResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct{}
}

// introduceSendRequest model
//
// This is used for operation to send a request.
//
// swagger:parameters introduceSendRequest
type introduceSendRequest struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		// MyDID sender's did
		// required: true
		MyDID string `json:"my_did"`
		// TheirDID receiver's did
		// required: true
		TheirDID string `json:"their_did"`
		// PleaseIntroduceTo keeps information about the introduction
		// required: true
		PleaseIntroduceTo *protocol.PleaseIntroduceTo `json:"please_introduce_to"`
	}
}

// introduceSendRequestResponse model
//
// Represents a SendRequest response message.
//
// swagger:response introduceSendRequestResponse
type introduceSendRequestResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct{}
}

// introduceDeclineProposalRequest model
//
// This is used for operation to decline a proposal.
//
// swagger:parameters introduceDeclineProposal
type introduceDeclineProposalRequest struct { // nolint: unused,deadcode
	// Protocol instance ID
	//
	// in: path
	// required: true
	PIID string `json:"piid"`

	// Reason is an explanation of why it was declined
	Reason string `json:"reason"`
}

// introduceDeclineProposalResponse model
//
// Represents a DeclineProposal response message.
//
// swagger:response introduceDeclineProposalResponse
type introduceDeclineProposalResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct{}
}

// introduceDeclineRequest model
//
// This is used for operation to decline a request.
//
// swagger:parameters introduceDeclineRequest
type introduceDeclineRequest struct { // nolint: unused,deadcode
	// Protocol instance ID
	//
	// in: path
	// required: true
	PIID string `json:"piid"`

	// Reason is an explanation of why it was declined
	Reason string `json:"reason"`
}

// introduceDeclineRequestResponse model
//
// Represents a DeclineRequest response message.
//
// swagger:response introduceDeclineRequestResponse
type introduceDeclineRequestResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct{}
}

// introduceAcceptProposalRequest model
//
// This is used for operation to accept a proposal.
//
// swagger:parameters introduceAcceptProposal
type introduceAcceptProposalRequest struct { // nolint: unused,deadcode
	// Protocol instance ID
	//
	// in: path
	// required: true
	PIID string `json:"piid"`
}

// introduceAcceptProposalResponse model
//
// Represents a AcceptProposal response message.
//
// swagger:response introduceAcceptProposalResponse
type introduceAcceptProposalResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct{}
}
