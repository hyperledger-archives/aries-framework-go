/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import protocol "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"

// issueCredentialAcceptProposalRequest model
//
// This is used for operation to accept proposal
//
// swagger:parameters issueCredentialAcceptProposal
type issueCredentialAcceptProposalRequest struct { // nolint: unused,deadcode
	// Protocol instance ID
	//
	// in: path
	// required: true
	PIID string `json:"piid"`

	// in: body
	// required: true
	OfferCredential protocol.OfferCredential `json:""`
}

// issueCredentialAcceptProposalResponse model
//
// Represents a AcceptProposal response message
//
// swagger:response issueCredentialAcceptProposalResponse
type issueCredentialAcceptProposalResponse struct{} // nolint: unused,deadcode

// issueCredentialAcceptOfferRequest model
//
// This is used for operation to accept an offer
//
// swagger:parameters issueCredentialAcceptOffer
type issueCredentialAcceptOfferRequest struct { // nolint: unused,deadcode
	// Protocol instance ID
	//
	// in: path
	// required: true
	PIID string `json:"piid"`
}

// issueCredentialAcceptOfferResponse model
//
// Represents a AcceptOffer response message
//
// swagger:response issueCredentialAcceptOfferResponse
type issueCredentialAcceptOfferResponse struct{} // nolint: unused,deadcode

// issueCredentialAcceptRequestRequest model
//
// This is used for operation to accept a request
//
// swagger:parameters issueCredentialAcceptRequest
type issueCredentialAcceptRequestRequest struct { // nolint: unused,deadcode
	// Protocol instance ID
	//
	// in: path
	// required: true
	PIID string `json:"piid"`

	// in: body
	// required: true
	IssueCredential protocol.IssueCredential `json:""`
}

// issueCredentialAcceptRequestResponse model
//
// Represents a AcceptRequest response message
//
// swagger:response issueCredentialAcceptRequestResponse
type issueCredentialAcceptRequestResponse struct{} // nolint: unused,deadcode

// issueCredentialAcceptCredentialRequest model
//
// This is used for operation to accept a credential
//
// swagger:parameters issueCredentialAcceptCredential
type issueCredentialAcceptCredentialRequest struct { // nolint: unused,deadcode
	// Protocol instance ID
	//
	// in: path
	// required: true
	PIID string `json:"piid"`

	// in: body
	// required: true
	Names []string `json:""`
}

// issueCredentialAcceptCredentialResponse model
//
// Represents a AcceptCredential response message
//
// swagger:response issueCredentialAcceptCredentialResponse
type issueCredentialAcceptCredentialResponse struct{} // nolint: unused,deadcode

// issueCredentialDeclineCredentialRequest model
//
// This is used for operation to decline a credential
//
// swagger:parameters issueCredentialDeclineCredential
type issueCredentialDeclineCredentialRequest struct { // nolint: unused,deadcode
	// Protocol instance ID
	//
	// in: path
	// required: true
	PIID string `json:"piid"`

	// Reason is an explanation of why it was declined
	Reason string `json:"reason"`
}

// issueCredentialDeclineCredentialResponse model
//
// Represents a DeclineCredential response message
//
// swagger:response issueCredentialDeclineCredentialResponse
type issueCredentialDeclineCredentialResponse struct{} // nolint: unused,deadcode

// issueCredentialDeclineRequestRequest model
//
// This is used for operation to decline a request
//
// swagger:parameters issueCredentialDeclineRequest
type issueCredentialDeclineRequestRequest struct { // nolint: unused,deadcode
	// Protocol instance ID
	//
	// in: path
	// required: true
	PIID string `json:"piid"`

	// Reason is an explanation of why it was declined
	Reason string `json:"reason"`
}

// issueCredentialDeclineRequestResponse model
//
// Represents a DeclineRequest response message
//
// swagger:response issueCredentialDeclineRequestResponse
type issueCredentialDeclineRequestResponse struct{} // nolint: unused,deadcode

// issueCredentialDeclineOfferRequest model
//
// This is used for operation to decline an Offer
//
// swagger:parameters issueCredentialDeclineOffer
type issueCredentialDeclineOfferRequest struct { // nolint: unused,deadcode
	// Protocol instance ID
	//
	// in: path
	// required: true
	PIID string `json:"piid"`

	// Reason is an explanation of why it was declined
	Reason string `json:"reason"`
}

// issueCredentialDeclineOfferResponse model
//
// Represents a DeclineOffer response message
//
// swagger:response issueCredentialDeclineOfferResponse
type issueCredentialDeclineOfferResponse struct{} // nolint: unused,deadcode

// issueCredentialDeclineProposalRequest model
//
// This is used for operation to decline a proposal
//
// swagger:parameters issueCredentialDeclineProposal
type issueCredentialDeclineProposalRequest struct { // nolint: unused,deadcode
	// Protocol instance ID
	//
	// in: path
	// required: true
	PIID string `json:"piid"`

	// Reason is an explanation of why it was declined
	Reason string `json:"reason"`
}

// issueCredentialDeclineProposalResponse model
//
// Represents a DeclineProposal response message
//
// swagger:response issueCredentialDeclineProposalResponse
type issueCredentialDeclineProposalResponse struct{} // nolint: unused,deadcode

// issueCredentialNegotiateProposalRequest model
//
// This is used for operation when the Holder wants to negotiate about an offer he received.
//
// swagger:parameters issueCredentialNegotiateProposal
type issueCredentialNegotiateProposalRequest struct { // nolint: unused,deadcode
	// Protocol instance ID
	//
	// in: path
	// required: true
	PIID string `json:"piid"`

	// in: body
	// required: true
	ProposeCredential protocol.ProposeCredential `json:""`
}

// issueCredentialNegotiateProposalResponse model
//
// Represents a NegotiateProposal response message
//
// swagger:response issueCredentialNegotiateProposalResponse
type issueCredentialNegotiateProposalResponse struct{} // nolint: unused,deadcode

// issueCredentialActionsRequest model
//
// Returns pending actions that have not yet to be executed or cancelled.
//
// swagger:parameters issueCredentialActions
type issueCredentialActionsRequest struct{} // nolint: unused,deadcode

// issueCredentialActionsResponse model
//
// Represents a Actions response message
//
// swagger:response issueCredentialActionsResponse
type issueCredentialActionsResponse struct { // nolint: unused,deadcode
	// in: body
	Actions []protocol.Action `json:"actions"`
}

// issueCredentialSendOfferRequest model
//
// This is used for operation to send an offer.
//
// swagger:parameters issueCredentialSendOffer
type issueCredentialSendOfferRequest struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		// MyDID sender's did
		// required: true
		MyDID string `json:"my_did"`
		// TheirDID receiver's did
		// required: true
		TheirDID string `json:"their_did"`
		// OfferCredential is a message describing the credential intend to offer and
		// possibly the price they expect to be paid.
		// required: true
		OfferCredential *protocol.OfferCredential `json:"offer_credential"`
	}
}

// issueCredentialSendOfferResponse model
//
// Represents a SendOffer response message
//
// swagger:response issueCredentialSendOfferResponse
type issueCredentialSendOfferResponse struct{} // nolint: unused,deadcode

// issueCredentialSendProposalRequest model
//
// This is used for operation to send a proposal
//
// swagger:parameters issueCredentialSendProposal
type issueCredentialSendProposalRequest struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		// MyDID sender's did
		// required: true
		MyDID string `json:"my_did"`
		// TheirDID receiver's did
		// required: true
		TheirDID string `json:"their_did"`
		// ProposeCredential is a message sent by the potential Holder to the Issuer to initiate the protocol
		// required: true
		ProposeCredential *protocol.ProposeCredential `json:"propose_credential"`
	}
}

// issueCredentialSendProposalResponse model
//
// Represents a SendProposal response message
//
// swagger:response issueCredentialSendProposalResponse
type issueCredentialSendProposalResponse struct{} // nolint: unused,deadcode

// issueCredentialSendRequestRequest model
//
// This is used for operation to send a request
//
// swagger:parameters issueCredentialSendRequest
type issueCredentialSendRequestRequest struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		// MyDID sender's did
		// required: true
		MyDID string `json:"my_did"`
		// TheirDID receiver's did
		// required: true
		TheirDID string `json:"their_did"`
		// RequestCredential is a message sent by the potential Holder to the Issuer,
		// to request the issuance of a credential.
		// required: true
		RequestCredential *protocol.RequestCredential `json:"request_credential"`
	}
}

// issueCredentialSendRequestResponse model
//
// Represents a SendRequest response message
//
// swagger:response issueCredentialSendRequestResponse
type issueCredentialSendRequestResponse struct{} // nolint: unused,deadcode
