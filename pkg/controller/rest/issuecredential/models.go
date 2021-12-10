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
	Body struct {
		// required: true
		OfferCredential struct{ *protocol.OfferCredentialV2 } `json:"offer_credential"`
	}
}

// issueCredentialAcceptProposalRequestV3 model
//
// This is used for operation to accept proposal
//
// swagger:parameters issueCredentialAcceptProposalV3
type issueCredentialAcceptProposalRequestV3 struct { // nolint: unused,deadcode
	// Protocol instance ID
	//
	// in: path
	// required: true
	PIID string `json:"piid"`

	// in: body
	Body struct {
		// required: true
		OfferCredential struct{ *protocol.OfferCredentialV3 } `json:"offer_credential"`
	}
}

// issueCredentialAcceptProposalResponse model
//
// Represents a AcceptProposal response message
//
// swagger:response issueCredentialAcceptProposalResponse
type issueCredentialAcceptProposalResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct{}
}

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
type issueCredentialAcceptOfferResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct{}
}

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
	Body struct {
		// required: true
		IssueCredential struct{ *protocol.IssueCredentialV2 } `json:"issue_credential"`
	}
}

// issueCredentialAcceptRequestRequestV3 model
//
// This is used for operation to accept a request
//
// swagger:parameters issueCredentialAcceptRequestV3
type issueCredentialAcceptRequestRequestV3 struct { // nolint: unused,deadcode
	// Protocol instance ID
	//
	// in: path
	// required: true
	PIID string `json:"piid"`

	// in: body
	Body struct {
		// required: true
		IssueCredential struct{ *protocol.IssueCredentialV3 } `json:"issue_credential"`
	}
}

// issueCredentialAcceptRequestResponse model
//
// Represents a AcceptRequest response message
//
// swagger:response issueCredentialAcceptRequestResponse
type issueCredentialAcceptRequestResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct{}
}

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
	Body struct {
		// required: true
		// Names represent the names of how credentials will be stored.
		Names []string `json:"names"`

		// SkipStore if true then credential will not be saved agent store, but protocol state will be updated.
		SkipStore bool `json:"skipStore"`
	}
}

// issueCredentialAcceptCredentialResponse model
//
// Represents a AcceptCredential response message
//
// swagger:response issueCredentialAcceptCredentialResponse
type issueCredentialAcceptCredentialResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct{}
}

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
type issueCredentialDeclineCredentialResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct{}
}

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

	// RedirectURL is optional web redirect URL that can be sent to holder.
	// Useful in cases where issuer would like holder to redirect after its credential request gets declined.
	RedirectURL string `json:"redirectURL"`
}

// issueCredentialDeclineRequestResponse model
//
// Represents a DeclineRequest response message
//
// swagger:response issueCredentialDeclineRequestResponse
type issueCredentialDeclineRequestResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct{}
}

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
type issueCredentialDeclineOfferResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct{}
}

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

	// RedirectURL is optional web redirect URL that can be sent to holder.
	// Useful in cases where issuer would like holder to redirect after its credential request gets declined.
	RedirectURL string `json:"redirectURL"`
}

// issueCredentialDeclineProposalResponse model
//
// Represents a DeclineProposal response message
//
// swagger:response issueCredentialDeclineProposalResponse
type issueCredentialDeclineProposalResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct{}
}

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
	Body struct {
		// required: true
		ProposeCredential struct{ *protocol.ProposeCredentialV2 } `json:"propose_credential"`
	}
}

// issueCredentialNegotiateProposalRequestV3 model
//
// This is used for operation when the Holder wants to negotiate about an offer he received.
//
// swagger:parameters issueCredentialNegotiateProposalV3
type issueCredentialNegotiateProposalRequestV3 struct { // nolint: unused,deadcode
	// Protocol instance ID
	//
	// in: path
	// required: true
	PIID string `json:"piid"`

	// in: body
	Body struct {
		// required: true
		ProposeCredential struct{ *protocol.ProposeCredentialV3 } `json:"propose_credential"`
	}
}

// issueCredentialNegotiateProposalResponse model
//
// Represents a NegotiateProposal response message
//
// swagger:response issueCredentialNegotiateProposalResponse
type issueCredentialNegotiateProposalResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct{}
}

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
	Body struct {
		Actions []struct{ *protocol.Action } `json:"actions"`
	}
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
		OfferCredential struct{ *protocol.OfferCredentialV2 } `json:"offer_credential"`
	}
}

// issueCredentialSendOfferRequestV3 model
//
// This is used for operation to send an offer.
//
// swagger:parameters issueCredentialSendOfferV3
type issueCredentialSendOfferRequestV3 struct { // nolint: unused,deadcode
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
		OfferCredential struct{ *protocol.OfferCredentialV3 } `json:"offer_credential"`
	}
}

// issueCredentialSendOfferResponse model
//
// Represents a SendOffer response message
//
// swagger:response issueCredentialSendOfferResponse
type issueCredentialSendOfferResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		// PIID Protocol instance ID. It can be used as a correlation ID
		PIID string `json:"piid"`
	}
}

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
		ProposeCredential struct{ *protocol.ProposeCredentialV2 } `json:"propose_credential"`
	}
}

// issueCredentialSendProposalRequestV3 model
//
// This is used for operation to send a proposal
//
// swagger:parameters issueCredentialSendProposalV3
type issueCredentialSendProposalRequestV3 struct { // nolint: unused,deadcode
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
		ProposeCredential struct{ *protocol.ProposeCredentialV3 } `json:"propose_credential"`
	}
}

// issueCredentialSendProposalResponse model
//
// Represents a SendProposal response message
//
// swagger:response issueCredentialSendProposalResponse
type issueCredentialSendProposalResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		// PIID Protocol instance ID. It can be used as a correlation ID
		PIID string `json:"piid"`
	}
}

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
		RequestCredential struct{ *protocol.RequestCredentialV2 } `json:"request_credential"`
	}
}

// issueCredentialSendRequestRequestV3 model
//
// This is used for operation to send a request
//
// swagger:parameters issueCredentialSendRequestV3
type issueCredentialSendRequestRequestV3 struct { // nolint: unused,deadcode
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
		RequestCredential struct{ *protocol.RequestCredentialV3 } `json:"request_credential"`
	}
}

// issueCredentialSendRequestResponse model
//
// Represents a SendRequest response message
//
// swagger:response issueCredentialSendRequestResponse
type issueCredentialSendRequestResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		// PIID Protocol instance ID. It can be used as a correlation ID
		PIID string `json:"piid"`
	}
}

// issueCredentialAcceptProblemReportRequest model
//
// This is used for operation to accept a problem report.
//
// swagger:parameters issueCredentialAcceptProblemReport
type issueCredentialAcceptProblemReportRequest struct { // nolint: unused,deadcode
	// Protocol instance ID
	//
	// in: path
	// required: true
	PIID string `json:"piid"`
}

// issueCredentialAcceptProblemReportResponse model
//
// Represents a AcceptProblemReport response message
//
// swagger:response issueCredentialAcceptProblemReportResponse
type issueCredentialAcceptProblemReportResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct{}
}
