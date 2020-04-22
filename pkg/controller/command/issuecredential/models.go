/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import "github.com/hyperledger/aries-framework-go/pkg/client/issuecredential"

// AcceptProposalArgs model
//
// This is used for accepting proposal
//
type AcceptProposalArgs struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// OfferCredential is a message describing the credential intend to offer and
	// possibly the price they expect to be paid.
	OfferCredential *issuecredential.OfferCredential `json:"offer_credential"`
}

// AcceptProposalResponse model
//
// Represents a AcceptProposal response message
//
type AcceptProposalResponse struct{}

// AcceptOfferArgs model
//
// This is used for accepting an offer
//
type AcceptOfferArgs struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
}

// AcceptOfferResponse model
//
// Represents a AcceptOffer response message
//
type AcceptOfferResponse struct{}

// AcceptRequestArgs model
//
// This is used for accepting a request
//
type AcceptRequestArgs struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// IssueCredential contains as attached payload the credentials being issued
	IssueCredential *issuecredential.IssueCredential `json:"issue_credential"`
}

// AcceptRequestResponse model
//
// Represents a AcceptRequest response message
//
type AcceptRequestResponse struct{}

// AcceptCredentialArgs model
//
// This is used for accepting a credential
//
type AcceptCredentialArgs struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// Names represent the names of how credentials will be stored
	Names []string `json:"names"`
}

// AcceptCredentialResponse model
//
// Represents a AcceptCredential response message
//
type AcceptCredentialResponse struct{}

// NegotiateProposalArgs model
//
// This is used when the Holder wants to negotiate about an offer he received.
//
type NegotiateProposalArgs struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// ProposeCredential is a message sent in response to a offer-credential message when the Holder
	// wants some adjustments made to the credential data offered by Issuer.
	ProposeCredential *issuecredential.ProposeCredential `json:"propose_credential"`
}

// NegotiateProposalResponse model
//
// Represents a NegotiateProposal response message
//
type NegotiateProposalResponse struct{}

// DeclineProposalArgs model
//
// This is used when proposal needs to be rejected
//
type DeclineProposalArgs struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// Reason why proposal is declined
	Reason string `json:"reason"`
}

// DeclineProposalResponse model
//
// Represents a DeclineProposal response message
//
type DeclineProposalResponse struct{}

// DeclineOfferArgs model
//
// This is used when offer needs to be rejected
//
type DeclineOfferArgs struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// Reason why offer is declined
	Reason string `json:"reason"`
}

// DeclineOfferResponse model
//
// Represents a DeclineOffer response message
//
type DeclineOfferResponse struct{}

// DeclineRequestArgs model
//
// This is used when request needs to be rejected
//
type DeclineRequestArgs struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// Reason why request is declined
	Reason string `json:"reason"`
}

// DeclineRequestResponse model
//
// Represents a DeclineRequest response message
//
type DeclineRequestResponse struct{}

// DeclineCredentialArgs model
//
// This is used when credential needs to be rejected
//
type DeclineCredentialArgs struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// Reason why credential is declined
	Reason string `json:"reason"`
}

// DeclineCredentialResponse model
//
// Represents a DeclineCredential response message
//
type DeclineCredentialResponse struct{}

// SendProposalArgs model
//
// This is used for sending a proposal to initiate the protocol
//
type SendProposalArgs struct {
	// MyDID sender's did
	MyDID string `json:"my_did"`
	// TheirDID receiver's did
	TheirDID string `json:"their_did"`
	// ProposeCredential is a message sent by the potential Holder to the Issuer to initiate the protocol
	ProposeCredential *issuecredential.ProposeCredential `json:"propose_credential"`
}

// SendProposalResponse model
//
// Represents a SendProposal response message
//
type SendProposalResponse struct{}

// SendOfferArgs model
//
// This is used for sending an offer
//
type SendOfferArgs struct {
	// MyDID sender's did
	MyDID string `json:"my_did"`
	// TheirDID receiver's did
	TheirDID string `json:"their_did"`
	// OfferCredential is a message describing the credential intend to offer and
	// possibly the price they expect to be paid.
	OfferCredential *issuecredential.OfferCredential `json:"offer_credential"`
}

// SendOfferResponse model
//
// Represents a SendOffer response message
//
type SendOfferResponse struct{}

// SendRequestArgs model
//
// This is used for sending a request
//
type SendRequestArgs struct {
	// MyDID sender's did
	MyDID string `json:"my_did"`
	// TheirDID receiver's did
	TheirDID string `json:"their_did"`
	// RequestCredential is a message sent by the potential Holder to the Issuer,
	// to request the issuance of a credential.
	RequestCredential *issuecredential.RequestCredential `json:"request_credential"`
}

// SendRequestResponse model
//
// Represents a SendRequest response message
//
type SendRequestResponse struct{}

// ActionsResponse model
//
// Represents Actions response message
//
type ActionsResponse struct {
	Actions []issuecredential.Action `json:"actions"`
}
