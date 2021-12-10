/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import "github.com/hyperledger/aries-framework-go/pkg/client/issuecredential"

// AcceptProposalArgs model
//
// This is used for accepting proposal.
//
type AcceptProposalArgs struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// OfferCredential is a message describing the credential intend to offer and
	// possibly the price they expect to be paid.
	OfferCredential *issuecredential.OfferCredential `json:"offer_credential"`
}

// AcceptProposalArgsV2 model
//
// This is used for accepting proposal.
//
type AcceptProposalArgsV2 struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// OfferCredential is a message describing the credential intend to offer and
	// possibly the price they expect to be paid.
	OfferCredential *issuecredential.OfferCredentialV2 `json:"offer_credential"`
}

// AcceptProposalArgsV3 model
//
// This is used for accepting proposal.
//
type AcceptProposalArgsV3 struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// OfferCredential is a message describing the credential intend to offer and
	// possibly the price they expect to be paid.
	OfferCredential *issuecredential.OfferCredentialV3 `json:"offer_credential"`
}

// AcceptProposalResponse model
//
// Represents a AcceptProposal response message.
//
type AcceptProposalResponse struct{}

// AcceptOfferArgs model
//
// This is used for accepting an offer.
//
type AcceptOfferArgs struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
}

// AcceptOfferResponse model
//
// Represents a AcceptOffer response message.
//
type AcceptOfferResponse struct{}

// AcceptRequestArgs model
//
// This is used for accepting a request.
//
type AcceptRequestArgs struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// IssueCredential contains as attached payload the credentials being issued
	IssueCredential *issuecredential.IssueCredential `json:"issue_credential"`
}

// AcceptRequestArgsV2 model
//
// This is used for accepting a request.
//
type AcceptRequestArgsV2 struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// IssueCredential contains as attached payload the credentials being issued
	IssueCredential *issuecredential.IssueCredentialV2 `json:"issue_credential"`
}

// AcceptRequestArgsV3 model
//
// This is used for accepting a request.
//
type AcceptRequestArgsV3 struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// IssueCredential contains as attached payload the credentials being issued
	IssueCredential *issuecredential.IssueCredentialV3 `json:"issue_credential"`
}

// AcceptRequestResponse model
//
// Represents a AcceptRequest response message.
//
type AcceptRequestResponse struct{}

// AcceptCredentialArgs model
//
// This is used for accepting a credential.
//
type AcceptCredentialArgs struct {
	// PIID Protocol instance ID.
	PIID string `json:"piid"`
	// Names represent the names of how credentials will be stored.
	Names []string `json:"names"`
	// SkipStore if true then credential will not be saved in agent's verifiable store,
	// but protocol state will be updated.
	SkipStore bool `json:"skipStore"`
}

// AcceptCredentialResponse model
//
// Represents a AcceptCredential response message.
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

// NegotiateProposalArgsV2 model
//
// This is used when the Holder wants to negotiate about an offer he received.
//
type NegotiateProposalArgsV2 struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// ProposeCredential is a message sent in response to a offer-credential message when the Holder
	// wants some adjustments made to the credential data offered by Issuer.
	ProposeCredential *issuecredential.ProposeCredentialV2 `json:"propose_credential"`
}

// NegotiateProposalArgsV3 model
//
// This is used when the Holder wants to negotiate about an offer he received.
//
type NegotiateProposalArgsV3 struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// ProposeCredential is a message sent in response to a offer-credential message when the Holder
	// wants some adjustments made to the credential data offered by Issuer.
	ProposeCredential *issuecredential.ProposeCredentialV3 `json:"propose_credential"`
}

// NegotiateProposalResponse model
//
// Represents a NegotiateProposal response message.
//
type NegotiateProposalResponse struct{}

// DeclineProposalArgs model
//
// This is used when proposal needs to be rejected.
//
type DeclineProposalArgs struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// Reason why proposal is declined
	Reason string `json:"reason"`
	// RedirectURL is optional web redirect URL that can be sent to holder.
	// Useful in cases where issuer would like holder to redirect after its proposal gets declined.
	RedirectURL string `json:"redirectURL"`
}

// DeclineProposalResponse model
//
// Represents a DeclineProposal response message.
//
type DeclineProposalResponse struct{}

// DeclineOfferArgs model
//
// This is used when offer needs to be rejected.
//
type DeclineOfferArgs struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// Reason why offer is declined
	Reason string `json:"reason"`
}

// DeclineOfferResponse model
//
// Represents a DeclineOffer response message.
//
type DeclineOfferResponse struct{}

// DeclineRequestArgs model
//
// This is used when request needs to be rejected.
//
type DeclineRequestArgs struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// Reason why request is declined
	Reason string `json:"reason"`
	// RedirectURL is optional web redirect URL that can be sent to holder.
	// Useful in cases where issuer would like holder to redirect after its credential request gets declined.
	RedirectURL string `json:"redirectURL"`
}

// DeclineRequestResponse model
//
// Represents a DeclineRequest response message.
//
type DeclineRequestResponse struct{}

// DeclineCredentialArgs model
//
// This is used when credential needs to be rejected.
//
type DeclineCredentialArgs struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// Reason why credential is declined
	Reason string `json:"reason"`
}

// DeclineCredentialResponse model
//
// Represents a DeclineCredential response message.
//
type DeclineCredentialResponse struct{}

// SendProposalArgs model
//
// This is used for sending a proposal to initiate the protocol.
//
type SendProposalArgs struct {
	// MyDID sender's did
	MyDID string `json:"my_did"`
	// TheirDID receiver's did
	TheirDID string `json:"their_did"`
	// ProposeCredential is a message sent by the potential Holder to the Issuer to initiate the protocol
	ProposeCredential *issuecredential.ProposeCredential `json:"propose_credential"`
}

// SendProposalArgsV2 model
//
// This is used for sending a proposal to initiate the protocol.
//
type SendProposalArgsV2 struct {
	// MyDID sender's did
	MyDID string `json:"my_did"`
	// TheirDID receiver's did
	TheirDID string `json:"their_did"`
	// ProposeCredential is a message sent by the potential Holder to the Issuer to initiate the protocol
	ProposeCredential *issuecredential.ProposeCredentialV2 `json:"propose_credential"`
}

// SendProposalArgsV3 model
//
// This is used for sending a proposal to initiate the protocol.
//
type SendProposalArgsV3 struct {
	// MyDID sender's did
	MyDID string `json:"my_did"`
	// TheirDID receiver's did
	TheirDID string `json:"their_did"`
	// ProposeCredential is a message sent by the potential Holder to the Issuer to initiate the protocol
	ProposeCredential *issuecredential.ProposeCredentialV3 `json:"propose_credential"`
}

// SendProposalResponse model
//
// Represents a SendProposal response message.
//
type SendProposalResponse struct {
	// PIID Protocol instance ID. It can be used as a correlation ID
	PIID string `json:"piid"`
}

// SendOfferArgs model
//
// This is used for sending an offer.
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

// SendOfferArgsV2 model
//
// This is used for sending an offer.
//
type SendOfferArgsV2 struct {
	// MyDID sender's did
	MyDID string `json:"my_did"`
	// TheirDID receiver's did
	TheirDID string `json:"their_did"`
	// OfferCredential is a message describing the credential intend to offer and
	// possibly the price they expect to be paid.
	OfferCredential *issuecredential.OfferCredentialV2 `json:"offer_credential"`
}

// SendOfferArgsV3 model
//
// This is used for sending an offer.
//
type SendOfferArgsV3 struct {
	// MyDID sender's did
	MyDID string `json:"my_did"`
	// TheirDID receiver's did
	TheirDID string `json:"their_did"`
	// OfferCredential is a message describing the credential intend to offer and
	// possibly the price they expect to be paid.
	OfferCredential *issuecredential.OfferCredentialV3 `json:"offer_credential"`
}

// SendOfferResponse model
//
// Represents a SendOffer response message.
//
type SendOfferResponse struct {
	// PIID Protocol instance ID. It can be used as a correlation ID
	PIID string `json:"piid"`
}

// SendRequestArgs model
//
// This is used for sending a request.
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

// SendRequestArgsV2 model
//
// This is used for sending a request.
//
type SendRequestArgsV2 struct {
	// MyDID sender's did
	MyDID string `json:"my_did"`
	// TheirDID receiver's did
	TheirDID string `json:"their_did"`
	// RequestCredential is a message sent by the potential Holder to the Issuer,
	// to request the issuance of a credential.
	RequestCredential *issuecredential.RequestCredentialV2 `json:"request_credential"`
}

// SendRequestArgsV3 model
//
// This is used for sending a request.
//
type SendRequestArgsV3 struct {
	// MyDID sender's did
	MyDID string `json:"my_did"`
	// TheirDID receiver's did
	TheirDID string `json:"their_did"`
	// RequestCredential is a message sent by the potential Holder to the Issuer,
	// to request the issuance of a credential.
	RequestCredential *issuecredential.RequestCredentialV3 `json:"request_credential"`
}

// SendRequestResponse model
//
// Represents a SendRequest response message.
//
type SendRequestResponse struct {
	// PIID Protocol instance ID. It can be used as a correlation ID
	PIID string `json:"piid"`
}

// ActionsResponse model
//
// Represents Actions response message.
//
type ActionsResponse struct {
	Actions []issuecredential.Action `json:"actions"`
}

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
