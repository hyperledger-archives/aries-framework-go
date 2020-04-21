/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

import "github.com/hyperledger/aries-framework-go/pkg/client/presentproof"

// DeclinePresentationArgs model
//
// This is used when the presentation needs to be rejected
//
type DeclinePresentationArgs struct {
	// PIID protocol state machine identifier
	PIID string `json:"piid"`
	// Reason why presentation is declined
	Reason string `json:"reason"`
}

// DeclinePresentationResponse model
//
// Represents a DeclinePresentation response message
//
type DeclinePresentationResponse struct{}

// DeclineProposePresentationArgs model
//
// This is used when proposal needs to be rejected
//
type DeclineProposePresentationArgs struct {
	// PIID protocol state machine identifier
	PIID string `json:"piid"`
	// Reason why proposal is declined
	Reason string `json:"reason"`
}

// DeclineProposePresentationResponse model
//
// Represents a DeclineProposePresentation response message
//
type DeclineProposePresentationResponse struct{}

// DeclineRequestPresentationArgs model
//
// This is used when the request needs to be rejected
//
type DeclineRequestPresentationArgs struct {
	// PIID protocol state machine identifier
	PIID string `json:"piid"`
	// Reason why request is declined
	Reason string `json:"reason"`
}

// DeclineRequestPresentationResponse model
//
// Represents a DeclineRequestPresentation response message
//
type DeclineRequestPresentationResponse struct{}

// ActionsResponse model
//
// Represents Actions response message
//
type ActionsResponse struct {
	Actions []presentproof.Action `json:"actions"`
}

// AcceptPresentationArgs model
//
// This is used for accepting a presentation
//
type AcceptPresentationArgs struct {
	// PIID protocol state machine identifier
	PIID string `json:"piid"`
}

// AcceptPresentationResponse model
//
// Represents a AcceptPresentation response message
//
type AcceptPresentationResponse struct{}

// AcceptRequestPresentationArgs model
//
// This is used for accepting a request presentation
//
type AcceptRequestPresentationArgs struct {
	// PIID protocol state machine identifier
	PIID string `json:"piid"`
	// Presentation is a message that contains signed presentations.
	Presentation *presentproof.Presentation `json:"presentation"`
}

// AcceptRequestPresentationResponse model
//
// Represents a AcceptRequestPresentation response message
//
type AcceptRequestPresentationResponse struct{}

// AcceptProposePresentationArgs model
//
// This is used for accepting a propose presentation
//
type AcceptProposePresentationArgs struct {
	// PIID protocol state machine identifier
	PIID string `json:"piid"`
	// RequestPresentation describes values that need to be revealed and predicates that need to be fulfilled.
	RequestPresentation *presentproof.RequestPresentation `json:"request_presentation"`
}

// AcceptProposePresentationResponse model
//
// Represents a AcceptProposePresentation response message
//
type AcceptProposePresentationResponse struct{}

// NegotiateRequestPresentationArgs model
//
// This is used by the Prover to counter a presentation request they received with a proposal.
//
type NegotiateRequestPresentationArgs struct {
	// PIID protocol state machine identifier
	PIID string `json:"piid"`
	// ProposePresentation is a response message to a request-presentation message when the Prover wants to
	// propose using a different presentation format.
	ProposePresentation *presentproof.ProposePresentation `json:"propose_presentation"`
}

// NegotiateRequestPresentationResponse model
//
// Represents a NegotiateRequestPresentation response message
//
type NegotiateRequestPresentationResponse struct{}

// SendProposePresentationArgs model
//
// This is used for sending a propose presentation
//
type SendProposePresentationArgs struct {
	// MyDID sender's did
	MyDID string `json:"my_did"`
	// TheirDID receiver's did
	TheirDID string `json:"their_did"`
	// ProposePresentation is a message sent by the Prover to the verifier to initiate a proof
	// presentation process.
	ProposePresentation *presentproof.ProposePresentation `json:"propose_presentation"`
}

// SendProposePresentationResponse model
//
// Represents a SendProposePresentation response message
//
type SendProposePresentationResponse struct{}

// SendRequestPresentationArgs model
//
// This is used for sending a request presentation
//
type SendRequestPresentationArgs struct {
	// MyDID sender's did
	MyDID string `json:"my_did"`
	// TheirDID receiver's did
	TheirDID string `json:"their_did"`
	// RequestPresentation describes values that need to be revealed and predicates that need to be fulfilled.
	RequestPresentation *presentproof.RequestPresentation `json:"request_presentation"`
}

// SendRequestPresentationResponse model
//
// Represents a SendRequestPresentation response message
//
type SendRequestPresentationResponse struct{}
