/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

import (
	"github.com/hyperledger/aries-framework-go/pkg/client/presentproof"
)

// DeclinePresentationArgs model
//
// This is used when the presentation needs to be rejected.
//
type DeclinePresentationArgs struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// Reason why presentation is declined
	Reason string `json:"reason"`
	// RedirectURL is optional web redirect URL that can be sent to prover.
	// Useful in cases where verifier would want prover to redirect once presentation is declined.
	RedirectURL string `json:"redirectURL"`
}

// DeclinePresentationResponse model
//
// Represents a DeclinePresentation response message.
//
type DeclinePresentationResponse struct{}

// DeclineProposePresentationArgs model
//
// This is used when proposal needs to be rejected.
//
type DeclineProposePresentationArgs struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// Reason why proposal is declined
	Reason string `json:"reason"`
	// RedirectURL is optional web redirect URL that can be sent to prover.
	// Useful in cases where verifier would want prover to redirect after its proposal gets declined.
	RedirectURL string `json:"redirectURL"`
}

// DeclineProposePresentationResponse model
//
// Represents a DeclineProposePresentation response message.
//
type DeclineProposePresentationResponse struct{}

// DeclineRequestPresentationArgs model
//
// This is used when the request needs to be rejected.
//
type DeclineRequestPresentationArgs struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// Reason why request is declined
	Reason string `json:"reason"`
}

// DeclineRequestPresentationResponse model
//
// Represents a DeclineRequestPresentation response message.
//
type DeclineRequestPresentationResponse struct{}

// ActionsResponse model
//
// Represents Actions response message.
//
type ActionsResponse struct {
	Actions []presentproof.Action `json:"actions"`
}

// AcceptPresentationArgs model
//
// This is used for accepting a presentation.
//
type AcceptPresentationArgs struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// Names represent the names of how presentations will be stored
	Names []string `json:"names"`
	// RedirectURL is optional web redirect URL that can be sent to prover.
	// Useful in cases where verifier would want prover to redirect once protocol is over.
	RedirectURL string `json:"redirectURL"`
}

// AcceptPresentationResponse model
//
// Represents a AcceptPresentation response message.
//
type AcceptPresentationResponse struct{}

// AcceptRequestPresentationArgs model
//
// This is used for accepting a request presentation.
//
type AcceptRequestPresentationArgs struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// Presentation is a message that contains signed presentations.
	Presentation *presentproof.Presentation `json:"presentation"`
}

// AcceptRequestPresentationV2Args model
//
// This is used for accepting a request presentation.
//
type AcceptRequestPresentationV2Args struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// Presentation is a message that contains signed presentations.
	Presentation *presentproof.PresentationV2 `json:"presentation"`
}

// AcceptRequestPresentationV3Args model
//
// This is used for accepting a request presentation.
//
type AcceptRequestPresentationV3Args struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// Presentation is a message that contains signed presentations.
	Presentation *presentproof.PresentationV3 `json:"presentation"`
}

// AcceptRequestPresentationResponse model
//
// Represents a AcceptRequestPresentation response message.
//
type AcceptRequestPresentationResponse struct{}

// AcceptProposePresentationArgs model
//
// This is used for accepting a propose presentation.
//
type AcceptProposePresentationArgs struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// RequestPresentation describes values that need to be revealed and predicates that need to be fulfilled.
	RequestPresentation *presentproof.RequestPresentation `json:"request_presentation"`
}

// AcceptProposePresentationV2Args model
//
// This is used for accepting a propose presentation.
//
type AcceptProposePresentationV2Args struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// RequestPresentation describes values that need to be revealed and predicates that need to be fulfilled.
	RequestPresentation *presentproof.RequestPresentationV2 `json:"request_presentation"`
}

// AcceptProposePresentationV3Args model
//
// This is used for accepting a propose presentation.
//
type AcceptProposePresentationV3Args struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// RequestPresentation describes values that need to be revealed and predicates that need to be fulfilled.
	RequestPresentation *presentproof.RequestPresentationV3 `json:"request_presentation"`
}

// AcceptProposePresentationResponse model
//
// Represents a AcceptProposePresentation response message.
//
type AcceptProposePresentationResponse struct{}

// NegotiateRequestPresentationArgs model
//
// This is used by the Prover to counter a presentation request they received with a proposal.
//
type NegotiateRequestPresentationArgs struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// ProposePresentation is a response message to a request-presentation message when the Prover wants to
	// propose using a different presentation format.
	ProposePresentation *presentproof.ProposePresentation `json:"propose_presentation"`
}

// NegotiateRequestPresentationV2Args model
//
// This is used by the Prover to counter a presentation request they received with a proposal.
//
type NegotiateRequestPresentationV2Args struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// ProposePresentation is a response message to a request-presentation message when the Prover wants to
	// propose using a different presentation format.
	ProposePresentation *presentproof.ProposePresentationV2 `json:"propose_presentation"`
}

// NegotiateRequestPresentationV3Args model
//
// This is used by the Prover to counter a presentation request they received with a proposal.
//
type NegotiateRequestPresentationV3Args struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// ProposePresentation is a response message to a request-presentation message when the Prover wants to
	// propose using a different presentation format.
	ProposePresentation *presentproof.ProposePresentationV3 `json:"propose_presentation"`
}

// NegotiateRequestPresentationResponse model
//
// Represents a NegotiateRequestPresentation response message.
//
type NegotiateRequestPresentationResponse struct{}

// SendProposePresentationArgs model
//
// This is used for sending a propose presentation.
//
type SendProposePresentationArgs struct {
	// MyDID sender's did
	MyDID string `json:"my_did"`
	// TheirDID receiver's did
	TheirDID string `json:"their_did"`
	// ConnectionID ID of connection between sender and receiver.
	// Optional: if present, is used instead of MyDID + TheirDID.
	ConnectionID string `json:"connection_id"`
	// ProposePresentation is a message sent by the Prover to the verifier to initiate a proof
	// presentation process.
	ProposePresentation *presentproof.ProposePresentation `json:"propose_presentation"`
}

// SendProposePresentationV2Args model
//
// This is used for sending a propose presentation.
//
type SendProposePresentationV2Args struct {
	// MyDID sender's did
	MyDID string `json:"my_did"`
	// TheirDID receiver's did
	TheirDID string `json:"their_did"`
	// ConnectionID ID of connection between sender and receiver.
	// Optional: if present, is used instead of MyDID + TheirDID.
	ConnectionID string `json:"connection_id"`
	// ProposePresentation is a message sent by the Prover to the verifier to initiate a proof
	// presentation process.
	ProposePresentation *presentproof.ProposePresentationV2 `json:"propose_presentation"`
}

// SendProposePresentationV3Args model
//
// This is used for sending a propose presentation.
//
type SendProposePresentationV3Args struct {
	// MyDID sender's did
	MyDID string `json:"my_did"`
	// TheirDID receiver's did
	TheirDID string `json:"their_did"`
	// ConnectionID ID of connection between sender and receiver.
	// Optional: if present, is used instead of MyDID + TheirDID.
	ConnectionID string `json:"connection_id"`
	// ProposePresentation is a message sent by the Prover to the verifier to initiate a proof
	// presentation process.
	ProposePresentation *presentproof.ProposePresentationV3 `json:"propose_presentation"`
}

// SendProposePresentationResponse model
//
// Represents a SendProposePresentation response message.
//
type SendProposePresentationResponse struct {
	// PIID Protocol instance ID. It can be used as a correlation ID
	PIID string `json:"piid"`
}

// SendRequestPresentationArgs model
//
// This is used for sending a request presentation.
//
type SendRequestPresentationArgs struct {
	// MyDID sender's did
	MyDID string `json:"my_did"`
	// TheirDID receiver's did
	TheirDID string `json:"their_did"`
	// ConnectionID ID of connection between sender and receiver.
	// Optional: if present, is used instead of MyDID + TheirDID.
	ConnectionID string `json:"connection_id"`
	// RequestPresentation describes values that need to be revealed and predicates that need to be fulfilled.
	RequestPresentation *presentproof.RequestPresentation `json:"request_presentation"`
}

// SendRequestPresentationV2Args model
//
// This is used for sending a request presentation.
//
type SendRequestPresentationV2Args struct {
	// MyDID sender's did
	MyDID string `json:"my_did"`
	// TheirDID receiver's did
	TheirDID string `json:"their_did"`
	// ConnectionID ID of connection between sender and receiver.
	// Optional: if present, is used instead of MyDID + TheirDID.
	ConnectionID string `json:"connection_id"`
	// RequestPresentation describes values that need to be revealed and predicates that need to be fulfilled.
	RequestPresentation *presentproof.RequestPresentationV2 `json:"request_presentation"`
}

// SendRequestPresentationV3Args model
//
// This is used for sending a request presentation.
//
type SendRequestPresentationV3Args struct {
	// MyDID sender's did
	MyDID string `json:"my_did"`
	// TheirDID receiver's did
	TheirDID string `json:"their_did"`
	// ConnectionID ID of connection between sender and receiver.
	// Optional: if present, is used instead of MyDID + TheirDID.
	ConnectionID string `json:"connection_id"`
	// RequestPresentation describes values that need to be revealed and predicates that need to be fulfilled.
	RequestPresentation *presentproof.RequestPresentationV3 `json:"request_presentation"`
}

// SendRequestPresentationResponse model
//
// Represents a SendRequestPresentation response message.
//
type SendRequestPresentationResponse struct {
	// PIID Protocol instance ID. It can be used as a correlation ID
	PIID string `json:"piid"`
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
