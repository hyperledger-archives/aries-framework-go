/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

import protocol "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"

// presentProofActionsRequest model
//
// Returns pending actions that have not yet to be executed or cancelled.
//
// swagger:parameters presentProofActions
type presentProofActionsRequest struct{} // nolint: unused,deadcode

// presentProofActionsResponse model
//
// Represents a Actions response message.
//
// swagger:response presentProofActionsResponse
type presentProofActionsResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		Actions []struct{ *protocol.Action } `json:"actions"`
	}
}

// presentProofSendRequestPresentationRequest model
//
// This is used for operation to send a request presentation.
//
// swagger:parameters presentProofSendRequestPresentation
type presentProofSendRequestPresentationRequest struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		// MyDID sender's did
		// required: true
		MyDID string `json:"my_did"`
		// TheirDID receiver's did
		// required: true
		TheirDID string `json:"their_did"`
		// RequestPresentation describes values that need to be revealed and predicates that need to be fulfilled.
		// required: true
		RequestPresentation struct {
			*protocol.RequestPresentationV2
		} `json:"request_presentation"`
	}
}

// presentProofSendRequestPresentationV3Request model
//
// This is used for operation to send a request presentation.
//
// swagger:parameters presentProofSendRequestPresentationV3
type presentProofSendRequestPresentationV3Request struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		// MyDID sender's did
		// required: true
		MyDID string `json:"my_did"`
		// TheirDID receiver's did
		// required: true
		TheirDID string `json:"their_did"`
		// RequestPresentation describes values that need to be revealed and predicates that need to be fulfilled.
		// required: true
		RequestPresentation struct {
			*protocol.RequestPresentationV3
		} `json:"request_presentation"`
	}
}

// presentProofSendRequestPresentationResponse model
//
// Represents a SendRequestPresentation response message.
//
// swagger:response presentProofSendRequestPresentationResponse
type presentProofSendRequestPresentationResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		// PIID Protocol instance ID. It can be used as a correlation ID
		PIID string `json:"piid"`
	}
}

// presentProofSendProposePresentationRequest model
//
// This is used for operation to send a propose presentation.
//
// swagger:parameters presentProofSendProposePresentation
type presentProofSendProposePresentationRequest struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		// MyDID sender's did
		// required: true
		MyDID string `json:"my_did"`
		// TheirDID receiver's did
		// required: true
		TheirDID string `json:"their_did"`
		// ProposePresentation is a message sent by the Prover to the verifier to initiate a proof presentation process.
		// required: true
		ProposePresentation struct {
			*protocol.ProposePresentationV2
		} `json:"propose_presentation"`
	}
}

// presentProofSendProposePresentationV3Request model
//
// This is used for operation to send a propose presentation.
//
// swagger:parameters presentProofSendProposePresentationV3
type presentProofSendProposePresentationV3Request struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		// MyDID sender's did
		// required: true
		MyDID string `json:"my_did"`
		// TheirDID receiver's did
		// required: true
		TheirDID string `json:"their_did"`
		// ProposePresentation is a message sent by the Prover to the verifier to initiate a proof presentation process.
		// required: true
		ProposePresentation struct {
			*protocol.ProposePresentationV3
		} `json:"propose_presentation"`
	}
}

// presentProofSendProposePresentationResponse model
//
// Represents a SendProposePresentation response message.
//
// swagger:response presentProofSendProposePresentationResponse
type presentProofSendProposePresentationResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		// PIID Protocol instance ID. It can be used as a correlation ID
		PIID string `json:"piid"`
	}
}

// presentProofAcceptRequestPresentationRequest model
//
// This is used for operation to accept a request presentation.
//
// swagger:parameters presentProofAcceptRequestPresentation
type presentProofAcceptRequestPresentationRequest struct { // nolint: unused,deadcode
	// Protocol instance ID
	//
	// in: path
	// required: true
	PIID string `json:"piid"`

	// in: body
	Body struct {
		// Presentation is a message that contains signed presentations.
		//
		// required: true
		Presentation struct{ *protocol.PresentationV2 } `json:"presentation"`
	}
}

// presentProofAcceptRequestPresentationV3Request model
//
// This is used for operation to accept a request presentation.
//
// swagger:parameters presentProofAcceptRequestPresentationV3
type presentProofAcceptRequestPresentationV3Request struct { // nolint: unused,deadcode
	// Protocol instance ID
	//
	// in: path
	// required: true
	PIID string `json:"piid"`

	// in: body
	Body struct {
		// Presentation is a message that contains signed presentations.
		//
		// required: true
		Presentation struct{ *protocol.PresentationV3 } `json:"presentation"`
	}
}

// presentProofAcceptRequestPresentationResponse model
//
// Represents a AcceptRequestPresentation response message.
//
// swagger:response presentProofAcceptRequestPresentationResponse
type presentProofAcceptRequestPresentationResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct{}
}

// presentProofAcceptProposePresentationRequest model
//
// This is used for operation to accept a propose presentation.
//
// swagger:parameters presentProofAcceptProposePresentation
type presentProofAcceptProposePresentationRequest struct { // nolint: unused,deadcode
	// Protocol instance ID
	//
	// in: path
	// required: true
	PIID string `json:"piid"`

	// in: body
	Body struct {
		// RequestPresentation describes values that need to be revealed and predicates that need to be fulfilled.
		//
		// required: true
		RequestPresentation struct {
			*protocol.RequestPresentationV2
		} `json:"request_presentation"`
	}
}

// presentProofAcceptProposePresentationV3Request model
//
// This is used for operation to accept a propose presentation.
//
// swagger:parameters presentProofAcceptProposePresentationV3
type presentProofAcceptProposePresentationV3Request struct { // nolint: unused,deadcode
	// Protocol instance ID
	//
	// in: path
	// required: true
	PIID string `json:"piid"`

	// in: body
	Body struct {
		// RequestPresentation describes values that need to be revealed and predicates that need to be fulfilled.
		//
		// required: true
		RequestPresentation struct {
			*protocol.RequestPresentationV3
		} `json:"request_presentation"`
	}
}

// presentProofAcceptProposePresentationResponse model
//
// Represents a AcceptProposePresentation response message.
//
// swagger:response presentProofAcceptProposePresentationResponse
type presentProofAcceptProposePresentationResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct{}
}

// presentProofAcceptPresentationRequest model
//
// This is used for operation to accept a presentation.
//
// swagger:parameters presentProofAcceptPresentation
type presentProofAcceptPresentationRequest struct { // nolint: unused,deadcode
	// Protocol instance ID
	//
	// in: path
	// required: true
	PIID string `json:"piid"`

	// in: body
	Body struct {
		// required: true
		Names []string `json:"names"`
	}
}

// presentProofAcceptPresentationResponse model
//
// Represents a AcceptPresentation response message.
//
// swagger:response presentProofAcceptPresentationResponse
type presentProofAcceptPresentationResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct{}
}

// presentProofNegotiateRequestPresentationRequest model
//
// Is used by the Prover to counter a presentation request they received with a proposal.
//
// swagger:parameters presentProofNegotiateRequestPresentation
type presentProofNegotiateRequestPresentationRequest struct { // nolint: unused,deadcode
	// Protocol instance ID
	//
	// in: path
	// required: true
	PIID string `json:"piid"`

	// in: body
	Body struct {
		// ProposePresentation is a response message to a request-presentation message when the Prover wants to
		// propose using a different presentation format.
		//
		// required: true
		ProposePresentation struct {
			*protocol.ProposePresentationV2
		} `json:"propose_presentation"`
	}
}

// presentProofNegotiateRequestPresentationV3Request model
//
// Is used by the Prover to counter a presentation request they received with a proposal.
//
// swagger:parameters presentProofNegotiateRequestPresentationV3
type presentProofNegotiateRequestPresentationV3Request struct { // nolint: unused,deadcode
	// Protocol instance ID
	//
	// in: path
	// required: true
	PIID string `json:"piid"`

	// in: body
	Body struct {
		// ProposePresentation is a response message to a request-presentation message when the Prover wants to
		// propose using a different presentation format.
		//
		// required: true
		ProposePresentation struct {
			*protocol.ProposePresentationV3
		} `json:"propose_presentation"`
	}
}

// presentProofNegotiateRequestPresentationResponse model
//
// Represents a NegotiateRequestPresentation response message
//
// swagger:response presentProofNegotiateRequestPresentationResponse
type presentProofNegotiateRequestPresentationResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct{}
}

// presentProofDeclineRequestPresentationRequest model
//
// This is used for operation to decline a request presentation.
//
// swagger:parameters presentProofDeclineRequestPresentation
type presentProofDeclineRequestPresentationRequest struct { // nolint: unused,deadcode
	// Protocol instance ID
	//
	// in: path
	// required: true
	PIID string `json:"piid"`

	// Reason is an explanation of why it was declined
	Reason string `json:"reason"`
}

// presentProofDeclineRequestPresentationResponse model
//
// Represents a DeclineRequestPresentation response message.
//
// swagger:response presentProofDeclineRequestPresentationResponse
type presentProofDeclineRequestPresentationResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct{}
}

// presentProofDeclineProposePresentationRequest model
//
// This is used for operation to decline a propose presentation.
//
// swagger:parameters presentProofDeclineProposePresentation
type presentProofDeclineProposePresentationRequest struct { // nolint: unused,deadcode
	// Protocol instance ID
	//
	// in: path
	// required: true
	PIID string `json:"piid"`

	// Reason is an explanation of why it was declined
	Reason string `json:"reason"`
}

// presentProofDeclineProposePresentationResponse model
//
// Represents a DeclineProposePresentation response message.
//
// swagger:response presentProofDeclineProposePresentationResponse
type presentProofDeclineProposePresentationResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct{}
}

// presentProofDeclinePresentationRequest model
//
// This is used for operation to decline a presentation.
//
// swagger:parameters presentProofDeclinePresentation
type presentProofDeclinePresentationRequest struct { // nolint: unused,deadcode
	// Protocol instance ID
	//
	// in: path
	// required: true
	PIID string `json:"piid"`

	// Reason is an explanation of why it was declined
	Reason string `json:"reason"`

	// RedirectURL is optional web redirect URL that can be sent to prover.
	// Useful in cases where verifier would want prover to redirect once presentation is declined.
	RedirectURL string `json:"redirectURL"`
}

// presentProofDeclinePresentationResponse model
//
// Represents a DeclinePresentation response message.
//
// swagger:response presentProofDeclinePresentationResponse
type presentProofDeclinePresentationResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct{}
}

// presentProofAcceptProblemReportRequest model
//
// This is used for operation to accept a problem report.
//
// swagger:parameters presentProofAcceptProblemReport
type presentProofAcceptProblemReportRequest struct { // nolint: unused,deadcode
	// Protocol instance ID
	//
	// in: path
	// required: true
	PIID string `json:"piid"`
}

// presentProofAcceptProblemReportResponse model
//
// Represents a AcceptProblemReport response message
//
// swagger:response presentProofAcceptProblemReportResponse
type presentProofAcceptProblemReportResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct{}
}
