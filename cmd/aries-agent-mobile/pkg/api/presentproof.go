/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

import "github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"

// PresentProofController defines methods for the PresentProof protocol controller.
type PresentProofController interface {

	// Actions returns pending actions that have not yet to be executed or canceled.
	Actions(request *models.RequestEnvelope) *models.ResponseEnvelope

	// SendRequestPresentation is used by the Verifier to send a request presentation.
	SendRequestPresentation(request *models.RequestEnvelope) *models.ResponseEnvelope

	// SendProposePresentation is used by the Prover to send a propose presentation.
	SendProposePresentation(request *models.RequestEnvelope) *models.ResponseEnvelope

	// AcceptRequestPresentation is used by the Prover is to accept a presentation request.
	AcceptRequestPresentation(request *models.RequestEnvelope) *models.ResponseEnvelope

	// NegotiateRequestPresentation is used by the Prover to counter a presentation request they received with a proposal.
	NegotiateRequestPresentation(request *models.RequestEnvelope) *models.ResponseEnvelope

	// DeclineRequestPresentation is used when the Prover does not want to accept the request presentation.
	DeclineRequestPresentation(request *models.RequestEnvelope) *models.ResponseEnvelope

	// AcceptProposePresentation is used when the Verifier is willing to accept the propose presentation.
	AcceptProposePresentation(request *models.RequestEnvelope) *models.ResponseEnvelope

	// DeclineProposePresentation is used when the Verifier does not want to accept the propose presentation.
	DeclineProposePresentation(request *models.RequestEnvelope) *models.ResponseEnvelope

	// AcceptPresentation is used by the Verifier to accept a presentation.
	AcceptPresentation(request *models.RequestEnvelope) *models.ResponseEnvelope

	// AcceptProblemReport is used for accepting problem report.
	AcceptProblemReport(request *models.RequestEnvelope) *models.ResponseEnvelope

	// DeclinePresentation is used by the Verifier to decline a presentation.
	DeclinePresentation(request *models.RequestEnvelope) *models.ResponseEnvelope
}
