/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

import (
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
)

// IntroduceController defines methods for the introduce protocol controller.
type IntroduceController interface {

	// Actions returns unfinished actions for the async usage.
	Actions(request *models.RequestEnvelope) *models.ResponseEnvelope

	// SendProposal sends a proposal to the introducees (the client has not published an out-of-band message)
	SendProposal(request *models.RequestEnvelope) *models.ResponseEnvelope

	// SendProposalWithOOBInvitation sends a proposal to the introducee (the client has published an out-of-band request)
	SendProposalWithOOBInvitation(request *models.RequestEnvelope) *models.ResponseEnvelope

	// SendRequest sends a request showing that the introducee is willing to share their own out-of-band message
	SendRequest(request *models.RequestEnvelope) *models.ResponseEnvelope

	// AcceptProposalWithOOBInvitation is used when introducee wants to provide an out-of-band request
	AcceptProposalWithOOBInvitation(request *models.RequestEnvelope) *models.ResponseEnvelope

	// AcceptProposal is used when introducee wants to accept a proposal without providing a OOBRequest
	AcceptProposal(request *models.RequestEnvelope) *models.ResponseEnvelope

	// AcceptRequestWithPublicOOBInvitation is used when introducer wants to provide a published out-of-band request
	AcceptRequestWithPublicOOBInvitation(request *models.RequestEnvelope) *models.ResponseEnvelope

	// AcceptRequestWithRecipients is used when the introducer does not have a published out-of-band message on hand
	// but they are willing to introduce agents to each other
	AcceptRequestWithRecipients(request *models.RequestEnvelope) *models.ResponseEnvelope

	// DeclineProposal is used to reject the proposal
	DeclineProposal(request *models.RequestEnvelope) *models.ResponseEnvelope

	// DeclineRequest is used to reject the request
	DeclineRequest(request *models.RequestEnvelope) *models.ResponseEnvelope

	// AcceptProblemReport is used for accepting problem report.
	AcceptProblemReport(request *models.RequestEnvelope) *models.ResponseEnvelope
}
