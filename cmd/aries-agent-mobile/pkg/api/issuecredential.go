/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

import "github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"

// IssueCredentialController defines methods for the IssueCredential protocol controller.
type IssueCredentialController interface {

	// Actions returns pending actions that have not yet to be executed or canceled.
	Actions(request *models.RequestEnvelope) *models.ResponseEnvelope

	// SendOffer is used by the Issuer to send an offer.
	SendOffer(request *models.RequestEnvelope) *models.ResponseEnvelope

	// SendProposal is used by the Holder to send a proposal.
	SendProposal(request *models.RequestEnvelope) *models.ResponseEnvelope

	// SendRequest is used by the Holder to send a request.
	SendRequest(request *models.RequestEnvelope) *models.ResponseEnvelope

	// AcceptProposal is used when the Issuer is willing to accept the proposal.
	AcceptProposal(request *models.RequestEnvelope) *models.ResponseEnvelope

	// NegotiateProposal is used when the Holder wants to negotiate about an offer he received.
	NegotiateProposal(request *models.RequestEnvelope) *models.ResponseEnvelope

	// DeclineProposal is used when the Issuer does not want to accept the proposal.
	DeclineProposal(request *models.RequestEnvelope) *models.ResponseEnvelope

	// AcceptOffer is used when the Holder is willing to accept the offer.
	AcceptOffer(request *models.RequestEnvelope) *models.ResponseEnvelope

	// AcceptProblemReport is used for accepting problem report.
	AcceptProblemReport(request *models.RequestEnvelope) *models.ResponseEnvelope

	// DeclineOffer is used when the Holder does not want to accept the offer.
	DeclineOffer(request *models.RequestEnvelope) *models.ResponseEnvelope

	// AcceptRequest is used when the Issuer is willing to accept the request.
	AcceptRequest(request *models.RequestEnvelope) *models.ResponseEnvelope

	// DeclineRequest is used when the Issuer does not want to accept the request.
	DeclineRequest(request *models.RequestEnvelope) *models.ResponseEnvelope

	// AcceptCredential is used when the Holder is willing to accept the IssueCredential.
	AcceptCredential(request *models.RequestEnvelope) *models.ResponseEnvelope

	// DeclineCredential is used when the Holder does not want to accept the IssueCredential.
	DeclineCredential(request *models.RequestEnvelope) *models.ResponseEnvelope
}
