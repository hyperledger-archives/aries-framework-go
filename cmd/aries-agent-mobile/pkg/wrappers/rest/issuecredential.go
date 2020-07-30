/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	cmdisscred "github.com/hyperledger/aries-framework-go/pkg/controller/command/issuecredential"
)

// IssueCredential implements the IssueCredentialController interface for all credential issuing operations.
type IssueCredential struct {
	httpClient httpClient
	endpoints  map[string]*endpoint

	URL   string
	Token string
}

// Actions returns pending actions that have not yet to be executed or canceled.
func (ic *IssueCredential) Actions(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return ic.createRespEnvelope(request, cmdisscred.Actions)
}

// SendOffer is used by the Issuer to send an offer.
func (ic *IssueCredential) SendOffer(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return ic.createRespEnvelope(request, cmdisscred.SendOffer)
}

// SendProposal is used by the Holder to send a proposal.
func (ic *IssueCredential) SendProposal(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return ic.createRespEnvelope(request, cmdisscred.SendProposal)
}

// SendRequest is used by the Holder to send a request.
func (ic *IssueCredential) SendRequest(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return ic.createRespEnvelope(request, cmdisscred.SendRequest)
}

// AcceptProposal is used when the Issuer is willing to accept the proposal.
func (ic *IssueCredential) AcceptProposal(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return ic.createRespEnvelope(request, cmdisscred.AcceptProposal)
}

// NegotiateProposal is used when the Holder wants to negotiate about an offer he received.
func (ic *IssueCredential) NegotiateProposal(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return ic.createRespEnvelope(request, cmdisscred.NegotiateProposal)
}

// DeclineProposal is used when the Issuer does not want to accept the proposal.
func (ic *IssueCredential) DeclineProposal(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return ic.createRespEnvelope(request, cmdisscred.DeclineProposal)
}

// AcceptOffer is used when the Holder is willing to accept the offer.
func (ic *IssueCredential) AcceptOffer(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return ic.createRespEnvelope(request, cmdisscred.AcceptOffer)
}

// AcceptProblemReport is used for accepting problem report.
func (ic *IssueCredential) AcceptProblemReport(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return ic.createRespEnvelope(request, cmdisscred.AcceptProblemReport)
}

// DeclineOffer is used when the Holder does not want to accept the offer.
func (ic *IssueCredential) DeclineOffer(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return ic.createRespEnvelope(request, cmdisscred.DeclineOffer)
}

// AcceptRequest is used when the Issuer is willing to accept the request.
func (ic *IssueCredential) AcceptRequest(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return ic.createRespEnvelope(request, cmdisscred.AcceptRequest)
}

// DeclineRequest is used when the Issuer does not want to accept the request.
func (ic *IssueCredential) DeclineRequest(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return ic.createRespEnvelope(request, cmdisscred.DeclineRequest)
}

// AcceptCredential is used when the Holder is willing to accept the IssueCredential.
func (ic *IssueCredential) AcceptCredential(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return ic.createRespEnvelope(request, cmdisscred.AcceptCredential)
}

// DeclineCredential is used when the Holder does not want to accept the IssueCredential.
func (ic *IssueCredential) DeclineCredential(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return ic.createRespEnvelope(request, cmdisscred.DeclineCredential)
}

//nolint: lll
func (ic *IssueCredential) createRespEnvelope(request *models.RequestEnvelope, endpoint string) *models.ResponseEnvelope {
	return exec(&restOperation{
		url:        ic.URL,
		token:      ic.Token,
		httpClient: ic.httpClient,
		endpoint:   ic.endpoints[endpoint],
		request:    request,
	})
}
