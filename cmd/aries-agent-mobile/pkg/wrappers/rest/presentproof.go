/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	cmdpresproof "github.com/hyperledger/aries-framework-go/pkg/controller/command/presentproof"
)

// PresentProof contains necessary fields for each of its operations.
type PresentProof struct {
	httpClient httpClient
	endpoints  map[string]*endpoint

	URL   string
	Token string
}

// Actions returns pending actions that have not yet to be executed or canceled.
func (p *PresentProof) Actions(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return p.createRespEnvelope(request, cmdpresproof.Actions)
}

// SendRequestPresentation is used by the Verifier to send a request presentation.
func (p *PresentProof) SendRequestPresentation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return p.createRespEnvelope(request, cmdpresproof.SendRequestPresentation)
}

// SendProposePresentation is used by the Prover to send a propose presentation.
func (p *PresentProof) SendProposePresentation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return p.createRespEnvelope(request, cmdpresproof.SendProposePresentation)
}

// AcceptRequestPresentation is used by the Prover is to accept a presentation request.
func (p *PresentProof) AcceptRequestPresentation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return p.createRespEnvelope(request, cmdpresproof.AcceptRequestPresentation)
}

// NegotiateRequestPresentation is used by the Prover to counter a presentation request they received with a proposal.
func (p *PresentProof) NegotiateRequestPresentation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return p.createRespEnvelope(request, cmdpresproof.NegotiateRequestPresentation)
}

// DeclineRequestPresentation is used when the Prover does not want to accept the request presentation.
func (p *PresentProof) DeclineRequestPresentation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return p.createRespEnvelope(request, cmdpresproof.DeclineRequestPresentation)
}

// AcceptProposePresentation is used when the Verifier is willing to accept the propose presentation.
func (p *PresentProof) AcceptProposePresentation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return p.createRespEnvelope(request, cmdpresproof.AcceptProposePresentation)
}

// DeclineProposePresentation is used when the Verifier does not want to accept the propose presentation.
func (p *PresentProof) DeclineProposePresentation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return p.createRespEnvelope(request, cmdpresproof.DeclineProposePresentation)
}

// AcceptPresentation is used by the Verifier to accept a presentation.
func (p *PresentProof) AcceptPresentation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return p.createRespEnvelope(request, cmdpresproof.AcceptPresentation)
}

// AcceptProblemReport is used for accepting problem report.
func (p *PresentProof) AcceptProblemReport(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return p.createRespEnvelope(request, cmdpresproof.AcceptProblemReport)
}

// DeclinePresentation is used by the Verifier to decline a presentation.
func (p *PresentProof) DeclinePresentation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return p.createRespEnvelope(request, cmdpresproof.DeclinePresentation)
}

func (p *PresentProof) createRespEnvelope(request *models.RequestEnvelope, endpoint string) *models.ResponseEnvelope {
	return exec(&restOperation{
		url:        p.URL,
		token:      p.Token,
		httpClient: p.httpClient,
		endpoint:   p.endpoints[endpoint],
		request:    request,
	})
}
