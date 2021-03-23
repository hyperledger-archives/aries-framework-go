/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	cmdintroduce "github.com/hyperledger/aries-framework-go/pkg/controller/command/introduce"
)

// Introduce contains necessary fields for each of its operations.
type Introduce struct {
	httpClient httpClient
	endpoints  map[string]*endpoint

	URL   string
	Token string
}

// Actions returns unfinished actions for the async usage.
// This creates an http request based on the provided method arguments.
func (ir *Introduce) Actions(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return ir.createRespEnvelope(request, cmdintroduce.Actions)
}

// SendProposal sends a proposal to the introducees (the client has not published an out-of-band message) via HTTP.
func (ir *Introduce) SendProposal(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return ir.createRespEnvelope(request, cmdintroduce.SendProposal)
}

// SendProposalWithOOBInvitation sends a proposal to the introducee
// (the client has published an out-of-band request) via HTTP.
func (ir *Introduce) SendProposalWithOOBInvitation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return ir.createRespEnvelope(request, cmdintroduce.SendProposalWithOOBInvitation)
}

// SendRequest sends a request showing that the introducee is willing to share their own out-of-band message (via HTTP).
func (ir *Introduce) SendRequest(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return ir.createRespEnvelope(request, cmdintroduce.SendRequest)
}

// AcceptProposalWithOOBInvitation is used when introducee wants to provide an out-of-band request (via HTTP).
func (ir *Introduce) AcceptProposalWithOOBInvitation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return ir.createRespEnvelope(request, cmdintroduce.AcceptProposalWithOOBInvitation)
}

// AcceptProposal is used when introducee wants to accept a proposal without providing a OOBRequest (via HTTP).
func (ir *Introduce) AcceptProposal(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return ir.createRespEnvelope(request, cmdintroduce.AcceptProposal)
}

// AcceptRequestWithPublicOOBInvitation is used when an introducer
// wants to provide a published out-of-band request (via HTTP).
func (ir *Introduce) AcceptRequestWithPublicOOBInvitation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return ir.createRespEnvelope(request, cmdintroduce.AcceptRequestWithPublicOOBInvitation)
}

// AcceptRequestWithRecipients is used when the introducer does not have a published out-of-band message on hand
// but they are willing to introduce agents to each other. This is done via HTTP.
func (ir *Introduce) AcceptRequestWithRecipients(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return ir.createRespEnvelope(request, cmdintroduce.AcceptRequestWithRecipients)
}

// DeclineProposal is used to reject the proposal (via HTTP).
func (ir *Introduce) DeclineProposal(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return ir.createRespEnvelope(request, cmdintroduce.DeclineProposal)
}

// DeclineRequest is used to reject the request (via HTTP).
func (ir *Introduce) DeclineRequest(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return ir.createRespEnvelope(request, cmdintroduce.DeclineRequest)
}

// AcceptProblemReport is used for accepting problem report.
func (ir *Introduce) AcceptProblemReport(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return ir.createRespEnvelope(request, cmdintroduce.AcceptProblemReport)
}

func (ir *Introduce) createRespEnvelope(request *models.RequestEnvelope, endpoint string) *models.ResponseEnvelope {
	return exec(&restOperation{
		url:        ir.URL,
		token:      ir.Token,
		httpClient: ir.httpClient,
		endpoint:   ir.endpoints[endpoint],
		request:    request,
	})
}
