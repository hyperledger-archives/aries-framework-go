/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	cmdisscred "github.com/hyperledger/aries-framework-go/pkg/controller/command/issuecredential"
)

// IssueCredential implements the IssueCredentialController interface for all credential issuing operations.
type IssueCredential struct {
	handlers map[string]command.Exec
}

// Actions returns pending actions that have not yet to be executed or canceled.
func (ic *IssueCredential) Actions(request *models.RequestEnvelope) *models.ResponseEnvelope {
	response, cmdErr := exec(ic.handlers[cmdisscred.Actions], request.Payload)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// SendOffer is used by the Issuer to send an offer.
func (ic *IssueCredential) SendOffer(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdisscred.SendOfferArgsV2{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(ic.handlers[cmdisscred.SendOffer], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// SendProposal is used by the Holder to send a proposal.
func (ic *IssueCredential) SendProposal(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdisscred.SendProposalArgsV2{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(ic.handlers[cmdisscred.SendProposal], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// SendRequest is used by the Holder to send a request.
func (ic *IssueCredential) SendRequest(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdisscred.SendRequestArgsV2{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(ic.handlers[cmdisscred.SendRequest], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// AcceptProposal is used when the Issuer is willing to accept the proposal.
func (ic *IssueCredential) AcceptProposal(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdisscred.AcceptProposalArgsV2{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(ic.handlers[cmdisscred.AcceptProposal], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// NegotiateProposal is used when the Holder wants to negotiate about an offer he received.
func (ic *IssueCredential) NegotiateProposal(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdisscred.NegotiateProposalArgsV2{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(ic.handlers[cmdisscred.NegotiateProposal], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// DeclineProposal is used when the Issuer does not want to accept the proposal.
func (ic *IssueCredential) DeclineProposal(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdisscred.DeclineProposalArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(ic.handlers[cmdisscred.DeclineProposal], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// AcceptOffer is used when the Holder is willing to accept the offer.
func (ic *IssueCredential) AcceptOffer(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdisscred.AcceptOfferArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(ic.handlers[cmdisscred.AcceptOffer], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// AcceptProblemReport is used for accepting problem report.
func (ic *IssueCredential) AcceptProblemReport(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdisscred.AcceptProblemReportArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(ic.handlers[cmdisscred.AcceptProblemReport], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// DeclineOffer is used when the Holder does not want to accept the offer.
func (ic *IssueCredential) DeclineOffer(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdisscred.DeclineOfferArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(ic.handlers[cmdisscred.DeclineOffer], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// AcceptRequest is used when the Issuer is willing to accept the request.
func (ic *IssueCredential) AcceptRequest(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdisscred.AcceptRequestArgsV2{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(ic.handlers[cmdisscred.AcceptRequest], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// DeclineRequest is used when the Issuer does not want to accept the request.
func (ic *IssueCredential) DeclineRequest(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdisscred.DeclineRequestArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(ic.handlers[cmdisscred.DeclineRequest], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// AcceptCredential is used when the Holder is willing to accept the IssueCredential.
func (ic *IssueCredential) AcceptCredential(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdisscred.AcceptCredentialArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(ic.handlers[cmdisscred.AcceptCredential], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// DeclineCredential is used when the Holder does not want to accept the IssueCredential.
func (ic *IssueCredential) DeclineCredential(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdisscred.DeclineCredentialArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(ic.handlers[cmdisscred.DeclineCredential], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}
