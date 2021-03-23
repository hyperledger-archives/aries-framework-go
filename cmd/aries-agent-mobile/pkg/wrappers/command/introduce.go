/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	cmdintroduce "github.com/hyperledger/aries-framework-go/pkg/controller/command/introduce"
)

// Introduce contains handler function for introduce protocol commands.
type Introduce struct {
	handlers map[string]command.Exec
}

// SendProposal sends a proposal to the introducees (the client has not published an out-of-band message).
func (i *Introduce) SendProposal(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdintroduce.SendProposalArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(i.handlers[cmdintroduce.SendProposal], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// Actions returns unfinished actions for the async usage.
func (i *Introduce) Actions(request *models.RequestEnvelope) *models.ResponseEnvelope {
	response, cmdErr := exec(i.handlers[cmdintroduce.Actions], request.Payload)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// SendProposalWithOOBInvitation sends a proposal to the introducee (the client has published an out-of-band request).
func (i *Introduce) SendProposalWithOOBInvitation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdintroduce.SendProposalWithOOBInvitationArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(i.handlers[cmdintroduce.SendProposalWithOOBInvitation], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// SendRequest sends a request showing that the introducee is willing to share their own out-of-band message.
func (i *Introduce) SendRequest(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdintroduce.SendRequestArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(i.handlers[cmdintroduce.SendRequest], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// AcceptProposalWithOOBInvitation is used when introducee wants to provide an out-of-band request.
func (i *Introduce) AcceptProposalWithOOBInvitation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdintroduce.AcceptProposalWithOOBInvitationArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(i.handlers[cmdintroduce.AcceptProposalWithOOBInvitation], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// AcceptProposal is used when introducee wants to accept a proposal without providing an OOBRequest.
func (i *Introduce) AcceptProposal(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdintroduce.AcceptProposalArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(i.handlers[cmdintroduce.AcceptProposal], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// AcceptRequestWithPublicOOBInvitation is used when introducer wants to provide a published out-of-band request.
func (i *Introduce) AcceptRequestWithPublicOOBInvitation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdintroduce.AcceptRequestWithPublicOOBInvitationArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(i.handlers[cmdintroduce.AcceptRequestWithPublicOOBInvitation], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// AcceptRequestWithRecipients is used when the introducer does not have a published out-of-band message on hand
// but they are willing to introduce agents to each other.
func (i *Introduce) AcceptRequestWithRecipients(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdintroduce.AcceptRequestWithRecipientsArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(i.handlers[cmdintroduce.AcceptRequestWithRecipients], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// DeclineProposal is used to reject the proposal.
func (i *Introduce) DeclineProposal(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdintroduce.DeclineProposalArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(i.handlers[cmdintroduce.DeclineProposal], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// DeclineRequest is used to reject the request.
func (i *Introduce) DeclineRequest(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdintroduce.DeclineRequestArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(i.handlers[cmdintroduce.DeclineRequest], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// AcceptProblemReport is used for accepting problem report.
func (i *Introduce) AcceptProblemReport(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdintroduce.AcceptProblemReportArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(i.handlers[cmdintroduce.AcceptProblemReport], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}
