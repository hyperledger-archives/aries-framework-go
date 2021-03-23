/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/outofband"
)

// OutOfBand contains necessary fields to support its operations.
type OutOfBand struct {
	handlers map[string]command.Exec
}

// CreateInvitation creates and saves an out-of-band invitation.
func (oob *OutOfBand) CreateInvitation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := outofband.CreateInvitationArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(oob.handlers[outofband.CreateInvitation], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// AcceptInvitation from another agent and return the ID of the new connection records.
func (oob *OutOfBand) AcceptInvitation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := outofband.AcceptInvitationArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(oob.handlers[outofband.AcceptInvitation], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// Actions returns pending actions that have not yet to be executed or canceled.
func (oob *OutOfBand) Actions(request *models.RequestEnvelope) *models.ResponseEnvelope {
	response, cmdErr := exec(oob.handlers[outofband.Actions], request.Payload)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// ActionContinue allows continuing with the protocol after an action event was triggered.
func (oob *OutOfBand) ActionContinue(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := outofband.ActionContinueArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(oob.handlers[outofband.ActionContinue], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// ActionStop stops the protocol after an action event was triggered.
func (oob *OutOfBand) ActionStop(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := outofband.ActionStopArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(oob.handlers[outofband.ActionStop], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}
