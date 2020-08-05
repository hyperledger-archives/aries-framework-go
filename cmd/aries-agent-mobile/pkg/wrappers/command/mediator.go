/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/mediator"
)

// Mediator contains necessary fields to support its operations.
type Mediator struct {
	handlers map[string]command.Exec
}

// Register registers the agent with the router.
func (m *Mediator) Register(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := mediator.RegisterRoute{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(m.handlers[mediator.RegisterCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// Unregister unregisters the agent with the router.
func (m *Mediator) Unregister(request *models.RequestEnvelope) *models.ResponseEnvelope {
	response, cmdErr := exec(m.handlers[mediator.UnregisterCommandMethod], request.Payload)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// Connection returns the connectionID of the router.
func (m *Mediator) Connection(request *models.RequestEnvelope) *models.ResponseEnvelope {
	response, cmdErr := exec(m.handlers[mediator.GetConnectionIDCommandMethod], request.Payload)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// Reconnect sends noop message to reestablish a connection when there is no other reason to message the mediator.
func (m *Mediator) Reconnect(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := mediator.RegisterRoute{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(m.handlers[mediator.ReconnectCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// Status returns details about pending messages for given connection.
func (m *Mediator) Status(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := mediator.StatusRequest{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(m.handlers[mediator.StatusCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// BatchPickup dispatches pending messages for given connection.
func (m *Mediator) BatchPickup(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := mediator.BatchPickupRequest{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(m.handlers[mediator.BatchPickupCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}
