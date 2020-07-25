/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	clientdidexch "github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	cmddidexch "github.com/hyperledger/aries-framework-go/pkg/controller/command/didexchange"
)

// DIDExchange contains necessary fields to support its operations.
type DIDExchange struct {
	handlers map[string]command.Exec
}

// CreateInvitation creates a new connection invitation.
func (de *DIDExchange) CreateInvitation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmddidexch.CreateInvitationArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(de.handlers[cmddidexch.CreateInvitationCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// ReceiveInvitation receives a new connection invitation.
func (de *DIDExchange) ReceiveInvitation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := clientdidexch.Invitation{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(de.handlers[cmddidexch.ReceiveInvitationCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// AcceptInvitation accepts a stored connection invitation.
func (de *DIDExchange) AcceptInvitation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmddidexch.AcceptInvitationArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(de.handlers[cmddidexch.AcceptInvitationCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// CreateImplicitInvitation creates implicit invitation using inviter DID.
func (de *DIDExchange) CreateImplicitInvitation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmddidexch.ImplicitInvitationArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(de.handlers[cmddidexch.CreateImplicitInvitationCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// AcceptExchangeRequest accepts a stored connection request.
func (de *DIDExchange) AcceptExchangeRequest(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmddidexch.AcceptExchangeRequestArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(de.handlers[cmddidexch.AcceptExchangeRequestCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// QueryConnections queries agent to agent connections.
func (de *DIDExchange) QueryConnections(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmddidexch.QueryConnectionsArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(de.handlers[cmddidexch.QueryConnectionsCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// QueryConnectionByID fetches a single connection record by connection ID.
func (de *DIDExchange) QueryConnectionByID(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmddidexch.ConnectionIDArg{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(de.handlers[cmddidexch.QueryConnectionByIDCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// CreateConnection creates a new connection record in completed state and returns the generated connectionID.
func (de *DIDExchange) CreateConnection(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmddidexch.CreateConnectionRequest{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(de.handlers[cmddidexch.CreateConnectionCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// RemoveConnection removes given connection record.
func (de *DIDExchange) RemoveConnection(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmddidexch.ConnectionIDArg{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(de.handlers[cmddidexch.RemoveConnectionCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}
