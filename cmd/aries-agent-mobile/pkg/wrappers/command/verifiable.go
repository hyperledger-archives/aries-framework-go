/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	cmdverifiable "github.com/hyperledger/aries-framework-go/pkg/controller/command/verifiable"
)

// Verifiable contains necessary fields for each of its operations.
type Verifiable struct {
	handlers map[string]command.Exec
}

// ValidateCredential validates the verifiable credential.
func (v *Verifiable) ValidateCredential(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdverifiable.Credential{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(v.handlers[cmdverifiable.ValidateCredentialCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// SaveCredential saves the verifiable credential to the store.
func (v *Verifiable) SaveCredential(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdverifiable.CredentialExt{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(v.handlers[cmdverifiable.SaveCredentialCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// SavePresentation saves the presentation to the store.
func (v *Verifiable) SavePresentation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdverifiable.PresentationExt{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(v.handlers[cmdverifiable.SavePresentationCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// GetCredential retrieves the verifiable credential from the store.
func (v *Verifiable) GetCredential(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdverifiable.IDArg{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(v.handlers[cmdverifiable.GetCredentialCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// SignCredential adds proof to given verifiable credential.
func (v *Verifiable) SignCredential(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdverifiable.SignCredentialRequest{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(v.handlers[cmdverifiable.SignCredentialCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// GetPresentation retrieves the verifiable presentation from the store.
func (v *Verifiable) GetPresentation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdverifiable.IDArg{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(v.handlers[cmdverifiable.GetPresentationCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// GetCredentialByName retrieves the verifiable credential by name from the store.
func (v *Verifiable) GetCredentialByName(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdverifiable.NameArg{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(v.handlers[cmdverifiable.GetCredentialByNameCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// GetCredentials retrieves the verifiable credential records containing name and fields of interest.
func (v *Verifiable) GetCredentials(request *models.RequestEnvelope) *models.ResponseEnvelope {
	response, cmdErr := exec(v.handlers[cmdverifiable.GetCredentialsCommandMethod], request.Payload)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// GetPresentations retrieves the verifiable presentation records containing name and fields of interest.
func (v *Verifiable) GetPresentations(request *models.RequestEnvelope) *models.ResponseEnvelope {
	response, cmdErr := exec(v.handlers[cmdverifiable.GetPresentationsCommandMethod], request.Payload)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// GeneratePresentation generates verifiable presentation from a verifiable credential.
func (v *Verifiable) GeneratePresentation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdverifiable.PresentationRequest{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(v.handlers[cmdverifiable.GeneratePresentationCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// GeneratePresentationByID generates verifiable presentation from a stored verifiable credential.
func (v *Verifiable) GeneratePresentationByID(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdverifiable.PresentationRequestByID{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(v.handlers[cmdverifiable.GeneratePresentationByIDCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// RemoveCredentialByName will remove a VC that matches the specified name from the verifiable store.
func (v *Verifiable) RemoveCredentialByName(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdverifiable.NameArg{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(v.handlers[cmdverifiable.RemoveCredentialByNameCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// RemovePresentationByName will remove a VP that matches the specified name from the verifiable store.
func (v *Verifiable) RemovePresentationByName(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdverifiable.NameArg{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(v.handlers[cmdverifiable.RemovePresentationByNameCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}
