/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/ld"
)

// LD contains necessary fields to support JSON-LD operations.
type LD struct {
	handlers map[string]command.Exec
}

// AddContexts adds JSON-LD contexts to the underlying storage.
func (c *LD) AddContexts(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := ld.AddContextsRequest{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(c.handlers[ld.AddContextsCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// AddRemoteProvider adds remote provider and JSON-LD contexts from that provider.
func (c *LD) AddRemoteProvider(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := ld.AddRemoteProviderRequest{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(c.handlers[ld.AddRemoteProviderCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// RefreshRemoteProvider updates contexts from the remote provider.
func (c *LD) RefreshRemoteProvider(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := ld.ProviderID{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(c.handlers[ld.RefreshRemoteProviderCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// DeleteRemoteProvider deletes remote provider and contexts from that provider.
func (c *LD) DeleteRemoteProvider(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := ld.ProviderID{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(c.handlers[ld.DeleteRemoteProviderCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// GetAllRemoteProviders gets all remote providers.
func (c *LD) GetAllRemoteProviders(request *models.RequestEnvelope) *models.ResponseEnvelope {
	response, cmdErr := exec(c.handlers[ld.GetAllRemoteProvidersCommandMethod], request.Payload)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// RefreshAllRemoteProviders updates contexts from all remote providers.
func (c *LD) RefreshAllRemoteProviders(request *models.RequestEnvelope) *models.ResponseEnvelope {
	response, cmdErr := exec(c.handlers[ld.RefreshAllRemoteProvidersCommandMethod], request.Payload)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}
