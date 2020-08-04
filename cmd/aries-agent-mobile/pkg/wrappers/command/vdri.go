/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	cmdvdri "github.com/hyperledger/aries-framework-go/pkg/controller/command/vdri"
)

// VDRI contains necessary fields for each of its operations.
type VDRI struct {
	handlers map[string]command.Exec
}

// ResolveDID resolve did.
func (v *VDRI) ResolveDID(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdvdri.IDArg{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(v.handlers[cmdvdri.ResolveDIDCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// SaveDID saves the did doc to the store.
func (v *VDRI) SaveDID(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdvdri.DIDArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(v.handlers[cmdvdri.SaveDIDCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// GetDID retrieves the did from the store.
func (v *VDRI) GetDID(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdvdri.IDArg{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(v.handlers[cmdvdri.GetDIDCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// GetDIDRecords retrieves the did doc containing name and didID.
func (v *VDRI) GetDIDRecords(request *models.RequestEnvelope) *models.ResponseEnvelope {
	response, cmdErr := exec(v.handlers[cmdvdri.GetDIDsCommandMethod], request.Payload)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}
