/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/kms"
)

// KMS contains necessary fields to support its operations.
type KMS struct {
	handlers map[string]command.Exec
}

// CreateKeySet create a new public/private encryption and signature key pairs set.
func (k *KMS) CreateKeySet(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := kms.CreateKeySetRequest{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(k.handlers[kms.CreateKeySetCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// ImportKey imports a key.
func (k *KMS) ImportKey(request *models.RequestEnvelope) *models.ResponseEnvelope {
	response, cmdErr := exec(k.handlers[kms.ImportKeyCommandMethod], request.Payload)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}
