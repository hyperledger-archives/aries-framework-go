/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/jsonld/context"
)

// JSONLDContext contains necessary fields to support its operations.
type JSONLDContext struct {
	handlers map[string]command.Exec
}

// AddContext adds JSON-LD contexts to the underlying storage.
func (c *JSONLDContext) AddContext(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := context.AddRequest{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(c.handlers[context.AddContextCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}
