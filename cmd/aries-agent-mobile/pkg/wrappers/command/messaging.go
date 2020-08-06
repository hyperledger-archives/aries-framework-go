/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/messaging"
)

// Messaging defines methods for the Messaging controller.
type Messaging struct {
	handlers map[string]command.Exec
}

// RegisterService registers new message service to message handler registrar.
func (m *Messaging) RegisterService(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := messaging.RegisterMsgSvcArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(m.handlers[messaging.RegisterMessageServiceCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// UnregisterService unregisters given message service handler registrar.
func (m *Messaging) UnregisterService(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := messaging.UnregisterMsgSvcArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(m.handlers[messaging.UnregisterMessageServiceCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// Services returns list of registered service names.
func (m *Messaging) Services(request *models.RequestEnvelope) *models.ResponseEnvelope {
	response, cmdErr := exec(m.handlers[messaging.RegisteredServicesCommandMethod], request.Payload)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// Send sends new message to destination provided.
func (m *Messaging) Send(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := messaging.SendNewMessageArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(m.handlers[messaging.SendNewMessageCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// Reply sends reply to existing message.
func (m *Messaging) Reply(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := messaging.SendReplyMessageArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(m.handlers[messaging.SendReplyMessageCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// RegisterHTTPService registers new http over didcomm service to message handler registrar.
func (m *Messaging) RegisterHTTPService(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := messaging.RegisterHTTPMsgSvcArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(m.handlers[messaging.RegisterHTTPMessageServiceCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}
