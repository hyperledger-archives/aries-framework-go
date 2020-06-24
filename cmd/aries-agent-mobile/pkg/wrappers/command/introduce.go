/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	commandintroduce "github.com/hyperledger/aries-framework-go/pkg/controller/command/introduce"
)

// Introduce contains handler function for introduce protocol commands
type Introduce struct {
	handlers map[string]command.Exec
}

// Actions returns unfinished actions for the async usage
func (i *Introduce) Actions(_ *wrappers.IntroduceActionsRequest) *wrappers.IntroduceActionsResponse {
	actionsResponse := commandintroduce.ActionsResponse{}

	marshaledActionsResponse, err := json.Marshal(actionsResponse)
	if err != nil {
		return &wrappers.IntroduceActionsResponse{
			Error: &wrappers.CommandError{Message: fmt.Sprintf("failed to marshal actions response: %v", err)},
		}
	}

	responseWriter := bytes.NewBuffer(marshaledActionsResponse)
	handlerFunc := i.handlers[wrappers.HandlerActions]

	if err := handlerFunc(responseWriter, nil); err != nil {
		return &wrappers.IntroduceActionsResponse{
			Error: &wrappers.CommandError{
				Message: err.Error(),
				Code:    int(err.Code()),
				Type:    int(err.Type()),
			},
		}
	}

	_, err = responseWriter.Write(marshaledActionsResponse)
	if err != nil {
		return &wrappers.IntroduceActionsResponse{
			Error: &wrappers.CommandError{Message: err.Error()},
		}
	}

	return &wrappers.IntroduceActionsResponse{ActionsResponse: string(marshaledActionsResponse)}
}
