/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
)

func exec(handlerFunc command.Exec, request interface{}) ([]byte, *models.CommandError) {
	marshaledRequest, err := json.Marshal(request)
	if err != nil {
		return nil, &models.CommandError{Message: fmt.Sprintf("failed to marshal request: %v", err)}
	}

	responseWriter := &bytes.Buffer{}
	requestReader := bytes.NewReader(marshaledRequest)

	if err := handlerFunc(responseWriter, requestReader); err != nil {
		return nil, &models.CommandError{
			Message: err.Error(),
			Code:    int(err.Code()),
			Type:    int(err.Type()),
		}
	}

	return responseWriter.Bytes(), nil
}
