/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
)

var logger = log.New("aries-framework/command/verifiable")

// Error codes
const (
	// InvalidRequestErrorCode is typically a code for invalid requests
	InvalidRequestErrorCode = command.Code(iota + command.VC)

	// ValidateCredential for validate vc error
	ValidateCredentialErrorCode
)

const (
	// command name
	commandName = "verifiable"

	// command methods
	validateCredentialCommandMethod = "ValidateCredential"
)

// Command contains command operations provided by verifiable credential controller.
type Command struct {
}

// New returns new verifiable credential controller command instance.
func New() *Command {
	return &Command{}
}

// GetHandlers returns list of all commands supported by this controller command.
func (o *Command) GetHandlers() []command.Handler {
	return []command.Handler{
		cmdutil.NewCommandHandler(commandName, validateCredentialCommandMethod, o.ValidateCredential),
	}
}

// ValidateCredential validates the verifiable credential.
func (o *Command) ValidateCredential(rw io.Writer, req io.Reader) command.Error {
	request := &Credential{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, commandName, validateCredentialCommandMethod, "request decode : "+err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	// we are only validating the VC here, hence ignoring other return values
	// TODO https://github.com/hyperledger/aries-framework-go/issues/1316 VC Validate Command - Add keys for proof
	//  verification as options to the function.
	_, _, err = verifiable.NewCredential([]byte(request.VC))
	if err != nil {
		logutil.LogInfo(logger, commandName, validateCredentialCommandMethod, "new credential : "+err.Error())

		return command.NewValidationError(ValidateCredentialErrorCode, fmt.Errorf("new credential : %w", err))
	}

	command.WriteNillableResponse(rw, nil, logger)

	logutil.LogDebug(logger, commandName, validateCredentialCommandMethod, "success")

	return nil
}
