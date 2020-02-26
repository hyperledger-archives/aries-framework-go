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
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	vcstore "github.com/hyperledger/aries-framework-go/pkg/store/verifiable"
)

var logger = log.New("aries-framework/command/verifiable")

// Error codes
const (
	// InvalidRequestErrorCode is typically a code for invalid requests
	InvalidRequestErrorCode = command.Code(iota + command.VC)

	// ValidateCredential for validate vc error
	ValidateCredentialErrorCode

	// SaveCredentialErrorCode for save vc error
	SaveCredentialErrorCode

	// GetCredentialErrorCode for get vc error
	GetCredentialErrorCode
)

const (
	// command name
	commandName = "verifiable"

	// command methods
	validateCredentialCommandMethod = "ValidateCredential"
	saveCredentialCommandMethod     = "SaveCredential"
	getCredentialCommandMethod      = "GetCredential"

	// error messages
	errEmptyCredentialID = "credential id is mandatory"

	// log constants
	vcID = "vcID"
)

// provider contains dependencies for the verifiable command and is typically created by using aries.Context().
type provider interface {
	StorageProvider() storage.Provider
}

// Command contains command operations provided by verifiable credential controller.
type Command struct {
	vcStore *vcstore.Store
}

// New returns new verifiable credential controller command instance.
func New(p provider) (*Command, error) {
	vcStore, err := vcstore.New(p)
	if err != nil {
		return nil, fmt.Errorf("new vc store : %w", err)
	}

	return &Command{
		vcStore: vcStore,
	}, nil
}

// GetHandlers returns list of all commands supported by this controller command.
func (o *Command) GetHandlers() []command.Handler {
	return []command.Handler{
		cmdutil.NewCommandHandler(commandName, validateCredentialCommandMethod, o.ValidateCredential),
		cmdutil.NewCommandHandler(commandName, saveCredentialCommandMethod, o.SaveCredential),
		cmdutil.NewCommandHandler(commandName, getCredentialCommandMethod, o.GetCredential),
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
		logutil.LogInfo(logger, commandName, validateCredentialCommandMethod, "validate vc : "+err.Error())

		return command.NewValidationError(ValidateCredentialErrorCode, fmt.Errorf("validate vc : %w", err))
	}

	command.WriteNillableResponse(rw, nil, logger)

	logutil.LogDebug(logger, commandName, validateCredentialCommandMethod, "success")

	return nil
}

// SaveCredential saves the verifiable credential to the store.
func (o *Command) SaveCredential(rw io.Writer, req io.Reader) command.Error {
	request := &Credential{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, commandName, saveCredentialCommandMethod, "request decode : "+err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	vc, _, err := verifiable.NewCredential([]byte(request.VC))
	if err != nil {
		logutil.LogError(logger, commandName, saveCredentialCommandMethod, "parse vc : "+err.Error())

		return command.NewValidationError(SaveCredentialErrorCode, fmt.Errorf("parse vc : %w", err))
	}

	err = o.vcStore.SaveVC(vc)
	if err != nil {
		logutil.LogError(logger, commandName, saveCredentialCommandMethod, "save vc : "+err.Error())

		return command.NewValidationError(SaveCredentialErrorCode, fmt.Errorf("save vc : %w", err))
	}

	command.WriteNillableResponse(rw, nil, logger)

	logutil.LogDebug(logger, commandName, saveCredentialCommandMethod, "success")

	return nil
}

// GetCredential retrives the verifiable credential from the store.
func (o *Command) GetCredential(rw io.Writer, req io.Reader) command.Error {
	var request IDArg

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, commandName, getCredentialCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	if request.ID == "" {
		logutil.LogDebug(logger, commandName, getCredentialCommandMethod, errEmptyCredentialID)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyCredentialID))
	}

	vc, err := o.vcStore.GetVC(request.ID)
	if err != nil {
		logutil.LogError(logger, commandName, getCredentialCommandMethod, "get vc : "+err.Error(),
			logutil.CreateKeyValueString(vcID, request.ID))

		return command.NewValidationError(GetCredentialErrorCode, fmt.Errorf("get vc : %w", err))
	}

	vcBytes, err := vc.MarshalJSON()
	if err != nil {
		logutil.LogError(logger, commandName, getCredentialCommandMethod, "marshal vc : "+err.Error(),
			logutil.CreateKeyValueString(vcID, request.ID))

		return command.NewValidationError(GetCredentialErrorCode, fmt.Errorf("marshal vc : %w", err))
	}

	command.WriteNillableResponse(rw, &Credential{
		VC: string(vcBytes),
	}, logger)

	logutil.LogDebug(logger, commandName, getCredentialCommandMethod, "success",
		logutil.CreateKeyValueString(vcID, request.ID))

	return nil
}
