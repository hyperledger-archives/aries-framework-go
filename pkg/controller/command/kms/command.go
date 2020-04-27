/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
)

var logger = log.New("aries-framework/command/kms")

// Error codes
const (
	// InvalidRequestErrorCode is typically a code for invalid requests
	InvalidRequestErrorCode = command.Code(iota + command.VC)
	// CreateKeySetError is for failures while creating key set
	CreateKeySetError
)

const (
	// command name
	commandName = "kms"

	// command methods
	createKeySetCommandMethod = "CreateKeySet"

	// error messages
	errEmptyKeyType = "key type is mandatory"
)

// provider contains dependencies for the kms command and is typically created by using aries.Context().
type provider interface {
	KMS() kms.KeyManager
}

// Command contains command operations provided by verifiable credential controller.
type Command struct {
	ctx               provider
	exportPubKeyBytes func(id string) ([]byte, error) // needed for unit test

}

// New returns new kms command instance.
func New(p provider) *Command {
	return &Command{
		ctx: p,
		exportPubKeyBytes: func(id string) ([]byte, error) {
			k, ok := p.KMS().(*localkms.LocalKMS)
			if !ok {
				return nil, fmt.Errorf("kms is not LocalKMS type")
			}

			return k.ExportPubKeyBytes(id)
		},
	}
}

// GetHandlers returns list of all commands supported by this controller command.
func (o *Command) GetHandlers() []command.Handler {
	return []command.Handler{
		cmdutil.NewCommandHandler(commandName, createKeySetCommandMethod, o.CreateKeySet),
	}
}

// CreateKeySet create a new public/private encryption and signature key pairs set.
func (o *Command) CreateKeySet(rw io.Writer, req io.Reader) command.Error {
	var request CreateKeySetRequest

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, commandName, createKeySetCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("failed request decode : %w", err))
	}

	if request.KeyType == "" {
		logutil.LogDebug(logger, commandName, createKeySetCommandMethod, errEmptyKeyType)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyKeyType))
	}

	keyID, _, err := o.ctx.KMS().Create(kms.KeyType(request.KeyType))
	if err != nil {
		logutil.LogError(logger, commandName, createKeySetCommandMethod, err.Error())
		return command.NewExecuteError(CreateKeySetError, err)
	}

	pubKeyBytes, err := o.exportPubKeyBytes(keyID)
	if err != nil {
		logutil.LogError(logger, commandName, createKeySetCommandMethod, err.Error())
		return command.NewExecuteError(CreateKeySetError, err)
	}

	command.WriteNillableResponse(rw, &CreateKeySetResponse{
		KeyID:     base64.RawURLEncoding.EncodeToString([]byte(keyID)),
		PublicKey: base64.RawURLEncoding.EncodeToString(pubKeyBytes),
	}, logger)

	logutil.LogDebug(logger, commandName, createKeySetCommandMethod, "success")

	return nil
}
