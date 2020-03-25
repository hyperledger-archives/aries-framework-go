/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"io"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
)

var logger = log.New("aries-framework/command/kms")

// Error codes
const (
	// CreateKeySetError is for failures while creating key set
	CreateKeySetError = command.Code(iota + command.KMS)
)

const (
	// command name
	commandName = "kms"

	// command methods
	createKeySetCommandMethod = "CreateKeySet"
)

// provider contains dependencies for the kms command and is typically created by using aries.Context().
type provider interface {
	LegacyKMS() legacykms.KeyManager
}

// Command contains command operations provided by verifiable credential controller.
type Command struct {
	ctx provider
}

// New returns new kms command instance.
func New(p provider) *Command {
	return &Command{
		ctx: p,
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
	encryptionPublicKey, signaturePublicKey, err := o.ctx.LegacyKMS().CreateKeySet()
	if err != nil {
		logutil.LogError(logger, commandName, createKeySetCommandMethod, err.Error())
		return command.NewExecuteError(CreateKeySetError, err)
	}

	command.WriteNillableResponse(rw, &CreateKeySetResponse{
		EncryptionPublicKey: encryptionPublicKey,
		SignaturePublicKey:  signaturePublicKey,
	}, logger)

	logutil.LogDebug(logger, commandName, createKeySetCommandMethod, "success")

	return nil
}
