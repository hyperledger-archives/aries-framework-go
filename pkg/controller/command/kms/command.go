/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

var logger = log.New("aries-framework/command/kms")

// Error codes
const (
	// InvalidRequestErrorCode is typically a code for invalid requests.
	InvalidRequestErrorCode = command.Code(iota + command.KMS)
	// CreateKeySetError is for failures while creating key set.
	CreateKeySetError
	// ImportKeyError is for failures while importing key.
	ImportKeyError
)

// constants for KMS commands
const (
	// command name
	CommandName = "kms"

	// command methods
	CreateKeySetCommandMethod = "CreateKeySet"
	ImportKeyCommandMethod    = "ImportKey"

	// error messages
	errEmptyKeyType = "key type is mandatory"
	errEmptyKeyID   = "key id is mandatory"
)

// provider contains dependencies for the kms command and is typically created by using aries.Context().
type provider interface {
	KMS() kms.KeyManager
}

// Command contains command operations provided by verifiable credential controller.
type Command struct {
	ctx       provider
	importKey func(privKey interface{}, kt kms.KeyType,
		opts ...kms.PrivateKeyOpts) (string, interface{}, error) // needed for unit test
}

// New returns new kms command instance.
func New(p provider) *Command {
	return &Command{
		ctx: p,
		importKey: func(privKey interface{}, kt kms.KeyType,
			opts ...kms.PrivateKeyOpts) (string, interface{}, error) {
			return p.KMS().ImportPrivateKey(privKey, kt, opts...)
		},
	}
}

// GetHandlers returns list of all commands supported by this controller command.
func (o *Command) GetHandlers() []command.Handler {
	return []command.Handler{
		cmdutil.NewCommandHandler(CommandName, CreateKeySetCommandMethod, o.CreateKeySet),
		cmdutil.NewCommandHandler(CommandName, ImportKeyCommandMethod, o.ImportKey),
	}
}

// CreateKeySet create a new public/private encryption and signature key pairs set.
func (o *Command) CreateKeySet(rw io.Writer, req io.Reader) command.Error {
	var request CreateKeySetRequest

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, CreateKeySetCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("failed request decode : %w", err))
	}

	if request.KeyType == "" {
		logutil.LogDebug(logger, CommandName, CreateKeySetCommandMethod, errEmptyKeyType)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyKeyType))
	}

	keyID, pubKeyBytes, err := o.ctx.KMS().CreateAndExportPubKeyBytes(kms.KeyType(request.KeyType))
	if err != nil {
		logutil.LogError(logger, CommandName, CreateKeySetCommandMethod, err.Error())
		return command.NewExecuteError(CreateKeySetError, err)
	}

	command.WriteNillableResponse(rw, &CreateKeySetResponse{
		KeyID:     keyID,
		PublicKey: base64.RawURLEncoding.EncodeToString(pubKeyBytes),
	}, logger)

	logutil.LogDebug(logger, CommandName, CreateKeySetCommandMethod, "success")

	return nil
}

// ImportKey import key.
func (o *Command) ImportKey(rw io.Writer, req io.Reader) command.Error {
	buf := new(bytes.Buffer)

	_, err := buf.ReadFrom(req)
	if err != nil {
		logutil.LogInfo(logger, CommandName, ImportKeyCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("failed request decode : %w", err))
	}

	var jwk jose.JWK
	if errUnmarshal := jwk.UnmarshalJSON(buf.Bytes()); errUnmarshal != nil {
		logutil.LogInfo(logger, CommandName, ImportKeyCommandMethod, errUnmarshal.Error())
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("failed request decode : %w", err))
	}

	if jwk.KeyID == "" {
		logutil.LogDebug(logger, CommandName, ImportKeyCommandMethod, errEmptyKeyID)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyKeyID))
	}

	var kType kms.KeyType

	switch jwk.Crv {
	case "Ed25519":
		kType = kms.ED25519Type
	case "P-256":
		kType = kms.ECDSAP256TypeIEEEP1363
	default:
		return command.NewValidationError(InvalidRequestErrorCode,
			fmt.Errorf("import key type not supported %s", jwk.Crv))
	}

	_, _, err = o.importKey(jwk.Key, kType, kms.WithKeyID(jwk.KeyID))
	if err != nil {
		logutil.LogError(logger, CommandName, ImportKeyCommandMethod, err.Error())
		return command.NewExecuteError(ImportKeyError, err)
	}

	command.WriteNillableResponse(rw, nil, logger)

	logutil.LogDebug(logger, CommandName, ImportKeyCommandMethod, "success")

	return nil
}
