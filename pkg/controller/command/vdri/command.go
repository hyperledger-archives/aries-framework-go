/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdri

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
)

var logger = log.New("aries-framework/command/vdri")

// Error codes
const (
	// InvalidRequestErrorCode is typically a code for invalid requests
	InvalidRequestErrorCode = command.Code(iota + command.VDRI)

	// CreatePublicDIDError is for failures while creating public DIDs
	CreatePublicDIDError
)

const (
	// command name
	commandName = "vdri"

	// error messages
	errDIDMethodMandatory = "invalid method name"

	// command methods
	createPublicDIDCommandMethod = "CreatePublicDID"
)

// provider contains dependencies for the vdri controller command operations
// and is typically created by using aries.Context()
type provider interface {
	VDRIRegistry() vdriapi.Registry
}

// Command contains command operations provided by vdri controller
type Command struct {
	ctx provider
}

// New returns new vdri controller command instance
func New(ctx provider) *Command {
	return &Command{
		ctx: ctx,
	}
}

// GetHandlers returns list of all commands supported by this controller command
func (o *Command) GetHandlers() []command.Handler {
	return []command.Handler{
		cmdutil.NewCommandHandler(commandName, createPublicDIDCommandMethod, o.CreatePublicDID),
	}
}

// CreatePublicDID creates new public DID using agent VDRI
func (o *Command) CreatePublicDID(rw io.Writer, req io.Reader) command.Error {
	var request CreatePublicDIDArgs

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, commandName, createPublicDIDCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if request.Method == "" {
		logutil.LogDebug(logger, commandName, createPublicDIDCommandMethod, errDIDMethodMandatory)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errDIDMethodMandatory))
	}

	logger.Debugf("creating public DID for method[%s]", request.Method)

	doc, err := o.ctx.VDRIRegistry().Create(strings.ToLower(request.Method),
		vdriapi.WithRequestBuilder(getBasicRequestBuilder(request.RequestHeader)))
	if err != nil {
		logutil.LogError(logger, commandName, createPublicDIDCommandMethod, err.Error(),
			logutil.CreateKeyValueString("method", request.Method))
		return command.NewExecuteError(CreatePublicDIDError, err)
	}

	command.WriteNillableResponse(rw, CreatePublicDIDResponse{DID: doc}, logger)

	logutil.LogDebug(logger, commandName, createPublicDIDCommandMethod, "success",
		logutil.CreateKeyValueString("method", request.Method))

	return nil
}

// prepareBasicRequestBuilder is basic request builder for public DID creation
// request body format is : {"header": {raw header}, "payload": "payload"}
func getBasicRequestBuilder(header string) func(payload []byte) (io.Reader, error) {
	return func(payload []byte) (io.Reader, error) {
		encodedDoc := base64.URLEncoding.EncodeToString(payload)

		schema := &createPayloadSchema{
			Operation:           "create",
			DidDocument:         encodedDoc,
			NextUpdateOTPHash:   "",
			NextRecoveryOTPHash: "",
		}

		payload, err := json.Marshal(schema)
		if err != nil {
			return nil, err
		}

		request := struct {
			Protected json.RawMessage `json:"protected"`
			Payload   string          `json:"payload"`
		}{
			Protected: json.RawMessage(header),
			Payload:   base64.URLEncoding.EncodeToString(payload),
		}

		b, err := json.Marshal(request)
		if err != nil {
			return nil, err
		}

		return bytes.NewReader(b), nil
	}
}

// createPayloadSchema is the struct for create payload
type createPayloadSchema struct {

	// operation
	Operation string `json:"type"`

	// Encoded original DID document
	DidDocument string `json:"didDocument"`

	// Hash of the one-time password for the next update operation
	NextUpdateOTPHash string `json:"nextUpdateOtpHash"`

	// Hash of the one-time password for this recovery/checkpoint/revoke operation.
	NextRecoveryOTPHash string `json:"nextRecoveryOtpHash"`
}
