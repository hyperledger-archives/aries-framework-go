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
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	didstore "github.com/hyperledger/aries-framework-go/pkg/store/did"
)

var logger = log.New("aries-framework/command/vdri")

// Error codes
const (
	// InvalidRequestErrorCode is typically a code for invalid requests
	InvalidRequestErrorCode = command.Code(iota + command.VDRI)

	// CreatePublicDIDError is for failures while creating public DIDs
	CreatePublicDIDError

	// SaveDIDErrorCode for save did error
	SaveDIDErrorCode

	// GetDIDErrorCode for get did error
	GetDIDErrorCode

	// ResolveDIDErrorCode for get did error
	ResolveDIDErrorCode
)

const (
	// command name
	commandName = "vdri"

	// command methods
	createPublicDIDCommandMethod = "CreatePublicDID"
	saveDIDCommandMethod         = "SaveDID"
	getDIDsCommandMethod         = "GetDIDRecords"
	getDIDCommandMethod          = "GetDID"
	resolveDIDCommandMethod      = "ResolveDID"

	// error messages
	errDIDMethodMandatory = "invalid method name"
	errEmptyDIDName       = "name is mandatory"
	errEmptyDIDID         = "did is mandatory"

	// log constants
	didID = "did"
)

// provider contains dependencies for the vdri controller command operations
// and is typically created by using aries.Context()
type provider interface {
	VDRIRegistry() vdriapi.Registry
	StorageProvider() storage.Provider
}

// Command contains command operations provided by vdri controller
type Command struct {
	ctx      provider
	didStore *didstore.Store
}

// New returns new vdri controller command instance
func New(ctx provider) (*Command, error) {
	didStore, err := didstore.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("new did store : %w", err)
	}

	return &Command{
		ctx:      ctx,
		didStore: didStore,
	}, nil
}

// GetHandlers returns list of all commands supported by this controller command
func (o *Command) GetHandlers() []command.Handler {
	return []command.Handler{
		cmdutil.NewCommandHandler(commandName, createPublicDIDCommandMethod, o.CreatePublicDID),
		cmdutil.NewCommandHandler(commandName, saveDIDCommandMethod, o.SaveDID),
		cmdutil.NewCommandHandler(commandName, getDIDCommandMethod, o.GetDID),
		cmdutil.NewCommandHandler(commandName, getDIDsCommandMethod, o.GetDIDRecords),
		cmdutil.NewCommandHandler(commandName, resolveDIDCommandMethod, o.ResolveDID),
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

	docByte, err := doc.JSONBytes()

	if err != nil {
		logutil.LogError(logger, commandName, createPublicDIDCommandMethod, err.Error(),
			logutil.CreateKeyValueString("method", request.Method))
		return command.NewExecuteError(CreatePublicDIDError, err)
	}

	command.WriteNillableResponse(rw, CreatePublicDIDResponse{DID: docByte}, logger)

	logutil.LogDebug(logger, commandName, createPublicDIDCommandMethod, "success",
		logutil.CreateKeyValueString("method", request.Method))

	return nil
}

// ResolveDID resolve did
func (o *Command) ResolveDID(rw io.Writer, req io.Reader) command.Error {
	var request IDArg

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, commandName, resolveDIDCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	if request.ID == "" {
		logutil.LogDebug(logger, commandName, resolveDIDCommandMethod, errEmptyDIDID)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyDIDID))
	}

	didDoc, err := o.ctx.VDRIRegistry().Resolve(request.ID)
	if err != nil {
		logutil.LogError(logger, commandName, resolveDIDCommandMethod, "resolve did doc: "+err.Error(),
			logutil.CreateKeyValueString(didID, request.ID))

		return command.NewValidationError(ResolveDIDErrorCode, fmt.Errorf("resolve did doc: %w", err))
	}

	docBytes, err := didDoc.JSONBytes()
	if err != nil {
		logutil.LogError(logger, commandName, resolveDIDCommandMethod, "unmarshal did doc: "+err.Error(),
			logutil.CreateKeyValueString(didID, request.ID))

		return command.NewValidationError(ResolveDIDErrorCode, fmt.Errorf("unmarshal did doc: %w", err))
	}

	command.WriteNillableResponse(rw, &Document{
		DID: json.RawMessage(docBytes),
	}, logger)

	logutil.LogDebug(logger, commandName, resolveDIDCommandMethod, "success",
		logutil.CreateKeyValueString(didID, request.ID))

	return nil
}

// SaveDID saves the did doc to the store
func (o *Command) SaveDID(rw io.Writer, req io.Reader) command.Error {
	request := &DIDArgs{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, commandName, saveDIDCommandMethod, "request decode : "+err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	if request.Name == "" {
		logutil.LogDebug(logger, commandName, saveDIDCommandMethod, errEmptyDIDName)
		return command.NewValidationError(SaveDIDErrorCode, fmt.Errorf(errEmptyDIDName))
	}

	didDoc, err := did.ParseDocument(request.DID)

	if err != nil {
		logutil.LogError(logger, commandName, saveDIDCommandMethod, "parse did doc: "+err.Error())
		return command.NewValidationError(SaveDIDErrorCode, fmt.Errorf("parse did doc: %w", err))
	}

	err = o.didStore.SaveDID(request.Name, didDoc)
	if err != nil {
		logutil.LogError(logger, commandName, saveDIDCommandMethod, "save did doc: "+err.Error())

		return command.NewValidationError(SaveDIDErrorCode, fmt.Errorf("save did doc: %w", err))
	}

	command.WriteNillableResponse(rw, nil, logger)

	logutil.LogDebug(logger, commandName, saveDIDCommandMethod, "success")

	return nil
}

// GetDID retrieves the did from the store.
func (o *Command) GetDID(rw io.Writer, req io.Reader) command.Error {
	var request IDArg

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, commandName, getDIDCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	if request.ID == "" {
		logutil.LogDebug(logger, commandName, getDIDCommandMethod, errEmptyDIDID)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyDIDID))
	}

	didDoc, err := o.didStore.GetDID(request.ID)
	if err != nil {
		logutil.LogError(logger, commandName, getDIDCommandMethod, "get did doc: "+err.Error(),
			logutil.CreateKeyValueString(didID, request.ID))

		return command.NewValidationError(GetDIDErrorCode, fmt.Errorf("get did doc: %w", err))
	}

	docBytes, err := didDoc.JSONBytes()
	if err != nil {
		logutil.LogError(logger, commandName, getDIDCommandMethod, "unmarshal did doc: "+err.Error(),
			logutil.CreateKeyValueString(didID, request.ID))

		return command.NewValidationError(GetDIDErrorCode, fmt.Errorf("unmarshal did doc: %w", err))
	}

	command.WriteNillableResponse(rw, &Document{
		DID: json.RawMessage(docBytes),
	}, logger)

	logutil.LogDebug(logger, commandName, getDIDCommandMethod, "success",
		logutil.CreateKeyValueString(didID, request.ID))

	return nil
}

// GetDIDRecords retrieves the did doc containing name and didID. //TODO Add pagination feature #1566
func (o *Command) GetDIDRecords(rw io.Writer, req io.Reader) command.Error {
	didRecords := o.didStore.GetDIDRecords()

	command.WriteNillableResponse(rw, &DIDRecordResult{
		Result: didRecords,
	}, logger)

	logutil.LogDebug(logger, commandName, getDIDsCommandMethod, "success")

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
