/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdr

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
	didstore "github.com/hyperledger/aries-framework-go/pkg/store/did"
	storage "github.com/hyperledger/aries-framework-go/spi/storage"
)

var logger = log.New("aries-framework/command/vdr")

// Error codes.
const (
	// InvalidRequestErrorCode is typically a code for invalid requests.
	InvalidRequestErrorCode = command.Code(iota + command.VDR)

	// SaveDIDErrorCode for save did error.
	SaveDIDErrorCode

	// GetDIDErrorCode for get did error.
	GetDIDErrorCode

	// ResolveDIDErrorCode for get did error.
	ResolveDIDErrorCode

	// CreateDIDErrorCode for create did error.
	CreateDIDErrorCode
)

// constants for the VDR controller's methods.
const (
	// command name.
	CommandName = "vdr"

	// command methods.
	SaveDIDCommandMethod    = "SaveDID"
	GetDIDsCommandMethod    = "GetDIDRecords"
	GetDIDCommandMethod     = "GetDID"
	ResolveDIDCommandMethod = "ResolveDID"
	CreateDIDCommandMethod  = "CreateDID"

	// error messages.
	errEmptyDIDName   = "name is mandatory"
	errEmptyDIDID     = "did is mandatory"
	errEmptyDIDMETHOD = "did method is mandatory"

	// log constants.
	didID = "did"
)

// provider contains dependencies for the vdr controller command operations
// and is typically created by using aries.Context().
type provider interface {
	VDRegistry() vdrapi.Registry
	StorageProvider() storage.Provider
}

// Command contains command operations provided by vdr controller.
type Command struct {
	ctx      provider
	didStore *didstore.Store
}

// New returns new vdr controller command instance.
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

// GetHandlers returns list of all commands supported by this controller command.
func (o *Command) GetHandlers() []command.Handler {
	return []command.Handler{
		cmdutil.NewCommandHandler(CommandName, SaveDIDCommandMethod, o.SaveDID),
		cmdutil.NewCommandHandler(CommandName, GetDIDCommandMethod, o.GetDID),
		cmdutil.NewCommandHandler(CommandName, GetDIDsCommandMethod, o.GetDIDRecords),
		cmdutil.NewCommandHandler(CommandName, ResolveDIDCommandMethod, o.ResolveDID),
		cmdutil.NewCommandHandler(CommandName, CreateDIDCommandMethod, o.CreateDID),
	}
}

// CreateDID create did.
func (o *Command) CreateDID(rw io.Writer, req io.Reader) command.Error {
	var request CreateDIDRequest

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, CreateDIDCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	if request.Method == "" {
		logutil.LogDebug(logger, CommandName, CreateDIDCommandMethod, errEmptyDIDMETHOD)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyDIDMETHOD))
	}

	didDoc := &did.Doc{}

	if len(request.DID) != 0 {
		didDoc, err = did.ParseDocument(request.DID)
		if err != nil {
			logutil.LogError(logger, CommandName, CreateDIDCommandMethod, "parse did doc: "+err.Error())

			return command.NewValidationError(CreateDIDErrorCode, fmt.Errorf("parse did doc: %w", err))
		}
	}

	opts := make([]vdrapi.DIDMethodOption, 0)

	for k, v := range request.Opts {
		opts = append(opts, vdrapi.WithOption(k, v))
	}

	doc, err := o.ctx.VDRegistry().Create(request.Method, didDoc, opts...)
	if err != nil {
		logutil.LogError(logger, CommandName, CreateDIDCommandMethod, "create did doc: "+err.Error())

		return command.NewValidationError(CreateDIDErrorCode, fmt.Errorf("create did doc: %w", err))
	}

	docBytes, err := doc.DIDDocument.JSONBytes()
	if err != nil {
		logutil.LogError(logger, CommandName, CreateDIDCommandMethod, "unmarshal did doc: "+err.Error())

		return command.NewValidationError(CreateDIDErrorCode, fmt.Errorf("unmarshal did doc: %w", err))
	}

	command.WriteNillableResponse(rw, &Document{
		DID: docBytes,
	}, logger)

	logutil.LogDebug(logger, CommandName, CreateDIDCommandMethod, "success")

	return nil
}

// ResolveDID resolve did.
func (o *Command) ResolveDID(rw io.Writer, req io.Reader) command.Error {
	var request IDArg

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, ResolveDIDCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	if request.ID == "" {
		logutil.LogDebug(logger, CommandName, ResolveDIDCommandMethod, errEmptyDIDID)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyDIDID))
	}

	doc, err := o.ctx.VDRegistry().Resolve(request.ID)
	if err != nil {
		logutil.LogError(logger, CommandName, ResolveDIDCommandMethod, "resolve did doc: "+err.Error(),
			logutil.CreateKeyValueString(didID, request.ID))

		return command.NewValidationError(ResolveDIDErrorCode, fmt.Errorf("resolve did doc: %w", err))
	}

	docBytes, err := doc.JSONBytes()
	if err != nil {
		logutil.LogError(logger, CommandName, ResolveDIDCommandMethod, "unmarshal did resolution response: "+err.Error(),
			logutil.CreateKeyValueString(didID, request.ID))

		return command.NewValidationError(ResolveDIDErrorCode, fmt.Errorf("unmarshal did resolution response: %w", err))
	}

	_, err = rw.Write(docBytes)
	if err != nil {
		logger.Errorf("Unable to send error response, %s", err)
	}

	logutil.LogDebug(logger, CommandName, ResolveDIDCommandMethod, "success",
		logutil.CreateKeyValueString(didID, request.ID))

	return nil
}

// SaveDID saves the did doc to the store.
func (o *Command) SaveDID(rw io.Writer, req io.Reader) command.Error {
	request := &DIDArgs{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, SaveDIDCommandMethod, "request decode : "+err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	if request.Name == "" {
		logutil.LogDebug(logger, CommandName, SaveDIDCommandMethod, errEmptyDIDName)
		return command.NewValidationError(SaveDIDErrorCode, fmt.Errorf(errEmptyDIDName))
	}

	didDoc, err := did.ParseDocument(request.DID)
	if err != nil {
		logutil.LogError(logger, CommandName, SaveDIDCommandMethod, "parse did doc: "+err.Error())
		return command.NewValidationError(SaveDIDErrorCode, fmt.Errorf("parse did doc: %w", err))
	}

	err = o.didStore.SaveDID(request.Name, didDoc)
	if err != nil {
		logutil.LogError(logger, CommandName, SaveDIDCommandMethod, "save did doc: "+err.Error())

		return command.NewValidationError(SaveDIDErrorCode, fmt.Errorf("save did doc: %w", err))
	}

	command.WriteNillableResponse(rw, nil, logger)

	logutil.LogDebug(logger, CommandName, SaveDIDCommandMethod, "success")

	return nil
}

// GetDID retrieves the did from the store.
func (o *Command) GetDID(rw io.Writer, req io.Reader) command.Error {
	var request IDArg

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, GetDIDCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	if request.ID == "" {
		logutil.LogDebug(logger, CommandName, GetDIDCommandMethod, errEmptyDIDID)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyDIDID))
	}

	didDoc, err := o.didStore.GetDID(request.ID)
	if err != nil {
		logutil.LogError(logger, CommandName, GetDIDCommandMethod, "get did doc: "+err.Error(),
			logutil.CreateKeyValueString(didID, request.ID))

		return command.NewValidationError(GetDIDErrorCode, fmt.Errorf("get did doc: %w", err))
	}

	docBytes, err := didDoc.JSONBytes()
	if err != nil {
		logutil.LogError(logger, CommandName, GetDIDCommandMethod, "unmarshal did doc: "+err.Error(),
			logutil.CreateKeyValueString(didID, request.ID))

		return command.NewValidationError(GetDIDErrorCode, fmt.Errorf("unmarshal did doc: %w", err))
	}

	command.WriteNillableResponse(rw, &Document{
		DID: json.RawMessage(docBytes),
	}, logger)

	logutil.LogDebug(logger, CommandName, GetDIDCommandMethod, "success",
		logutil.CreateKeyValueString(didID, request.ID))

	return nil
}

// GetDIDRecords retrieves the did doc containing name and didID. //TODO Add pagination feature #1566.
func (o *Command) GetDIDRecords(rw io.Writer, req io.Reader) command.Error {
	didRecords := o.didStore.GetDIDRecords()

	command.WriteNillableResponse(rw, &DIDRecordResult{
		Result: didRecords,
	}, logger)

	logutil.LogDebug(logger, CommandName, GetDIDsCommandMethod, "success")

	return nil
}
