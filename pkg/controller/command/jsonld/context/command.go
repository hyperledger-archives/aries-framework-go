/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	// InvalidRequestErrorCode is an error code for invalid requests.
	InvalidRequestErrorCode = command.Code(iota + command.JSONLDContext)

	// AddContextErrorCode for add context error.
	AddContextErrorCode
)

const (
	// CommandName is a base command name for JSON-LD context operations.
	CommandName = "context"
	// AddContextCommandMethod is a command method for adding context.
	AddContextCommandMethod = "Add"
)

var logger = log.New("aries-framework/command/jsonld/context")

// provider contains dependencies for the JSON-LD context commands.
type provider interface {
	StorageProvider() storage.Provider
}

// Command contains command operations provided by context.
type Command struct {
	store storage.Store
}

// New returns a new JSON-LD context command instance.
func New(p provider) (*Command, error) {
	store, err := p.StorageProvider().OpenStore(jsonld.ContextsDBName)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}

	return &Command{store: store}, nil
}

// GetHandlers returns list of all commands supported by this controller command.
func (c *Command) GetHandlers() []command.Handler {
	return []command.Handler{
		cmdutil.NewCommandHandler(CommandName, AddContextCommandMethod, c.Add),
	}
}

// Add command adds JSON-LD contexts to the underlying storage.
func (c *Command) Add(rw io.Writer, req io.Reader) command.Error {
	var request AddRequest

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		return commandError(InvalidRequestErrorCode, fmt.Errorf("decode request: %w", err))
	}

	var ops []storage.Operation

	for _, doc := range request.Documents {
		if doc.URL == "" {
			return commandError(AddContextErrorCode, errors.New("context URL is mandatory"))
		}

		if doc.Content == nil {
			return commandError(AddContextErrorCode, errors.New("content is mandatory"))
		}

		content, err := ld.DocumentFromReader(bytes.NewReader(doc.Content))
		if err != nil {
			return commandError(AddContextErrorCode, fmt.Errorf("document from reader: %w", err))
		}

		rd := ld.RemoteDocument{
			DocumentURL: doc.DocumentURL,
			Document:    content,
		}

		b, err := json.Marshal(rd)
		if err != nil {
			return commandError(AddContextErrorCode, fmt.Errorf("marshal remote document: %w", err))
		}

		ops = append(ops, storage.Operation{Key: doc.URL, Value: b})
	}

	if err := c.store.Batch(ops); err != nil {
		return commandError(AddContextErrorCode, fmt.Errorf("save contexts: %w", err))
	}

	command.WriteNillableResponse(rw, nil, logger)

	logutil.LogDebug(logger, CommandName, AddContextCommandMethod, "success")

	return nil
}

func commandError(errorCode command.Code, err error) command.Error {
	logutil.LogInfo(logger, CommandName, AddContextCommandMethod, err.Error())

	return command.NewValidationError(errorCode, err)
}
