/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ld

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext/remote"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
	"github.com/hyperledger/aries-framework-go/pkg/ld"
)

const (
	// InvalidRequestErrorCode is an error code for invalid requests.
	InvalidRequestErrorCode = command.Code(iota + command.LD)

	// AddContextsErrorCode is an error code for AddContexts command.
	AddContextsErrorCode

	// AddRemoteProviderErrorCode is an error code for AddRemoteProvider command.
	AddRemoteProviderErrorCode

	// RefreshRemoteProviderErrorCode is an error code for RefreshRemoteProvider command.
	RefreshRemoteProviderErrorCode

	// DeleteRemoteProviderErrorCode is an error code for DeleteRemoteProvider command.
	DeleteRemoteProviderErrorCode

	// GetAllRemoteProvidersErrorCode is an error code for GetAllRemoteProviders command.
	GetAllRemoteProvidersErrorCode

	// RefreshAllRemoteProvidersErrorCode is an error code for RefreshAllRemoteProviders command.
	RefreshAllRemoteProvidersErrorCode
)

const (
	// CommandName is a base command name for JSON-LD operations.
	CommandName = "ld"

	// AddContextsCommandMethod is a command method for adding contexts.
	AddContextsCommandMethod = "AddContexts"

	// AddRemoteProviderCommandMethod is a command method for adding new remote provider.
	AddRemoteProviderCommandMethod = "AddRemoteProvider"

	// RefreshRemoteProviderCommandMethod is a command method for refreshing contexts from the remote provider.
	RefreshRemoteProviderCommandMethod = "RefreshRemoteProvider"

	// DeleteRemoteProviderCommandMethod is a command method for deleting provider and contexts from that provider.
	DeleteRemoteProviderCommandMethod = "DeleteRemoteProvider"

	// GetAllRemoteProvidersCommandMethod is a command method for getting list of all remote providers.
	GetAllRemoteProvidersCommandMethod = "GetAllRemoteProviders"

	// RefreshAllRemoteProvidersCommandMethod is a command method for refreshing contexts from all remote providers.
	RefreshAllRemoteProvidersCommandMethod = "RefreshAllRemoteProviders"
)

var logger = log.New("aries-framework/command/ld")

// Command contains command operations.
type Command struct {
	service    ld.Service
	httpClient HTTPClient
}

// New returns a new JSON-LD command instance.
func New(svc ld.Service, opts ...Option) *Command {
	cmd := &Command{
		service:    svc,
		httpClient: http.DefaultClient,
	}

	for _, opt := range opts {
		opt(cmd)
	}

	return cmd
}

// GetHandlers returns list of all commands supported by this controller command.
func (c *Command) GetHandlers() []command.Handler {
	return []command.Handler{
		cmdutil.NewCommandHandler(CommandName, AddContextsCommandMethod, c.AddContexts),
		cmdutil.NewCommandHandler(CommandName, AddRemoteProviderCommandMethod, c.AddRemoteProvider),
		cmdutil.NewCommandHandler(CommandName, RefreshRemoteProviderCommandMethod, c.RefreshRemoteProvider),
		cmdutil.NewCommandHandler(CommandName, DeleteRemoteProviderCommandMethod, c.DeleteRemoteProvider),
		cmdutil.NewCommandHandler(CommandName, GetAllRemoteProvidersCommandMethod, c.GetAllRemoteProviders),
		cmdutil.NewCommandHandler(CommandName, RefreshAllRemoteProvidersCommandMethod, c.RefreshAllRemoteProviders),
	}
}

// AddContexts command adds JSON-LD contexts to the underlying storage.
func (c *Command) AddContexts(w io.Writer, r io.Reader) command.Error {
	var req AddContextsRequest

	if err := json.NewDecoder(r).Decode(&req); err != nil {
		return commandError(AddContextsCommandMethod, InvalidRequestErrorCode, fmt.Errorf("decode request: %w", err))
	}

	if err := c.service.AddContexts(req.Documents); err != nil {
		return commandError(AddContextsCommandMethod, AddContextsErrorCode, fmt.Errorf("import contexts: %w", err))
	}

	command.WriteNillableResponse(w, nil, logger)

	logutil.LogDebug(logger, CommandName, AddContextsCommandMethod, "success")

	return nil
}

// AddRemoteProvider command adds remote provider and JSON-LD contexts from that provider.
func (c *Command) AddRemoteProvider(w io.Writer, r io.Reader) command.Error {
	var req AddRemoteProviderRequest

	if err := json.NewDecoder(r).Decode(&req); err != nil {
		return commandError(AddRemoteProviderCommandMethod, InvalidRequestErrorCode,
			fmt.Errorf("decode request: %w", err))
	}

	providerID, err := c.service.AddRemoteProvider(req.Endpoint, remote.WithHTTPClient(c.httpClient))
	if err != nil {
		return commandError(AddRemoteProviderCommandMethod, AddRemoteProviderErrorCode,
			fmt.Errorf("add remote provider: %w", err))
	}

	command.WriteNillableResponse(w, &ProviderID{ID: providerID}, logger)

	logutil.LogDebug(logger, CommandName, AddRemoteProviderCommandMethod, "success")

	return nil
}

// RefreshRemoteProvider command updates contexts from the remote provider.
func (c *Command) RefreshRemoteProvider(w io.Writer, r io.Reader) command.Error {
	var req ProviderID

	if err := json.NewDecoder(r).Decode(&req); err != nil {
		return commandError(RefreshRemoteProviderCommandMethod, InvalidRequestErrorCode,
			fmt.Errorf("decode request: %w", err))
	}

	if err := c.service.RefreshRemoteProvider(req.ID, remote.WithHTTPClient(c.httpClient)); err != nil {
		return commandError(RefreshRemoteProviderCommandMethod, RefreshRemoteProviderErrorCode,
			fmt.Errorf("refresh remote provider: %w", err))
	}

	command.WriteNillableResponse(w, nil, logger)

	logutil.LogDebug(logger, CommandName, RefreshRemoteProviderCommandMethod, "success")

	return nil
}

// DeleteRemoteProvider command deletes remote provider and contexts from that provider.
func (c *Command) DeleteRemoteProvider(w io.Writer, r io.Reader) command.Error {
	var req ProviderID

	if err := json.NewDecoder(r).Decode(&req); err != nil {
		return commandError(DeleteRemoteProviderCommandMethod, InvalidRequestErrorCode,
			fmt.Errorf("decode request: %w", err))
	}

	if err := c.service.DeleteRemoteProvider(req.ID, remote.WithHTTPClient(c.httpClient)); err != nil {
		return commandError(DeleteRemoteProviderCommandMethod, DeleteRemoteProviderErrorCode,
			fmt.Errorf("delete remote provider: %w", err))
	}

	command.WriteNillableResponse(w, nil, logger)

	logutil.LogDebug(logger, CommandName, DeleteRemoteProviderCommandMethod, "success")

	return nil
}

// GetAllRemoteProviders command gets all remote providers.
func (c *Command) GetAllRemoteProviders(w io.Writer, _ io.Reader) command.Error {
	records, err := c.service.GetAllRemoteProviders()
	if err != nil {
		return commandError(GetAllRemoteProvidersCommandMethod, GetAllRemoteProvidersErrorCode,
			fmt.Errorf("get remote providers: %w", err))
	}

	command.WriteNillableResponse(w, &GetAllRemoteProvidersResponse{Providers: records}, logger)

	logutil.LogDebug(logger, CommandName, GetAllRemoteProvidersCommandMethod, "success")

	return nil
}

// RefreshAllRemoteProviders command updates contexts from all remote providers.
func (c *Command) RefreshAllRemoteProviders(w io.Writer, _ io.Reader) command.Error {
	if err := c.service.RefreshAllRemoteProviders(remote.WithHTTPClient(c.httpClient)); err != nil {
		return commandError(RefreshAllRemoteProvidersCommandMethod, RefreshAllRemoteProvidersErrorCode,
			fmt.Errorf("refresh remote providers: %w", err))
	}

	command.WriteNillableResponse(w, nil, logger)

	logutil.LogDebug(logger, CommandName, RefreshAllRemoteProvidersCommandMethod, "success")

	return nil
}

func commandError(action string, errorCode command.Code, err error) command.Error {
	logutil.LogInfo(logger, CommandName, action, err.Error())

	return command.NewValidationError(errorCode, err)
}

// Option configures the JSON-LD command.
type Option func(cmd *Command)

// HTTPClient represents an HTTP client.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// WithHTTPClient sets the custom HTTP client.
func WithHTTPClient(client HTTPClient) Option {
	return func(cmd *Command) {
		cmd.httpClient = client
	}
}
