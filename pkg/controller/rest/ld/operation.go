/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ld

import (
	"bytes"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"

	ldcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/ld"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	"github.com/hyperledger/aries-framework-go/pkg/ld"
)

// constants for the JSON-LD operations.
const (
	OperationID                   = "/ld"
	AddContextsPath               = OperationID + "/context"
	AddRemoteProviderPath         = OperationID + "/remote-provider"
	RefreshRemoteProviderPath     = OperationID + "/remote-provider/{id}/refresh"
	DeleteRemoteProviderPath      = OperationID + "/remote-provider/{id}"
	GetAllRemoteProvidersPath     = OperationID + "/remote-providers"
	RefreshAllRemoteProvidersPath = OperationID + "/remote-providers/refresh"
)

// Operation contains REST operations provided by JSON-LD API.
type Operation struct {
	handlers []rest.Handler
	command  *ldcmd.Command
}

// New returns a new instance of JSON-LD REST controller.
func New(svc ld.Service, opts ...Option) *Operation {
	o := &options{httpClient: http.DefaultClient}

	for _, opt := range opts {
		opt(o)
	}

	cmd := ldcmd.New(svc, ldcmd.WithHTTPClient(o.httpClient))

	op := &Operation{command: cmd}
	op.registerHandlers()

	return op
}

func (o *Operation) registerHandlers() {
	o.handlers = []rest.Handler{
		cmdutil.NewHTTPHandler(AddContextsPath, http.MethodPost, o.AddContexts),
		cmdutil.NewHTTPHandler(AddRemoteProviderPath, http.MethodPost, o.AddRemoteProvider),
		cmdutil.NewHTTPHandler(RefreshRemoteProviderPath, http.MethodPost, o.RefreshRemoteProvider),
		cmdutil.NewHTTPHandler(DeleteRemoteProviderPath, http.MethodDelete, o.DeleteRemoteProvider),
		cmdutil.NewHTTPHandler(GetAllRemoteProvidersPath, http.MethodGet, o.GetAllRemoteProviders),
		cmdutil.NewHTTPHandler(RefreshAllRemoteProvidersPath, http.MethodPost, o.RefreshAllRemoteProviders),
	}
}

// GetRESTHandlers gets all controller API handlers available for this service.
func (o *Operation) GetRESTHandlers() []rest.Handler {
	return o.handlers
}

// AddContexts swagger:route POST /ld/context ld addContextsReq
//
// Adds JSON-LD contexts to the underlying storage.
//
// Responses:
//    default: genericError
func (o *Operation) AddContexts(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.AddContexts, rw, req.Body)
}

// AddRemoteProvider swagger:route POST /ld/remote-provider ld addRemoteProviderReq
//
// Adds remote provider and JSON-LD contexts from that provider to the underlying storage.
//
// Responses:
//    default: genericError
func (o *Operation) AddRemoteProvider(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.AddRemoteProvider, rw, req.Body)
}

// RefreshRemoteProvider swagger:route POST /ld/remote-provider/{id}/refresh ld refreshRemoteProviderReq
//
// Updates contexts from the remote provider.
//
// Responses:
//    default: genericError
func (o *Operation) RefreshRemoteProvider(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.RefreshRemoteProvider, rw, bytes.NewBufferString(fmt.Sprintf(`{
		"id":%q
	}`, mux.Vars(req)["id"])))
}

// DeleteRemoteProvider swagger:route DELETE /ld/remote-provider/{id} ld deleteRemoteProviderReq
//
// Deletes remote provider and JSON-LD contexts from that provider from the underlying storage.
//
// Responses:
//    default: genericError
func (o *Operation) DeleteRemoteProvider(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.DeleteRemoteProvider, rw, bytes.NewBufferString(fmt.Sprintf(`{
		"id":%q
	}`, mux.Vars(req)["id"])))
}

// GetAllRemoteProviders swagger:route GET /ld/remote-providers ld getAllRemoteProvidersReq
//
// Gets all remote providers from the underlying storage.
//
// Responses:
//    default: genericError
//    200: getAllRemoteProvidersResp
func (o *Operation) GetAllRemoteProviders(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.GetAllRemoteProviders, rw, req.Body)
}

// RefreshAllRemoteProviders swagger:route POST /ld/remote-providers/refresh ld refreshAllRemoteProvidersReq
//
// Updates contexts from all remote providers in the underlying storage.
//
// Responses:
//    default: genericError
func (o *Operation) RefreshAllRemoteProviders(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.RefreshAllRemoteProviders, rw, req.Body)
}

// HTTPClient represents an HTTP client.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type options struct {
	httpClient HTTPClient
}

// Option configures the JSON-LD controller options.
type Option func(opts *options)

// WithHTTPClient sets the custom HTTP client.
func WithHTTPClient(client HTTPClient) Option {
	return func(opts *options) {
		opts.httpClient = client
	}
}
