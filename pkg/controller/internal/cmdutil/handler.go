/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cmdutil

import (
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
)

// NewHTTPHandler returns instance of HTTPHandler which can be used handle
// http requests.
func NewHTTPHandler(path, method string, handle http.HandlerFunc) *HTTPHandler {
	return &HTTPHandler{path: path, method: method, handle: handle}
}

// HTTPHandler contains REST API handling details which can be used to build routers
// for http requests for given path.
type HTTPHandler struct {
	path   string
	method string
	handle http.HandlerFunc
}

// Path returns http request path.
func (h *HTTPHandler) Path() string {
	return h.path
}

// Method returns http request method type.
func (h *HTTPHandler) Method() string {
	return h.method
}

// Handle returns http request handle func.
func (h *HTTPHandler) Handle() http.HandlerFunc {
	return h.handle
}

// NewCommandHandler returns instance of CommandHandler which can be used handle
// controller commands.
func NewCommandHandler(name, method string, exec command.Exec) *CommandHandler {
	return &CommandHandler{name: name, method: method, handle: exec}
}

// CommandHandler contains command handling details which can be used to build controller
// commands.
type CommandHandler struct {
	name   string
	method string
	handle command.Exec
}

// Name of the command.
func (c *CommandHandler) Name() string {
	return c.name
}

// Method name of the command.
func (c *CommandHandler) Method() string {
	return c.method
}

// Handle returns execute function of the command handler.
func (c *CommandHandler) Handle() command.Exec {
	return c.handle
}
