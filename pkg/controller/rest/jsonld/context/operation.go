/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"fmt"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command/jsonld/context"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// constants for the JSON-LD context operations.
const (
	OperationID    = "/context"
	AddContextPath = OperationID + "/add"
)

type provider interface {
	StorageProvider() storage.Provider
}

// Operation contains REST operations provided by JSON-LD context API.
type Operation struct {
	handlers []rest.Handler
	command  *context.Command
}

// New returns a new instance of JSON-LD context REST controller.
func New(p provider) (*Operation, error) {
	cmd, err := context.New(p)
	if err != nil {
		return nil, fmt.Errorf("create jsonld context command: %w", err)
	}

	o := &Operation{command: cmd}
	o.registerHandlers()

	return o, nil
}

func (o *Operation) registerHandlers() {
	o.handlers = []rest.Handler{
		cmdutil.NewHTTPHandler(AddContextPath, http.MethodPost, o.Add),
	}
}

// GetRESTHandlers gets all controller API handlers available for this service.
func (o *Operation) GetRESTHandlers() []rest.Handler {
	return o.handlers
}

// Add swagger:route POST /context/add context addContextReq
//
// Adds JSON-LD context documents to the underlying storage.
//
// Responses:
//    default: genericError
func (o *Operation) Add(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.Add, rw, req.Body)
}
