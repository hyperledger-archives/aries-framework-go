/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package legacyconnection

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/gorilla/mux"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/legacyconnection"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// constants for endpoints of legacy-connection.
const (
	OperationID                  = "/legacy/connections"
	CreateInvitationPath         = OperationID + "/create-invitation"
	CreateImplicitInvitationPath = OperationID + "/create-implicit-invitation"
	ReceiveInvitationPath        = OperationID + "/receive-invitation"
	AcceptInvitationPath         = OperationID + "/{id}/accept-invitation"
	Connections                  = OperationID
	ConnectionsByID              = OperationID + "/{id}"
	AcceptConnectionRequest      = OperationID + "/{id}/accept-request"
	CreateConnection             = OperationID + "/create"
	RemoveConnection             = OperationID + "/{id}/remove"
)

// provider contains dependencies for the legacy-connection protocol and is typically created by using aries.Context().
type provider interface {
	Service(id string) (interface{}, error)
	KMS() kms.KeyManager
	ServiceEndpoint() string
	StorageProvider() storage.Provider
	ProtocolStateStorageProvider() storage.Provider
	KeyType() kms.KeyType
	KeyAgreementType() kms.KeyType
	MediaTypeProfiles() []string
}

// New returns new legacy-connection rest client protocol instance.
func New(ctx provider, notifier command.Notifier, defaultLabel string, autoAccept bool) (*Operation, error) {
	dxcmd, err := legacyconnection.New(ctx, notifier, defaultLabel, autoAccept)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize legacy-connection command : %w", err)
	}

	o := &Operation{command: dxcmd}
	o.registerHandler()

	return o, nil
}

// Operation is controller REST service controller for legacy-connection.
type Operation struct {
	command  *legacyconnection.Command
	handlers []rest.Handler
}

// GetRESTHandlers get all controller API handler available for this protocol service.
func (c *Operation) GetRESTHandlers() []rest.Handler {
	return c.handlers
}

// registerHandler register handlers to be exposed from this protocol service as REST API endpoints.
func (c *Operation) registerHandler() {
	// Add more protocol endpoints here to expose them as controller API endpoints
	c.handlers = []rest.Handler{
		cmdutil.NewHTTPHandler(Connections, http.MethodGet, c.QueryConnections),
		cmdutil.NewHTTPHandler(ConnectionsByID, http.MethodGet, c.QueryConnectionByID),
		cmdutil.NewHTTPHandler(CreateInvitationPath, http.MethodPost, c.CreateInvitation),
		cmdutil.NewHTTPHandler(CreateImplicitInvitationPath, http.MethodPost, c.CreateImplicitInvitation),
		cmdutil.NewHTTPHandler(ReceiveInvitationPath, http.MethodPost, c.ReceiveInvitation),
		cmdutil.NewHTTPHandler(AcceptInvitationPath, http.MethodPost, c.AcceptInvitation),
		cmdutil.NewHTTPHandler(AcceptConnectionRequest, http.MethodPost, c.AcceptConnectionRequest),
		cmdutil.NewHTTPHandler(CreateConnection, http.MethodPost, c.CreateConnection),
		cmdutil.NewHTTPHandler(RemoveConnection, http.MethodPost, c.RemoveConnection),
	}
}

// CreateInvitation swagger:route POST /legacy/connections/create-invitation legacy-connection legacyCreateInvitation
//
// Creates a new connection invitation....
//
// Responses:
//    default: genericError
//        200: legacyCreateInvitationResponse
func (c *Operation) CreateInvitation(rw http.ResponseWriter, req *http.Request) {
	reqBytes, err := queryValuesAsJSON(req.URL.Query())
	if err != nil {
		rest.SendHTTPStatusError(rw, http.StatusBadRequest, legacyconnection.InvalidRequestErrorCode, err)
		return
	}

	rest.Execute(c.command.CreateInvitation, rw, bytes.NewReader(reqBytes))
}

// ReceiveInvitation swagger:route POST /legacy/connections/receive-invitation legacy-connection legacyReceiveInvitation
//
// Receive a new connection invitation....
//
// Responses:
//    default: genericError
//        200: legacyReceiveInvitationResponse
func (c *Operation) ReceiveInvitation(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(c.command.ReceiveInvitation, rw, req.Body)
}

// AcceptInvitation swagger:route POST /legacy/connections/{id}/accept-invitation legacy-connection legacyAcceptInvitation
//
// Accept a stored connection invitation....
//
// Responses:
//    default: genericError
//        200: legacyAcceptInvitationResponse
func (c *Operation) AcceptInvitation(rw http.ResponseWriter, req *http.Request) {
	id, found := getIDFromRequest(rw, req)
	if !found {
		return
	}

	request := fmt.Sprintf(`{"id":"%s", "public":"%s", "router_connections": "%s"}`,
		id, req.URL.Query().Get("public"), req.URL.Query().Get("router_connections"))

	rest.Execute(c.command.AcceptInvitation, rw, bytes.NewBufferString(request))
}

// CreateImplicitInvitation swagger:route POST /legacy/connections/create-implicit-invitation legacy-connection legacyImplicitInvitation
//
//  Create implicit invitation using inviter DID.
//
// Responses:
//    default: genericError
//        200: legacyImplicitInvitationResponse
func (c *Operation) CreateImplicitInvitation(rw http.ResponseWriter, req *http.Request) {
	reqBytes, err := queryValuesAsJSON(req.URL.Query())
	if err != nil {
		rest.SendHTTPStatusError(rw, http.StatusBadRequest, legacyconnection.InvalidRequestErrorCode, err)
		return
	}

	rest.Execute(c.command.CreateImplicitInvitation, rw, bytes.NewReader(reqBytes))
}

// AcceptConnectionRequest swagger:route POST /legacy/connections/{id}/accept-request legacy-connection legacyAcceptRequest
//
// Accepts a stored connection request.
//
// Responses:
//    default: genericError
//        200: legacyAcceptConnectionResponse
func (c *Operation) AcceptConnectionRequest(rw http.ResponseWriter, req *http.Request) {
	id, found := getIDFromRequest(rw, req)
	if !found {
		return
	}

	request := fmt.Sprintf(`{"id":"%s", "public":"%s", "router_connections": "%s"}`,
		id, req.URL.Query().Get("public"), req.URL.Query().Get("router_connections"))

	rest.Execute(c.command.AcceptConnectionRequest, rw, bytes.NewBufferString(request))
}

// QueryConnections swagger:route GET /legacy/connections legacy-connection legacyQueryConnections
//
// query agent to agent connections.
//
// Responses:
//    default: genericError
//        200: legacyQueryConnectionsResponse
func (c *Operation) QueryConnections(rw http.ResponseWriter, req *http.Request) {
	reqBytes, err := queryValuesAsJSON(req.URL.Query())
	if err != nil {
		rest.SendHTTPStatusError(rw, http.StatusBadRequest, legacyconnection.InvalidRequestErrorCode, err)
		return
	}

	rest.Execute(c.command.QueryConnections, rw, bytes.NewReader(reqBytes))
}

// QueryConnectionByID swagger:route GET /legacy/connections/{id} legacy-connection legacyGetConnection
//
// Fetch a single connection record.
//
// Responses:
//    default: genericError
//        200: legacyQueryConnectionResponse
func (c *Operation) QueryConnectionByID(rw http.ResponseWriter, req *http.Request) {
	id, found := getIDFromRequest(rw, req)
	if !found {
		return
	}

	request := fmt.Sprintf(`{"id":"%s"}`, id)

	rest.Execute(c.command.QueryConnectionByID, rw, bytes.NewBufferString(request))
}

// CreateConnection swagger:route POST /legacy/connections/create legacy-connection legacyCreateConnection
//
// Saves the connection record.
//
// Responses:
//    default: genericError
//    200: legacyCreateConnectionResp
func (c *Operation) CreateConnection(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(c.command.CreateConnection, rw, req.Body)
}

// RemoveConnection swagger:route POST /legacy/connections/{id}/remove legacy-connection legacyRemoveConnection
//
// Removes given connection record.
//
// Responses:
//    default: genericError
//    200: legacyRemoveConnectionResponse
func (c *Operation) RemoveConnection(rw http.ResponseWriter, req *http.Request) {
	id, found := getIDFromRequest(rw, req)
	if !found {
		return
	}

	request := fmt.Sprintf(`{"id":"%s"}`, id)

	rest.Execute(c.command.RemoveConnection, rw, bytes.NewBufferString(request))
}

// queryValuesAsJSON converts query strings to `map[string]string`
// and marshals them to JSON bytes.
func queryValuesAsJSON(vals url.Values) ([]byte, error) {
	// normalize all query string key/values
	args := make(map[string]string)

	for k, v := range vals {
		if len(v) > 0 {
			args[k] = v[0]
		}
	}

	return json.Marshal(args)
}

// getIDFromRequest returns ID from request.
func getIDFromRequest(rw http.ResponseWriter, req *http.Request) (string, bool) {
	id := mux.Vars(req)["id"]
	if id == "" {
		rest.SendHTTPStatusError(rw, http.StatusBadRequest, legacyconnection.InvalidRequestErrorCode,
			fmt.Errorf("empty connection ID"))
		return "", false
	}

	return id, true
}
