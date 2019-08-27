/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"encoding/json"
	"net/http"

	"github.com/go-openapi/runtime/middleware/denco"
	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	"github.com/hyperledger/aries-framework-go/pkg/internal/common/support"
)

var logger = log.New("aries-framework/did-exchange")

const (
	createInviationAPIPath = "/create-invitation"
)

// provider contains dependencies for the Exchange protocol and is typically created by using aries.Context()
type provider interface {
	Service(id string) (interface{}, error)
}

// A GenericError is the default error message that is generated.
// For certain status codes there are more appropriate error structures.
//
// swagger:response genericError
type GenericError struct {
	// in: body
	Body struct {
		Code    int32  `json:"code"`
		Message string `json:"message"`
	} `json:"body"`
}

//New returns new DID Exchange rest client protocol instance
func New(ctx provider) (*Client, error) {

	didExchange, err := didexchange.New(ctx)
	if err != nil {
		return nil, err
	}
	svc := &Client{ctx: ctx, didExchangeClient: didExchange}
	svc.registerHandler()

	return svc, nil
}

//Client DID Exchange rest client
type Client struct {
	ctx               provider
	didExchangeClient *didexchange.Client
	handlers          []api.Handler
}

// CreateInvitation swagger:route GET /create-invitation did-exchange createInvitation
//
// Creates a new connection invitation....
//
// Responses:
//    default: genericError
//        200: createInvitationResponse
func (c *Client) CreateInvitation(rw http.ResponseWriter, req *http.Request, param denco.Params) {

	logger.Debugf("Creating connection invitation ")

	// call didexchange client
	response, err := c.didExchangeClient.CreateInvitation()
	if err != nil {
		c.writeGenericError(rw, err)
		return
	}

	err = json.NewEncoder(rw).Encode(&response.Invitation)
	if err != nil {
		logger.Errorf("Unable to send response, %s", err)
	}
}

//writeGenericError writes given error to http response writer as generic error response
func (c *Client) writeGenericError(rw http.ResponseWriter, err error) {
	errResponse := GenericError{
		Body: struct {
			Code    int32  `json:"code"`
			Message string `json:"message"`
		}{
			//TODO implement error codes, below is sample error code
			Code:    1,
			Message: err.Error(),
		},
	}
	err = json.NewEncoder(rw).Encode(errResponse)
	if err != nil {
		logger.Errorf("Unable to send error response, %s", err)
	}
}

//GetRESTHandlers get all controller API handler available for this protocol service
func (c *Client) GetRESTHandlers() []api.Handler {
	return c.handlers
}

//registerHandler register handlers to be exposed from this protocol service as REST API endpoints
func (c *Client) registerHandler() {
	//Add more protocol endpoints here to expose them as controller API endpoints
	c.handlers = []api.Handler{
		support.NewHTTPHandler(createInviationAPIPath, http.MethodGet, c.CreateInvitation),
	}
}
