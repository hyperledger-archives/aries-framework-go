/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package errors

import (
	"encoding/json"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
)

var logger = log.New("aries-framework/rest")

// genericError is aries rest api error response
// swagger:response genericError
type genericError struct {
	// in: body
	Code command.Code `json:"code"`
	// in: body
	Message string `json:"message"`
}

// SendError sends command error as http response in generic error format
func SendError(rw http.ResponseWriter, err command.Error) {
	var status int

	switch err.Type() {
	case command.ValidationError:
		status = http.StatusBadRequest
	default:
		status = http.StatusInternalServerError
	}

	SendHTTPStatusError(rw, status, err.Code(), err)
}

// SendHTTPStatusError sends given http status code to response with error body
func SendHTTPStatusError(rw http.ResponseWriter, httpStatus int, code command.Code, err error) {
	rw.WriteHeader(httpStatus)
	rw.Header().Set("Content-Type", "application/json")

	e := json.NewEncoder(rw).Encode(genericError{
		Code:    code,
		Message: err.Error(),
	})
	if e != nil {
		logger.Errorf("Unable to send error response, %s", e)
	}
}
