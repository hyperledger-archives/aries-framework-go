/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package errors

import (
	"encoding/json"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
)

var logger = log.New("aries-framework/rest")

// genericError is aries rest api error response
// swagger:response genericError
type genericError struct {
	// in: body
	Code Code `json:"code"`
	// in: body
	Message string `json:"message"`
}

// Group is the error groups.
// Note: recommended to use [0-9]*000 pattern for any new entries
// Example: 2000, 3000, 4000 ...... 25000
type Group int32

const (
	// DIDExchange error group for DID exchange protocol rest api errors
	DIDExchange Group = 2000

	// Introduce error group for Introduce protocol rest api errors
	Introduce Group = 3000
)

// Code is the error code of aries rest api errors
type Code int32

const (
	// UnknownStatus default error code for unknown errors
	UnknownStatus Code = iota
)

// SendHTTPBadRequest sends http status code BAD REQUEST to response with given error body
func SendHTTPBadRequest(rw http.ResponseWriter, code Code, err error) {
	SendHTTPStatusError(rw, code, err, http.StatusBadRequest)
}

// SendHTTPInternalServerError sends http status code INTERNAL SERVER ERROR to response with given error body
func SendHTTPInternalServerError(rw http.ResponseWriter, code Code, err error) {
	SendHTTPStatusError(rw, code, err, http.StatusInternalServerError)
}

// SendUnknownError sends unnknown/default error through response with given error body
func SendUnknownError(rw http.ResponseWriter, err error) {
	SendHTTPStatusError(rw, UnknownStatus, err, http.StatusInternalServerError)
}

// SendHTTPStatusError sends given http status code to response with error body
func SendHTTPStatusError(rw http.ResponseWriter, code Code, err error, statusCode int) {
	rw.WriteHeader(statusCode)
	rw.Header().Set("Content-Type", "application/json")

	e := json.NewEncoder(rw).Encode(genericError{
		Code:    code,
		Message: err.Error(),
	})
	if e != nil {
		logger.Errorf("Unable to send error response, %s", e)
	}
}
