/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package support

import (
	"net/http"
)

//NewHTTPHandler returns instance of HTTPHandler which can be used handle
// http requests
func NewHTTPHandler(path, method string, handle http.HandlerFunc) *HTTPHandler {
	return &HTTPHandler{path: path, method: method, handle: handle}
}

//HTTPHandler contains REST API handling details which can be used to build routers
// for http requests for given path
type HTTPHandler struct {
	path   string
	method string
	handle http.HandlerFunc
}

//Path returns http request path
func (h *HTTPHandler) Path() string {
	return h.path
}

//Method returns http request method type
func (h *HTTPHandler) Method() string {
	return h.method
}

//Handle returns http request handle func
func (h *HTTPHandler) Handle() http.HandlerFunc {
	return h.handle
}
