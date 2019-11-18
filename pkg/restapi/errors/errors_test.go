/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package errors

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	invalidRequest = Code(iota + DIDExchange)
	createInvitationError
	receiveInvitationError
	removeConnectionError
)

func TestSendError(t *testing.T) {
	const errMsg = "here is the sample which I want to write to response"

	t.Run("Test sending HTTP Status Forbidden", func(t *testing.T) {
		var errors = []struct {
			err        error
			errCode    Code
			statusCode int
			response   genericError
		}{
			{fmt.Errorf(errMsg), UnknownStatus, http.StatusBadRequest,
				genericError{Code: UnknownStatus, Message: errMsg}},
			{fmt.Errorf(errMsg), createInvitationError, http.StatusBadRequest,
				genericError{Code: createInvitationError, Message: errMsg}},
			{fmt.Errorf(errMsg), receiveInvitationError, http.StatusBadRequest,
				genericError{Code: receiveInvitationError, Message: errMsg}},
			{fmt.Errorf(errMsg), removeConnectionError, http.StatusBadRequest,
				genericError{Code: removeConnectionError, Message: errMsg}},
		}

		for _, data := range errors {
			rr := httptest.NewRecorder()

			SendHTTPBadRequest(rr, data.errCode, data.err)
			require.NotEmpty(t, rr.Body.Bytes())

			response := genericError{}
			err := json.Unmarshal(rr.Body.Bytes(), &response)
			require.NoError(t, err)

			require.Equal(t, data.statusCode, rr.Code)
			require.Equal(t, data.response, response)
		}
	})

	t.Run("Test sending HTTP Status Internal Server error", func(t *testing.T) {
		const errMsg = "here is the sample which I want to write to response"
		var errors = []struct {
			err        error
			errCode    Code
			statusCode int
			response   genericError
		}{
			{fmt.Errorf(errMsg), UnknownStatus, http.StatusInternalServerError,
				genericError{Code: UnknownStatus, Message: errMsg}},
			{fmt.Errorf(errMsg), createInvitationError, http.StatusInternalServerError,
				genericError{Code: createInvitationError, Message: errMsg}},
			{fmt.Errorf(errMsg), receiveInvitationError, http.StatusInternalServerError,
				genericError{Code: receiveInvitationError, Message: errMsg}},
			{fmt.Errorf(errMsg), removeConnectionError, http.StatusInternalServerError,
				genericError{Code: removeConnectionError, Message: errMsg}},
		}

		for _, data := range errors {
			rr := httptest.NewRecorder()

			SendHTTPInternalServerError(rr, data.errCode, data.err)
			require.NotEmpty(t, rr.Body.Bytes())

			response := genericError{}
			err := json.Unmarshal(rr.Body.Bytes(), &response)
			require.NoError(t, err)

			require.Equal(t, data.statusCode, rr.Code)
			require.Equal(t, data.response, response)
		}
	})

	t.Run("Test sending Unknown error", func(t *testing.T) {
		const errMsg = "here is the sample which I want to write to response"
		var errors = []struct {
			err        error
			statusCode int
			response   genericError
		}{
			{fmt.Errorf(errMsg), http.StatusInternalServerError,
				genericError{Code: UnknownStatus, Message: errMsg}},
			{fmt.Errorf(errMsg), http.StatusInternalServerError,
				genericError{Code: UnknownStatus, Message: errMsg}},
			{fmt.Errorf(errMsg), http.StatusInternalServerError,
				genericError{Code: UnknownStatus, Message: errMsg}},
			{fmt.Errorf(errMsg), http.StatusInternalServerError,
				genericError{Code: UnknownStatus, Message: errMsg}},
		}

		for _, data := range errors {
			rr := httptest.NewRecorder()

			SendUnknownError(rr, data.err)
			require.NotEmpty(t, rr.Body.Bytes())

			response := genericError{}
			err := json.Unmarshal(rr.Body.Bytes(), &response)
			require.NoError(t, err)

			require.Equal(t, data.statusCode, rr.Code)
			require.Equal(t, data.response, response)
		}
	})

	t.Run("Test sending HTTP status codes", func(t *testing.T) {
		const errMsg = "here is the sample which I want to write to response"
		var errors = []struct {
			err        error
			errCode    Code
			statusCode int
			response   genericError
		}{
			{fmt.Errorf(errMsg), UnknownStatus, http.StatusOK,
				genericError{Code: UnknownStatus, Message: errMsg}},
			{fmt.Errorf(errMsg), invalidRequest, http.StatusForbidden,
				genericError{Code: invalidRequest, Message: errMsg}},
			{fmt.Errorf(errMsg), receiveInvitationError, http.StatusNotAcceptable,
				genericError{Code: receiveInvitationError, Message: errMsg}},
			{fmt.Errorf(errMsg), removeConnectionError, http.StatusNoContent,
				genericError{Code: removeConnectionError, Message: errMsg}},
		}

		for _, data := range errors {
			rr := httptest.NewRecorder()

			SendHTTPStatusError(rr, data.errCode, data.err, data.statusCode)
			require.NotEmpty(t, rr.Body.Bytes())

			response := genericError{}
			err := json.Unmarshal(rr.Body.Bytes(), &response)
			require.NoError(t, err)

			require.Equal(t, data.statusCode, rr.Code)
			require.Equal(t, data.response, response)
		}
	})
}

func TestSendErrorFailures(t *testing.T) {
	rw := &mockRWriter{}
	SendHTTPStatusError(rw, UnknownStatus, fmt.Errorf("sample error"), http.StatusBadRequest)
}

// mockRWriter to recreate response writer error scenario
type mockRWriter struct {
}

func (m *mockRWriter) Header() http.Header {
	return make(map[string][]string)
}

func (m *mockRWriter) Write([]byte) (int, error) {
	return 0, fmt.Errorf("failed to write body")
}

func (m *mockRWriter) WriteHeader(statusCode int) {}
