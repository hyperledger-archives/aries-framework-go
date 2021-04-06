/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
)

const (
	sampleErr1 = iota + command.UnknownStatus
	sampleErr2
	sampleErr3
	sampleErr4
)

func TestSendError(t *testing.T) {
	t.Run("Test sending HTTP status codes", func(t *testing.T) {
		const errMsg = "here is the sample which I want to write to response"
		errors := []struct {
			err        error
			errCode    command.Code
			statusCode int
			response   genericErrorBody
		}{
			{
				fmt.Errorf(errMsg), sampleErr1, http.StatusOK,
				genericErrorBody{Code: sampleErr1, Message: errMsg},
			},
			{
				fmt.Errorf(errMsg), sampleErr2, http.StatusForbidden,
				genericErrorBody{Code: sampleErr2, Message: errMsg},
			},
			{
				fmt.Errorf(errMsg), sampleErr3, http.StatusNotAcceptable,
				genericErrorBody{Code: sampleErr3, Message: errMsg},
			},
			{
				fmt.Errorf(errMsg), sampleErr4, http.StatusNoContent,
				genericErrorBody{Code: sampleErr4, Message: errMsg},
			},
		}

		for _, data := range errors {
			rr := httptest.NewRecorder()

			SendHTTPStatusError(rr, data.statusCode, data.errCode, data.err)
			require.NotEmpty(t, rr.Body.Bytes())

			response := genericErrorBody{}
			err := json.Unmarshal(rr.Body.Bytes(), &response)
			require.NoError(t, err)

			require.Equal(t, data.statusCode, rr.Code)
			require.Equal(t, data.response, response)
		}
	})

	t.Run("Test sending command errors", func(t *testing.T) {
		const errMsg = "here is the sample which I want to write to response"
		errors := []struct {
			err        command.Error
			statusCode int
			response   genericErrorBody
		}{
			{
				command.NewValidationError(sampleErr1, fmt.Errorf(errMsg)), http.StatusBadRequest,
				genericErrorBody{Code: sampleErr1, Message: errMsg},
			},
			{
				command.NewExecuteError(sampleErr2, fmt.Errorf(errMsg)), http.StatusInternalServerError,
				genericErrorBody{Code: sampleErr2, Message: errMsg},
			},
			{
				command.NewValidationError(sampleErr3, fmt.Errorf(errMsg)), http.StatusBadRequest,
				genericErrorBody{Code: sampleErr3, Message: errMsg},
			},
			{
				command.NewExecuteError(sampleErr4, fmt.Errorf(errMsg)), http.StatusInternalServerError,
				genericErrorBody{Code: sampleErr4, Message: errMsg},
			},
		}

		for _, data := range errors {
			rr := httptest.NewRecorder()

			SendError(rr, data.err)
			require.NotEmpty(t, rr.Body.Bytes())

			response := genericErrorBody{}
			err := json.Unmarshal(rr.Body.Bytes(), &response)
			require.NoError(t, err)

			require.Equal(t, data.statusCode, rr.Code)
			require.Equal(t, data.response, response)
		}
	})
}

func TestSendErrorFailures(t *testing.T) {
	rw := &mockRWriter{}
	SendHTTPStatusError(rw, http.StatusBadRequest, command.UnknownStatus, fmt.Errorf("sample error"))
}

func TestExecute(t *testing.T) {
	cmd := func(rw io.Writer, req io.Reader) command.Error {
		return command.NewValidationError(1, fmt.Errorf("sample"))
	}

	rw := httptest.NewRecorder()
	Execute(cmd, rw, nil)
	require.Contains(t, rw.Body.String(), `{"code":1,"message":"sample"}`)
}

// mockRWriter to recreate response writer error scenario.
type mockRWriter struct{}

func (m *mockRWriter) Header() http.Header {
	return make(map[string][]string)
}

func (m *mockRWriter) Write([]byte) (int, error) {
	return 0, fmt.Errorf("failed to write body")
}

func (m *mockRWriter) WriteHeader(statusCode int) {}
