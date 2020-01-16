/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/msghandler"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol/generic"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/vdri"
	resterrs "github.com/hyperledger/aries-framework-go/pkg/restapi/errors"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/internal/mocks/webhook"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/operation"
)

func TestOperation_GetAPIHandlers(t *testing.T) {
	svc := New(&protocol.MockProvider{}, msghandler.NewMockMsgServiceProvider(), webhook.NewMockWebhookNotifier())
	require.NotNil(t, svc)

	handlers := svc.GetRESTHandlers()
	require.NotEmpty(t, handlers)
}

func TestOperation_CreatePublicDID(t *testing.T) {
	t.Run("Successful Create public DID", func(t *testing.T) {
		svc := New(&protocol.MockProvider{}, msghandler.NewMockMsgServiceProvider(), webhook.NewMockWebhookNotifier())
		require.NotNil(t, svc)

		handler := lookupCreatePublicDIDHandler(t, svc, createPublicDIDPath)
		buf, err := getSuccessResponseFromHandler(handler, nil, handler.Path()+"?method=sidetree")
		require.NoError(t, err)

		response := CreatePublicDIDResponse{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.DID)
		require.NotEmpty(t, response.DID.ID)
		require.NotEmpty(t, response.DID.PublicKey)
		require.NotEmpty(t, response.DID.Service)
	})

	t.Run("Failed Create public DID", func(t *testing.T) {
		svc := New(&protocol.MockProvider{}, msghandler.NewMockMsgServiceProvider(), webhook.NewMockWebhookNotifier())
		require.NotNil(t, svc)

		handler := lookupCreatePublicDIDHandler(t, svc, createPublicDIDPath)
		buf, code, err := sendRequestToHandler(handler, nil, handler.Path())
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		verifyError(t, InvalidRequestErrorCode, "", buf.Bytes())

		handler = lookupCreatePublicDIDHandler(t, svc, createPublicDIDPath)
		buf, code, err = sendRequestToHandler(handler, nil, handler.Path()+"?-----")
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		verifyError(t, InvalidRequestErrorCode, "", buf.Bytes())
	})

	t.Run("Failed Create public DID, VDRI error", func(t *testing.T) {
		svc := New(&protocol.MockProvider{CustomVDRI: &vdri.MockVDRIRegistry{CreateErr: fmt.Errorf("just-fail-it")}},
			msghandler.NewMockMsgServiceProvider(), webhook.NewMockWebhookNotifier())
		require.NotNil(t, svc)

		handler := lookupCreatePublicDIDHandler(t, svc, createPublicDIDPath)
		buf, code, err := sendRequestToHandler(handler, nil, handler.Path()+"?method=valid")
		require.NoError(t, err)
		require.Equal(t, http.StatusInternalServerError, code)
		verifyError(t, CreatePublicDIDError, "", buf.Bytes())
	})
}

func TestOperation_RegisterMessageService(t *testing.T) {
	t.Run("Successful Register Message Service", func(t *testing.T) {
		mhandler := msghandler.NewMockMsgServiceProvider()
		svc := New(&protocol.MockProvider{}, mhandler, webhook.NewMockWebhookNotifier())
		require.NotNil(t, svc)

		var jsonStr = []byte(`{
		"name":"json-msg-01",
    	"type": "https://didcomm.org/json/1.0/msg",
    	"purpose": ["prp-01","prp-02"]
  	}`)

		handler := lookupCreatePublicDIDHandler(t, svc, registerMsgService)
		buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)
		require.Empty(t, buf)

		// verify if new service is registered
		require.NotEmpty(t, mhandler.Services())
		require.Equal(t, "json-msg-01", mhandler.Services()[0].Name())
		require.True(t, mhandler.Services()[0].Accept(
			&service.Header{Type: "https://didcomm.org/json/1.0/msg",
				Purpose: []string{"prp-01", "prp-02"}},
		))
	})

	t.Run("Register Message Service Input validation", func(t *testing.T) {
		tests := []struct {
			name      string
			json      string
			errorCode resterrs.Code
			errorMsg  string
		}{
			{
				name:      "missing name test",
				json:      `{"type": "https://didcomm.org/json/1.0/msg","purpose": ["prp-01","prp-02"]}`,
				errorCode: InvalidRequestErrorCode,
				errorMsg:  errMsgSvcNameRequired,
			},
			{
				name:      "missing name test",
				json:      `{"name": "svx-001"}`,
				errorCode: InvalidRequestErrorCode,
				errorMsg:  errMsgInvalidAcceptanceCrit,
			},
			{
				name:      "missing name test",
				json:      `-----`,
				errorCode: InvalidRequestErrorCode,
				errorMsg:  "invalid character",
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.name, func(t *testing.T) {
				svc := New(&protocol.MockProvider{}, msghandler.NewMockMsgServiceProvider(), webhook.NewMockWebhookNotifier())
				require.NotNil(t, svc)

				handler := lookupCreatePublicDIDHandler(t, svc, registerMsgService)
				buf, code, err := sendRequestToHandler(handler, bytes.NewBufferString(tc.json), handler.Path())
				require.NoError(t, err)
				require.NotEmpty(t, buf)
				require.Equal(t, http.StatusBadRequest, code)
				verifyError(t, InvalidRequestErrorCode, tc.errorMsg, buf.Bytes())
			})
		}
	})

	t.Run("Register Message Service failure", func(t *testing.T) {
		const errMsg = "sample-error"
		mhandler := msghandler.NewMockMsgServiceProvider()
		mhandler.RegisterErr = fmt.Errorf(errMsg)

		svc := New(&protocol.MockProvider{}, mhandler, webhook.NewMockWebhookNotifier())
		require.NotNil(t, svc)

		var jsonStr = []byte(`{
		"name":"json-msg-01",
    	"type": "https://didcomm.org/json/1.0/msg",
    	"purpose": ["prp-01","prp-02"]
  	}`)

		handler := lookupCreatePublicDIDHandler(t, svc, registerMsgService)
		buf, code, err := sendRequestToHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)
		require.NotEmpty(t, buf)
		require.Equal(t, http.StatusInternalServerError, code)
		verifyError(t, RegisterMsgSvcError, errMsg, buf.Bytes())
	})
}

func TestOperation_UnregisterMessageService(t *testing.T) {
	t.Run("Unregistering non existing message service", func(t *testing.T) {
		svc := New(&protocol.MockProvider{}, msghandler.NewMockMsgServiceProvider(), webhook.NewMockWebhookNotifier())
		require.NotNil(t, svc)

		var jsonStr = []byte(`{
		"name":"json-msg-01"
  	}`)

		handler := lookupCreatePublicDIDHandler(t, svc, unregisterMsgService)
		buf, code, err := sendRequestToHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)
		require.NotEmpty(t, buf)
		require.Equal(t, http.StatusInternalServerError, code)
		verifyError(t, UnregisterMsgSvcError, "failed to unregister", buf.Bytes())
	})

	t.Run("Unregistering message service input validation", func(t *testing.T) {
		svc := New(&protocol.MockProvider{}, msghandler.NewMockMsgServiceProvider(), webhook.NewMockWebhookNotifier())
		require.NotNil(t, svc)

		var jsonStr = []byte(`{
		"name":""
  	}`)

		handler := lookupCreatePublicDIDHandler(t, svc, unregisterMsgService)
		buf, code, err := sendRequestToHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)
		require.NotEmpty(t, buf)
		require.Equal(t, http.StatusBadRequest, code)
		verifyError(t, InvalidRequestErrorCode, errMsgSvcNameRequired, buf.Bytes())
	})

	t.Run("Unregistering message service successfully", func(t *testing.T) {
		svc := New(&protocol.MockProvider{}, msghandler.NewMockMsgServiceProvider(), webhook.NewMockWebhookNotifier())
		require.NotNil(t, svc)

		svcNames := []string{"svc-01", "svc-02", "svc-03", "svc-04"}
		for _, svcName := range svcNames {
			err := svc.msgRegistrar.Register(generic.NewCustomMockMessageSvc("test", svcName))
			require.NoError(t, err)
		}

		jsonStr := `{"name":"%s"}`
		for _, svcName := range svcNames {
			handler := lookupCreatePublicDIDHandler(t, svc, unregisterMsgService)
			buf, err := getSuccessResponseFromHandler(handler,
				bytes.NewBufferString(fmt.Sprintf(jsonStr, svcName)),
				handler.Path())
			require.NoError(t, err)
			require.Empty(t, buf)
		}
	})

	t.Run("Unregistering message service input decode failure", func(t *testing.T) {
		svc := New(&protocol.MockProvider{}, msghandler.NewMockMsgServiceProvider(), webhook.NewMockWebhookNotifier())
		require.NotNil(t, svc)

		var jsonStr = []byte(`{--`)

		handler := lookupCreatePublicDIDHandler(t, svc, unregisterMsgService)
		buf, code, err := sendRequestToHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)
		require.NotEmpty(t, buf)
		require.Equal(t, http.StatusBadRequest, code)
		verifyError(t, InvalidRequestErrorCode, "invalid character", buf.Bytes())
	})
}

func TestOperation_RegisteredServices(t *testing.T) {
	svc := New(&protocol.MockProvider{}, msghandler.NewMockMsgServiceProvider(), webhook.NewMockWebhookNotifier())
	require.NotNil(t, svc)

	verifyResponse := func(buf *bytes.Buffer, count int) {
		response := RegisteredServicesResponse{}
		err := json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		require.NotEmpty(t, response)
		require.Len(t, response.Names, count)
	}

	handler := lookupCreatePublicDIDHandler(t, svc, msgServiceList)
	buf, err := getSuccessResponseFromHandler(handler, nil, handler.Path())
	require.NoError(t, err)
	verifyResponse(buf, 0)

	testMsgSvcs := []dispatcher.MessageService{
		generic.NewCustomMockMessageSvc("type-01", "svc-name-01"),
		generic.NewCustomMockMessageSvc("type-02", "svc-name-02"),
		generic.NewCustomMockMessageSvc("type-03", "svc-name-03"),
		generic.NewCustomMockMessageSvc("type-04", "svc-name-04"),
		generic.NewCustomMockMessageSvc("type-05", "svc-name-05"),
	}
	err = svc.msgRegistrar.Register(testMsgSvcs...)
	require.NoError(t, err)

	buf, err = getSuccessResponseFromHandler(handler, nil, handler.Path())
	require.NoError(t, err)
	verifyResponse(buf, len(testMsgSvcs))
}

func TestBuildSideTreeRequest(t *testing.T) {
	registry := vdri.MockVDRIRegistry{}
	didDoc, err := registry.Create("sidetree")
	require.NoError(t, err)
	require.NotNil(t, didDoc)

	b, err := didDoc.JSONBytes()
	require.NoError(t, err)

	r, err := getBasicRequestBuilder(`{"operation":"create"}`)(b)
	require.NoError(t, err)
	require.NotNil(t, r)
}

func TestOperation_WriteResponse(t *testing.T) {
	svc := New(&protocol.MockProvider{}, msghandler.NewMockMsgServiceProvider(), webhook.NewMockWebhookNotifier())
	require.NotNil(t, svc)
	svc.writeResponse(&mockWriter{}, CreatePublicDIDResponse{})
}

func lookupCreatePublicDIDHandler(t *testing.T, op *Operation, path string) operation.Handler {
	handlers := op.GetRESTHandlers()
	require.NotEmpty(t, handlers)

	for _, h := range handlers {
		if h.Path() == path {
			return h
		}
	}

	require.Fail(t, "unable to find handler")

	return nil
}

// getSuccessResponseFromHandler reads response from given http handle func.
// expects http status OK.
func getSuccessResponseFromHandler(handler operation.Handler, requestBody io.Reader,
	path string) (*bytes.Buffer, error) {
	response, status, err := sendRequestToHandler(handler, requestBody, path)
	if status != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: got %v, want %v",
			status, http.StatusOK)
	}

	return response, err
}

// sendRequestToHandler reads response from given http handle func.
func sendRequestToHandler(handler operation.Handler, requestBody io.Reader, path string) (*bytes.Buffer, int, error) {
	// prepare request
	req, err := http.NewRequest(handler.Method(), path, requestBody)
	if err != nil {
		return nil, 0, err
	}

	// prepare router
	router := mux.NewRouter()

	router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())

	// create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()

	// serve http on given response and request
	router.ServeHTTP(rr, req)

	return rr.Body, rr.Code, nil
}

func verifyError(t *testing.T, expectedCode resterrs.Code, expectedMsg string, data []byte) {
	// Parser generic error response
	errResponse := struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}{}
	err := json.Unmarshal(data, &errResponse)
	require.NoError(t, err)

	// verify response
	require.EqualValues(t, expectedCode, errResponse.Code)
	require.NotEmpty(t, errResponse.Message)

	if expectedMsg != "" {
		require.Contains(t, errResponse.Message, expectedMsg)
	}
}

type mockWriter struct {
}

func (m *mockWriter) Write(p []byte) (n int, err error) {
	return 0, fmt.Errorf("sample-error")
}
