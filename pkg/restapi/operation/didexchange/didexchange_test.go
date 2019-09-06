/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/operation"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/operation/didexchange/models"
)

func TestOperation_GetAPIHandlers(t *testing.T) {
	svc, err := New(&mockProvider{})
	require.NoError(t, err)
	require.NotNil(t, svc)

	handlers := svc.GetRESTHandlers()
	require.NotEmpty(t, handlers)
}

func TestNew_Fail(t *testing.T) {
	svc, err := New(&mockProvider{errors.New("test-error")})
	require.Error(t, err)
	require.Nil(t, svc)
}

func TestOperation_CreateInvitation(t *testing.T) {

	handler := getHandler(t, createInvitationPath)
	buf, err := getResponseFromHandler(handler, nil, handler.Path())
	require.NoError(t, err)

	response := models.CreateInvitationResponse{}
	err = json.Unmarshal(buf.Bytes(), &response)
	require.NoError(t, err)

	// verify response
	require.NotEmpty(t, response.Payload)
	require.NotEmpty(t, response.Payload.Invitation.ServiceEndpoint)
	require.NotEmpty(t, response.Payload.Invitation.Label)
}

func TestOperation_ReceiveInvitation(t *testing.T) {

	var jsonStr = []byte(`{
    	"@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/invitation",
    	"@id": "4e8650d9-6cc9-491e-b00e-7bf6cb5858fc",
    	"serviceEndpoint": "http://ip10-0-46-4-blikjbs9psqg8vrg4p10-8020.direct.play-with-von.vonx.io",
    	"label": "Faber Agent",
    	"recipientKeys": [
      		"6LE8yhZB8Xffc5vFgFntE3YLrxq5JVUsoAvUQgUyktGt"
    		]
  	}`)

	handler := getHandler(t, receiveInvtiationPath)
	buf, err := getResponseFromHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
	require.NoError(t, err)

	response := models.ReceiveInvitationResponse{}
	err = json.Unmarshal(buf.Bytes(), &response)
	require.NoError(t, err)

	// verify response
	require.NotEmpty(t, response)
	require.NotEmpty(t, response.ConnectionID)
	require.NotEmpty(t, response.CreateTime)
	require.NotEmpty(t, response.UpdateTime)
	require.NotEmpty(t, response.RequestID)
	require.NotEmpty(t, response.DID)
}

func TestOperation_ReceiveInvitationFailure(t *testing.T) {

	var emptyRequest = []byte("")

	handler := getHandler(t, receiveInvtiationPath)
	buf, err := getResponseFromHandler(handler, bytes.NewBuffer(emptyRequest), handler.Path())
	require.NoError(t, err)

	response := models.ReceiveInvitationResponse{}
	err = json.Unmarshal(buf.Bytes(), &response)
	require.NoError(t, err)

	// verify response
	require.Empty(t, response.DID)
	require.Empty(t, response.CreateTime)
	require.Empty(t, response.UpdateTime)
	require.Empty(t, response.RequestID)

	// Parser generic error response
	errResponse := models.GenericError{}
	err = json.Unmarshal(buf.Bytes(), &errResponse)
	require.NoError(t, err)

	// verify response
	require.NotEmpty(t, errResponse.Body)
	require.NotEmpty(t, errResponse.Body.Code)
	require.NotEmpty(t, errResponse.Body.Message)
}

func TestOperation_AcceptInvitation(t *testing.T) {

	handler := getHandler(t, acceptInvitationPath)
	buf, err := getResponseFromHandler(handler, bytes.NewBuffer([]byte("test-id")), "/accept-invitation/1234")
	require.NoError(t, err)

	response := models.AcceptInvitationResponse{}
	err = json.Unmarshal(buf.Bytes(), &response)
	require.NoError(t, err)

	// verify response
	require.NotEmpty(t, response)
	require.NotEmpty(t, response.ConnectionID)
	require.NotEmpty(t, response.CreateTime)
	require.NotEmpty(t, response.UpdateTime)
	require.NotEmpty(t, response.RequestID)
	require.NotEmpty(t, response.DID)
}

func TestOperation_WriteGenericError(t *testing.T) {
	const errMsg = "sample-error-msg"

	svc, err := New(&mockProvider{})
	require.NoError(t, err)
	require.NotNil(t, svc)

	rr := httptest.NewRecorder()

	err = errors.New(errMsg)
	svc.writeGenericError(rr, err)

	response := models.GenericError{}
	err = json.Unmarshal(rr.Body.Bytes(), &response)

	require.NoError(t, err)
	require.NotEmpty(t, response.Body)
	require.NotEmpty(t, response.Body.Message)
	require.Equal(t, response.Body.Message, errMsg)
	require.NotEmpty(t, response.Body.Code)

}

// getResponseFromHandler reads response from given http handle func
func getResponseFromHandler(handler operation.Handler, requestBody io.Reader, path string) (*bytes.Buffer, error) {

	// prepare request
	req, err := http.NewRequest(handler.Method(), path, requestBody)
	if err != nil {
		return nil, err
	}

	// prepare router
	router := mux.NewRouter()

	router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())

	// create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()

	// serve http on given response and request
	router.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		return nil, fmt.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	return rr.Body, nil
}

func getHandler(t *testing.T, lookup string) operation.Handler {
	svc, err := New(&mockProvider{})
	require.NoError(t, err)
	require.NotNil(t, svc)

	handlers := svc.GetRESTHandlers()
	require.NotEmpty(t, handlers)

	for _, h := range handlers {
		if h.Path() == lookup {
			return h
		}
	}
	require.Fail(t, "unable to find handler")
	return nil
}

// mockProvider mocks provider needed for did exchange service initialization
type mockProvider struct {
	err error
}

func (p *mockProvider) Service(id string) (interface{}, error) {
	if p.err != nil {
		return nil, p.err
	}
	return &mockProtocolSvc{}, nil
}

type mockProtocolSvc struct {
}

func (m mockProtocolSvc) Handle(msg dispatcher.DIDCommMsg) error {
	return nil
}

func (m mockProtocolSvc) Accept(msgType string) bool {
	return true
}

func (m mockProtocolSvc) Name() string {
	return "mockProtocolSvc"
}
