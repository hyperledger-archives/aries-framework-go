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

	"github.com/go-openapi/runtime/middleware/denco"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	mocktransport "github.com/hyperledger/aries-framework-go/pkg/internal/didcomm/transport/mock"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/operation"
	"github.com/stretchr/testify/require"
)

const (
	successResponse = "success"
)

func TestExchangeService_GetAPIHandlers(t *testing.T) {
	svc, err := New(&mockProvider{})
	require.NoError(t, err)
	require.NotNil(t, svc)

	handlers := svc.GetRESTHandlers()
	require.NotEmpty(t, handlers)
}

func TestExchangeService_CreateInvitation(t *testing.T) {
	svc, err := New(&mockProvider{})
	require.NoError(t, err)
	require.NotNil(t, svc)

	handlers := svc.GetRESTHandlers()
	require.NotEmpty(t, handlers)

	var handler operation.Handler
	for _, h := range handlers {
		if h.Path() == createInviationAPIPath {
			handler = h
			break
		}
	}
	require.NotNil(t, handler)

	buf, err := getResponseFromHandler(handler, nil)
	require.NoError(t, err)

	response := didexchange.Invitation{}
	err = json.Unmarshal(buf.Bytes(), &response)
	require.NoError(t, err)

	//verify response
	require.NotEmpty(t, response.ID)
	require.NotEmpty(t, response.Label)
}

func TestExchangeService_WriteGenericError(t *testing.T) {
	const errMsg = "sample-error-msg"

	svc, err := New(&mockProvider{})
	require.NoError(t, err)
	require.NotNil(t, svc)

	rr := httptest.NewRecorder()

	err = errors.New(errMsg)
	svc.writeGenericError(rr, err)

	response := GenericError{}
	err = json.Unmarshal(rr.Body.Bytes(), &response)

	require.NoError(t, err)
	require.NotEmpty(t, response.Body)
	require.NotEmpty(t, response.Body.Message)
	require.Equal(t, response.Body.Message, errMsg)
	require.NotEmpty(t, response.Body.Code)

}

//getResponseFromHandler reads response from given http handle func
func getResponseFromHandler(handler operation.Handler, requestBody io.Reader) (*bytes.Buffer, error) {

	//prepare request
	req, err := http.NewRequest(handler.Method(), handler.Path(), requestBody)
	if err != nil {
		return nil, err
	}

	//prepare router
	mux := denco.NewMux()

	routes := []denco.Handler{mux.Handler(handler.Method(), handler.Path(), handler.Handle())}
	httpHandler, err := mux.Build(routes)
	if err != nil {
		return nil, err
	}

	// create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()

	//serve http on given response and request
	httpHandler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		return nil, fmt.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	return rr.Body, nil
}

//mockProvider mocks provider needed for did exchange service initialization
type mockProvider struct {
}

func (p *mockProvider) Service(id string) (interface{}, error) {
	return didexchange.New(nil, &mockOutboundTransport{}), nil
}

type mockOutboundTransport struct {
}

func (p *mockOutboundTransport) OutboundTransport() transport.OutboundTransport {
	return mocktransport.NewOutboundTransport(successResponse)
}

func (p *mockOutboundTransport) ProtocolConfig() api.ProtocolConfig {
	return &mockProtocolConfig{}
}

type mockProtocolConfig struct {
}

func (m *mockProtocolConfig) AgentLabel() string {
	return "agent"
}

func (m *mockProtocolConfig) AgentServiceEndpoint() string {
	return "endpoint"
}
