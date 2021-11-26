/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofbandv2

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	client "github.com/hyperledger/aries-framework-go/pkg/client/outofbandv2"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	mocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/client/outofbandv2"
)

func provider(ctrl *gomock.Controller) client.Provider {
	service := mocks.NewMockOobService(ctrl)
	service.EXPECT().AcceptInvitation(gomock.Any()).Return("123", nil).AnyTimes()

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(gomock.Any()).Return(service, nil)
	provider.EXPECT().MediaTypeProfiles().AnyTimes()

	return provider
}

func TestNew(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(gomock.Any()).Return(nil, errors.New("error"))
	provider.EXPECT().MediaTypeProfiles().Return(nil).AnyTimes()

	const errMsg = "outofband/2.0 command : cannot create a client: failed to look up service out-of-band/2.0 : error"

	_, err := New(provider)
	require.EqualError(t, err, errMsg)
}

func TestOperation_CreateInvitation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	operation, err := New(provider(ctrl))
	require.NoError(t, err)

	b, code, err := sendRequestToHandler(
		handlerLookup(t, operation, CreateInvitation),
		bytes.NewBufferString(`{
			"service":["did:example:123"]
		}`),
		CreateInvitation,
	)

	require.NoError(t, err)
	require.Equal(t, http.StatusOK, code)

	res := make(map[string]interface{})
	require.NoError(t, json.Unmarshal(b.Bytes(), &res))
	require.NotEmpty(t, res["invitation"])
}

func TestOperation_AcceptInvitation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	operation, err := New(provider(ctrl))
	require.NoError(t, err)

	b, code, err := sendRequestToHandler(
		handlerLookup(t, operation, AcceptInvitation),
		bytes.NewBufferString(`{
			"invitation":{},
			"my_label":"label"
		}`),
		AcceptInvitation,
	)

	require.NoError(t, err)
	require.Equal(t, http.StatusOK, code)

	res := make(map[string]interface{})
	require.NoError(t, json.Unmarshal(b.Bytes(), &res))
}

func handlerLookup(t *testing.T, op *Operation, lookup string) rest.Handler {
	t.Helper()

	handlers := op.GetRESTHandlers()
	require.NotEmpty(t, handlers)

	for _, h := range handlers {
		if h.Path() == lookup {
			return h
		}
	}

	require.Fail(t, "unable to find handler")

	return nil
}

// sendRequestToHandler reads response from given http handle func.
func sendRequestToHandler(handler rest.Handler, requestBody io.Reader, path string) (*bytes.Buffer, int, error) {
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
