/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofband

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	client "github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	mocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/client/outofband"
	mocknotifier "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/controller/webnotifier"
)

const (
	piid   = "1234"
	label  = "label"
	reason = "reason"
)

func provider(ctrl *gomock.Controller) client.Provider {
	service := mocks.NewMockOobService(ctrl)
	service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
	service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
	service.EXPECT().SaveInvitation(gomock.Any()).Return(nil).AnyTimes()
	service.EXPECT().AcceptInvitation(gomock.Any(), gomock.Any()).Return("conn-id", nil).AnyTimes()
	service.EXPECT().ActionContinue(piid, &client.EventOptions{Label: label}).AnyTimes()
	service.EXPECT().ActionStop(piid, errors.New(reason)).AnyTimes()
	service.EXPECT().Actions().AnyTimes()

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

	const errMsg = "outofband command : cannot create a client: failed to look up service out-of-band : error"

	_, err := New(provider, mocknotifier.NewMockNotifier(nil))
	require.EqualError(t, err, errMsg)
}

func TestOperation_CreateInvitation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	operation, err := New(provider(ctrl), mocknotifier.NewMockNotifier(nil))
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

	operation, err := New(provider(ctrl), mocknotifier.NewMockNotifier(nil))
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
	require.NotEmpty(t, res["connection_id"])
}

func TestOperation_Actions(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	operation, err := New(provider(ctrl), mocknotifier.NewMockNotifier(nil))
	require.NoError(t, err)

	_, code, err := sendRequestToHandler(
		handlerLookup(t, operation, Actions),
		nil,
		Actions,
	)

	require.NoError(t, err)
	require.Equal(t, http.StatusOK, code)
}

func TestOperation_ActionContinue(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	operation, err := New(provider(ctrl), mocknotifier.NewMockNotifier(nil))
	require.NoError(t, err)

	_, code, err := sendRequestToHandler(
		handlerLookup(t, operation, ActionContinue),
		nil,
		strings.Replace(ActionContinue+"?label="+label, `{piid}`, piid, 1),
	)

	require.NoError(t, err)
	require.Equal(t, http.StatusOK, code)
}

func TestOperation_ActionStop(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	operation, err := New(provider(ctrl), mocknotifier.NewMockNotifier(nil))
	require.NoError(t, err)

	_, code, err := sendRequestToHandler(
		handlerLookup(t, operation, ActionStop),
		nil,
		strings.Replace(ActionStop+"?reason="+reason, `{piid}`, piid, 1),
	)

	require.NoError(t, err)
	require.Equal(t, http.StatusOK, code)
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
