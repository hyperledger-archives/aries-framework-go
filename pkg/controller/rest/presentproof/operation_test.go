/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	client "github.com/hyperledger/aries-framework-go/pkg/client/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	mocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/client/presentproof"
	mocknotifier "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/controller/webnotifier"
)

func provider(ctrl *gomock.Controller) client.Provider {
	service := mocks.NewMockProtocolService(ctrl)
	service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
	service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
	service.EXPECT().ActionContinue(gomock.Any(), gomock.Any()).AnyTimes()
	service.EXPECT().ActionStop(gomock.Any(), gomock.Any()).AnyTimes()

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(gomock.Any()).Return(service, nil)

	return provider
}

func TestOperation_AcceptRequestPresentation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("No payload", func(t *testing.T) {
		operation, err := New(provider(ctrl), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		buf, code, err := sendRequestToHandler(
			handlerLookup(t, operation, AcceptRequestPresentation), nil,
			strings.Replace(AcceptRequestPresentation, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "payload was not provided")
	})

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, AcceptRequestPresentation),
			bytes.NewBufferString(`{"presentation":{}}`),
			strings.Replace(AcceptRequestPresentation, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_DeclineRequestPresentation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, DeclineRequestPresentation),
			nil,
			strings.Replace(DeclineRequestPresentation, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_AcceptProblemReport(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, AcceptProblemReport),
			nil,
			strings.Replace(AcceptProblemReport, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_AcceptProposePresentation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("No payload", func(t *testing.T) {
		operation, err := New(provider(ctrl), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		buf, code, err := sendRequestToHandler(
			handlerLookup(t, operation, AcceptProposePresentation), nil,
			strings.Replace(AcceptProposePresentation, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "payload was not provided")
	})

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, AcceptProposePresentation),
			bytes.NewBufferString(`{"request_presentation":{}}`),
			strings.Replace(AcceptProposePresentation, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_DeclineProposePresentation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, DeclineProposePresentation),
			nil,
			strings.Replace(DeclineProposePresentation, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_AcceptPresentation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("No payload", func(t *testing.T) {
		operation, err := New(provider(ctrl), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		buf, code, err := sendRequestToHandler(
			handlerLookup(t, operation, AcceptPresentation),
			nil,
			strings.Replace(AcceptPresentation, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "payload was not provided")
	})

	t.Run("Empty payload (success)", func(t *testing.T) {
		operation, err := New(provider(ctrl), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, AcceptPresentation),
			bytes.NewBufferString(`{}`),
			strings.Replace(AcceptPresentation, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, AcceptPresentation),
			bytes.NewBufferString(`{"names":[]}`),
			strings.Replace(AcceptPresentation, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_DeclinePresentation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, DeclinePresentation),
			nil,
			strings.Replace(DeclinePresentation, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_NegotiateRequestPresentation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("No payload", func(t *testing.T) {
		operation, err := New(provider(ctrl), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		buf, code, err := sendRequestToHandler(
			handlerLookup(t, operation, NegotiateRequestPresentation), nil,
			strings.Replace(NegotiateRequestPresentation, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "payload was not provided")
	})

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, NegotiateRequestPresentation),
			bytes.NewBufferString(`{"propose_presentation":{}}`),
			strings.Replace(NegotiateRequestPresentation, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
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
