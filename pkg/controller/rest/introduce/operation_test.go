/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

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

	client "github.com/hyperledger/aries-framework-go/pkg/client/introduce"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	mocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/client/introduce"
)

func provider(ctrl *gomock.Controller) client.Provider {
	service := mocks.NewMockProtocolService(ctrl)
	service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
	service.EXPECT().ActionContinue(gomock.Any(), gomock.Any()).AnyTimes()
	service.EXPECT().ActionStop(gomock.Any(), gomock.Any()).AnyTimes()
	service.EXPECT().HandleOutbound(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	service.EXPECT().Actions().AnyTimes()

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(gomock.Any()).Return(service, nil)

	return provider
}

func TestOperation_Actions(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl))
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, actions),
			nil,
			actions,
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_SendProposal(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl))
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, sendProposal),
			bytes.NewBufferString(`{"recipients":[{},{}]}`),
			strings.Replace(sendProposal, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_SendProposalWithOOBRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl))
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, sendProposalWithOOBRequest),
			bytes.NewBufferString(`{"request":{}, "recipient":{}}`),
			strings.Replace(sendProposalWithOOBRequest, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_SendRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl))
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, sendRequest),
			bytes.NewBufferString(`{"my_did":"my_did", "their_did":"their_did","please_introduce_to":{}}`),
			strings.Replace(sendRequest, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_AcceptProposalWithOOBRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("No payload", func(t *testing.T) {
		operation, err := New(provider(ctrl))
		require.NoError(t, err)

		buf, code, err := sendRequestToHandler(
			handlerLookup(t, operation, acceptProposalWithOOBRequest), nil,
			strings.Replace(acceptProposalWithOOBRequest, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "payload was not provided")
	})

	t.Run("Empty request", func(t *testing.T) {
		operation, err := New(provider(ctrl))
		require.NoError(t, err)

		buf, code, err := sendRequestToHandler(
			handlerLookup(t, operation, acceptProposalWithOOBRequest),
			bytes.NewBufferString(`{}`),
			strings.Replace(acceptProposalWithOOBRequest, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "empty request")
	})

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl))
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, acceptProposalWithOOBRequest),
			bytes.NewBufferString(`{"request":{}}`),
			strings.Replace(acceptProposalWithOOBRequest, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_AcceptProposal(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl))
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, acceptProposal),
			nil,
			strings.Replace(acceptProposal, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_AcceptRequestWithPublicOOBRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("No payload", func(t *testing.T) {
		operation, err := New(provider(ctrl))
		require.NoError(t, err)

		buf, code, err := sendRequestToHandler(
			handlerLookup(t, operation, acceptRequestWithPublicOOBRequest), nil,
			strings.Replace(acceptRequestWithPublicOOBRequest, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "payload was not provided")
	})

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl))
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, acceptRequestWithPublicOOBRequest),
			bytes.NewBufferString(`{"request":{},"to":{}}`),
			strings.Replace(acceptRequestWithPublicOOBRequest, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_AcceptRequestWithRecipients(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("No payload", func(t *testing.T) {
		operation, err := New(provider(ctrl))
		require.NoError(t, err)

		buf, code, err := sendRequestToHandler(
			handlerLookup(t, operation, acceptRequestWithRecipients), nil,
			strings.Replace(acceptRequestWithRecipients, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "payload was not provided")
	})

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl))
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, acceptRequestWithRecipients),
			bytes.NewBufferString(`{"recipient":{},"to":{}}`),
			strings.Replace(acceptRequestWithRecipients, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_DeclineRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl))
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, declineRequest),
			nil,
			strings.Replace(declineRequest, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_DeclineProposal(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl))
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, declineProposal),
			nil,
			strings.Replace(declineProposal, `{piid}`, "1234", 1),
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
