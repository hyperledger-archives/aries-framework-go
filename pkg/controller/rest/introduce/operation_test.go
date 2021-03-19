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
	mocknotifier "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/controller/webnotifier"
)

func provider(ctrl *gomock.Controller) client.Provider {
	service := mocks.NewMockProtocolService(ctrl)
	service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
	service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
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
		operation, err := New(provider(ctrl), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, Actions),
			nil,
			Actions,
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_SendProposal(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, SendProposal),
			bytes.NewBufferString(`{"recipients":[{},{}]}`),
			strings.Replace(SendProposal, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_SendProposalWithOOBInvitation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, SendProposalWithOOBInvitation),
			bytes.NewBufferString(`{"invitation":{}, "recipient":{}}`),
			strings.Replace(SendProposalWithOOBInvitation, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_SendRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, SendRequest),
			bytes.NewBufferString(`{"my_did":"my_did", "their_did":"their_did","please_introduce_to":{}}`),
			strings.Replace(SendRequest, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_AcceptProposalWithOOBRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("No payload", func(t *testing.T) {
		operation, err := New(provider(ctrl), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		buf, code, err := sendRequestToHandler(
			handlerLookup(t, operation, AcceptProposalWithOOBInvitation), nil,
			strings.Replace(AcceptProposalWithOOBInvitation, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "payload was not provided")
	})

	t.Run("Empty invitation", func(t *testing.T) {
		operation, err := New(provider(ctrl), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		buf, code, err := sendRequestToHandler(
			handlerLookup(t, operation, AcceptProposalWithOOBInvitation),
			bytes.NewBufferString(`{}`),
			strings.Replace(AcceptProposalWithOOBInvitation, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "empty invitation")
	})

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, AcceptProposalWithOOBInvitation),
			bytes.NewBufferString(`{"invitation":{}}`),
			strings.Replace(AcceptProposalWithOOBInvitation, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_AcceptProposal(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, AcceptProposal),
			nil,
			strings.Replace(AcceptProposal, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_AcceptRequestWithPublicOOBRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("No payload", func(t *testing.T) {
		operation, err := New(provider(ctrl), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		buf, code, err := sendRequestToHandler(
			handlerLookup(t, operation, AcceptRequestWithPublicOOBInvitation), nil,
			strings.Replace(AcceptRequestWithPublicOOBInvitation, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "payload was not provided")
	})

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, AcceptRequestWithPublicOOBInvitation),
			bytes.NewBufferString(`{"invitation":{},"to":{}}`),
			strings.Replace(AcceptRequestWithPublicOOBInvitation, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_AcceptRequestWithRecipients(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("No payload", func(t *testing.T) {
		operation, err := New(provider(ctrl), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		buf, code, err := sendRequestToHandler(
			handlerLookup(t, operation, AcceptRequestWithRecipients), nil,
			strings.Replace(AcceptRequestWithRecipients, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "payload was not provided")
	})

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, AcceptRequestWithRecipients),
			bytes.NewBufferString(`{"recipient":{},"to":{}}`),
			strings.Replace(AcceptRequestWithRecipients, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_DeclineRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, DeclineRequest),
			nil,
			strings.Replace(DeclineRequest, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_DeclineProposal(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, DeclineProposal),
			nil,
			strings.Replace(DeclineProposal, `{piid}`, "1234", 1),
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
