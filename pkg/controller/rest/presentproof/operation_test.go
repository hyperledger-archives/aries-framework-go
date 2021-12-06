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
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	didcomm "github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	mocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/client/presentproof"
	mocks2 "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/controller/command/presentproof"
	mocknotifier "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/controller/webnotifier"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
)

func provider(ctrl *gomock.Controller, lookup *connection.Lookup) *mocks2.MockProvider {
	service := mocks.NewMockProtocolService(ctrl)
	service.EXPECT().RegisterActionEvent(gomock.Any()).Return(nil)
	service.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
	service.EXPECT().ActionContinue(gomock.Any(), gomock.Any()).AnyTimes()
	service.EXPECT().ActionStop(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	service.EXPECT().HandleOutbound(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

	provider := mocks2.NewMockProvider(ctrl)
	provider.EXPECT().Service(gomock.Any()).Return(service, nil)
	provider.EXPECT().ConnectionLookup().Return(lookup).AnyTimes()

	return provider
}

func TestOperation_SendRequestPresentation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("No MyID", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		buf, code, err := sendRequestToHandler(
			handlerLookup(t, operation, SendRequestPresentation), bytes.NewBufferString(`{}`),
			strings.Replace(SendRequestPresentation, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "empty MyDID")
	})

	t.Run("Success", func(t *testing.T) {
		rec := mockConnectionRecorder(t, connection.Record{
			MyDID:          "1",
			TheirDID:       "2",
			DIDCommVersion: didcomm.V1,
		})

		p := provider(ctrl, rec.Lookup)

		operation, err := New(p, mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, SendRequestPresentation),
			bytes.NewBufferString(`{"my_did":"1", "their_did":"2","request_presentation":{}}`),
			strings.Replace(SendRequestPresentation, `{piid}`, "1234", 1),
		)
		require.NoError(t, err)

		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_SendRequestPresentationV3(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("No MyID", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		buf, code, err := sendRequestToHandler(
			handlerLookup(t, operation, SendRequestPresentationV3), bytes.NewBufferString(`{}`),
			strings.Replace(SendRequestPresentationV3, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "empty MyDID")
	})

	t.Run("Success", func(t *testing.T) {
		lookup := mockConnectionRecorder(t, connection.Record{
			MyDID:          "1",
			TheirDID:       "2",
			DIDCommVersion: didcomm.V2,
		}).Lookup

		operation, err := New(provider(ctrl, lookup), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, SendRequestPresentationV3),
			bytes.NewBufferString(`{"my_did":"1", "their_did":"2","request_presentation":{}}`),
			strings.Replace(SendRequestPresentationV3, `{piid}`, "1234", 1),
		)
		require.NoError(t, err)

		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_SendProposePresentation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("No MyID", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		buf, code, err := sendRequestToHandler(
			handlerLookup(t, operation, SendProposePresentation), bytes.NewBufferString(`{}`),
			strings.Replace(SendProposePresentation, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "empty MyDID")
	})

	t.Run("Success", func(t *testing.T) {
		rec := mockConnectionRecorder(t, connection.Record{
			MyDID:          "1",
			TheirDID:       "2",
			DIDCommVersion: didcomm.V1,
		})

		operation, err := New(provider(ctrl, rec.Lookup), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, SendProposePresentation),
			bytes.NewBufferString(`{"my_did":"1", "their_did":"2","propose_presentation":{}}`),
			strings.Replace(SendProposePresentation, `{piid}`, "1234", 1),
		)
		require.NoError(t, err)

		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_SendProposePresentationV3(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("No MyID", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		buf, code, err := sendRequestToHandler(
			handlerLookup(t, operation, SendProposePresentationV3), bytes.NewBufferString(`{}`),
			strings.Replace(SendProposePresentationV3, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "empty MyDID")
	})

	t.Run("Success", func(t *testing.T) {
		lookup := mockConnectionRecorder(t, connection.Record{
			MyDID:          "1",
			TheirDID:       "2",
			DIDCommVersion: didcomm.V2,
		}).Lookup

		operation, err := New(provider(ctrl, lookup), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, SendProposePresentationV3),
			bytes.NewBufferString(`{"my_did":"1", "their_did":"2","propose_presentation":{}}`),
			strings.Replace(SendProposePresentationV3, `{piid}`, "1234", 1),
		)
		require.NoError(t, err)

		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_AcceptRequestPresentation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("No payload", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil))
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
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil))
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

func TestOperation_AcceptRequestPresentationV3(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("No payload", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		buf, code, err := sendRequestToHandler(
			handlerLookup(t, operation, AcceptRequestPresentationV3), nil,
			strings.Replace(AcceptRequestPresentationV3, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "payload was not provided")
	})

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, AcceptRequestPresentationV3),
			bytes.NewBufferString(`{"presentation":{}}`),
			strings.Replace(AcceptRequestPresentationV3, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_DeclineRequestPresentation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil))
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
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil))
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
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil))
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
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil))
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

func TestOperation_AcceptProposePresentationV3(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("No payload", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		buf, code, err := sendRequestToHandler(
			handlerLookup(t, operation, AcceptProposePresentationV3), nil,
			strings.Replace(AcceptProposePresentationV3, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "payload was not provided")
	})

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, AcceptProposePresentationV3),
			bytes.NewBufferString(`{"request_presentation":{}}`),
			strings.Replace(AcceptProposePresentationV3, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_DeclineProposePresentation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil))
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

	t.Run("Empty payload (success)", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil))
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
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil))
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
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil))
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
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil))
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
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil))
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

func TestOperation_NegotiateRequestPresentationV3(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("No payload", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		buf, code, err := sendRequestToHandler(
			handlerLookup(t, operation, NegotiateRequestPresentationV3), nil,
			strings.Replace(NegotiateRequestPresentationV3, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "payload was not provided")
	})

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil))
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, NegotiateRequestPresentationV3),
			bytes.NewBufferString(`{"propose_presentation":{}}`),
			strings.Replace(NegotiateRequestPresentationV3, `{piid}`, "1234", 1),
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

func mockConnectionRecorder(t *testing.T, records ...connection.Record) *connection.Recorder {
	t.Helper()

	storeProv := mockstore.NewMockStoreProvider()

	prov := mockprovider.Provider{
		StorageProviderValue:              storeProv,
		ProtocolStateStorageProviderValue: storeProv,
	}

	recorder, err := connection.NewRecorder(&prov)
	require.NoError(t, err)

	for i := 0; i < len(records); i++ {
		rec := records[i]

		if rec.ConnectionID == "" {
			rec.ConnectionID = uuid.New().String()
		}

		if rec.State == "" {
			rec.State = connection.StateNameCompleted
		}

		err = recorder.SaveConnectionRecord(&rec)
		require.NoError(t, err)
	}

	return recorder
}
