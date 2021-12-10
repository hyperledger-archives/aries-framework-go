/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

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
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	command "github.com/hyperledger/aries-framework-go/pkg/controller/command/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	mocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/controller/command/issuecredential"
	mocknotifier "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/controller/webnotifier"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

func provider(ctrl *gomock.Controller, lookup *connection.Lookup) command.Provider {
	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().Service(gomock.Any()).Return(&mockService{}, nil).MaxTimes(2)
	provider.EXPECT().ConnectionLookup().Return(lookup).AnyTimes()

	return provider
}

func TestOperation_AcceptProposal(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("No payload", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil), &mockRFC0593Provider{})
		require.NoError(t, err)

		buf, code, err := sendRequestToHandler(
			handlerLookup(t, operation, AcceptProposal), nil,
			strings.Replace(AcceptProposal, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "payload was not provided")
	})

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil), &mockRFC0593Provider{})
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, AcceptProposal),
			bytes.NewBufferString(`{"offer_credential":{}}`),
			strings.Replace(AcceptProposal, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_SendRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("No payload", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil), &mockRFC0593Provider{})
		require.NoError(t, err)

		buf, code, err := sendRequestToHandler(
			handlerLookup(t, operation, SendRequest), nil,
			strings.Replace(SendRequest, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "payload was not provided")
	})

	t.Run("Success", func(t *testing.T) {
		rec := mockConnectionRecorder(t, connection.Record{
			MyDID:    "id",
			TheirDID: "id",
		})
		operation, err := New(provider(ctrl, rec.Lookup), mocknotifier.NewMockNotifier(nil), &mockRFC0593Provider{})
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, SendRequest),
			bytes.NewBufferString(`{"my_did":"id","their_did":"id","request_credential":{}}`),
			strings.Replace(SendRequest, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_SendRequestV3(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("No payload", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil), &mockRFC0593Provider{})
		require.NoError(t, err)

		buf, code, err := sendRequestToHandler(
			handlerLookup(t, operation, SendRequestV3), nil,
			strings.Replace(SendRequestV3, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "payload was not provided")
	})

	t.Run("Success", func(t *testing.T) {
		rec := mockConnectionRecorder(t, connection.Record{
			MyDID:          "id",
			TheirDID:       "id",
			DIDCommVersion: service.V2,
		})
		operation, err := New(provider(ctrl, rec.Lookup), mocknotifier.NewMockNotifier(nil), &mockRFC0593Provider{})
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, SendRequestV3),
			bytes.NewBufferString(`{"my_did":"id","their_did":"id","request_credential":{}}`),
			strings.Replace(SendRequestV3, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_SendOffer(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("No payload", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil), &mockRFC0593Provider{})
		require.NoError(t, err)

		buf, code, err := sendRequestToHandler(
			handlerLookup(t, operation, SendOffer), nil,
			strings.Replace(SendOffer, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "payload was not provided")
	})

	t.Run("Success", func(t *testing.T) {
		rec := mockConnectionRecorder(t, connection.Record{
			MyDID:    "id",
			TheirDID: "id",
		})
		operation, err := New(provider(ctrl, rec.Lookup), mocknotifier.NewMockNotifier(nil), &mockRFC0593Provider{})
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, SendOffer),
			bytes.NewBufferString(`{"my_did":"id","their_did":"id","offer_credential":{}}`),
			strings.Replace(SendOffer, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_SendOfferV3(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("No payload", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil), &mockRFC0593Provider{})
		require.NoError(t, err)

		buf, code, err := sendRequestToHandler(
			handlerLookup(t, operation, SendOfferV3), nil,
			strings.Replace(SendOfferV3, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "payload was not provided")
	})

	t.Run("Success", func(t *testing.T) {
		rec := mockConnectionRecorder(t, connection.Record{
			MyDID:          "id",
			TheirDID:       "id",
			DIDCommVersion: service.V2,
		})
		operation, err := New(provider(ctrl, rec.Lookup), mocknotifier.NewMockNotifier(nil), &mockRFC0593Provider{})
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, SendOfferV3),
			bytes.NewBufferString(`{"my_did":"id","their_did":"id","offer_credential":{}}`),
			strings.Replace(SendOfferV3, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_AcceptProposalV3(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("No payload", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil), &mockRFC0593Provider{})
		require.NoError(t, err)

		buf, code, err := sendRequestToHandler(
			handlerLookup(t, operation, AcceptProposalV3), nil,
			strings.Replace(AcceptProposalV3, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "payload was not provided")
	})

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil), &mockRFC0593Provider{})
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, AcceptProposalV3),
			bytes.NewBufferString(`{"offer_credential":{}}`),
			strings.Replace(AcceptProposalV3, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_AcceptOffer(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil), &mockRFC0593Provider{})
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, AcceptOffer),
			nil,
			strings.Replace(AcceptOffer, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_AcceptProblemReport(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil), &mockRFC0593Provider{})
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

func TestOperation_AcceptRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("No payload", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil), &mockRFC0593Provider{})
		require.NoError(t, err)

		buf, code, err := sendRequestToHandler(
			handlerLookup(t, operation, AcceptRequest), nil,
			strings.Replace(AcceptRequest, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "payload was not provided")
	})

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil), &mockRFC0593Provider{})
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, AcceptRequest),
			bytes.NewBufferString(`{"issue_credential":{}}`),
			strings.Replace(AcceptRequest, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_AcceptRequestV3(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("No payload", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil), &mockRFC0593Provider{})
		require.NoError(t, err)

		buf, code, err := sendRequestToHandler(
			handlerLookup(t, operation, AcceptRequestV3), nil,
			strings.Replace(AcceptRequestV3, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "payload was not provided")
	})

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil), &mockRFC0593Provider{})
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, AcceptRequestV3),
			bytes.NewBufferString(`{"issue_credential":{}}`),
			strings.Replace(AcceptRequestV3, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_NegotiateProposal(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("No payload", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil), &mockRFC0593Provider{})
		require.NoError(t, err)

		buf, code, err := sendRequestToHandler(
			handlerLookup(t, operation, NegotiateProposal), nil,
			strings.Replace(NegotiateProposal, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "payload was not provided")
	})

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil), &mockRFC0593Provider{})
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, NegotiateProposal),
			bytes.NewBufferString(`{"propose_credential":{}}`),
			strings.Replace(NegotiateProposal, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_NegotiateProposalV3(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("No payload", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil), &mockRFC0593Provider{})
		require.NoError(t, err)

		buf, code, err := sendRequestToHandler(
			handlerLookup(t, operation, NegotiateProposalV3), nil,
			strings.Replace(NegotiateProposalV3, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "payload was not provided")
	})

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil), &mockRFC0593Provider{})
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, NegotiateProposalV3),
			bytes.NewBufferString(`{"propose_credential":{}}`),
			strings.Replace(NegotiateProposalV3, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_AcceptCredential(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("No payload", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil), &mockRFC0593Provider{})
		require.NoError(t, err)

		buf, code, err := sendRequestToHandler(
			handlerLookup(t, operation, AcceptCredential), nil,
			strings.Replace(AcceptCredential, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "payload was not provided")
	})

	t.Run("Empty payload (success)", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil), &mockRFC0593Provider{})
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, AcceptCredential),
			bytes.NewBufferString(`{}`),
			strings.Replace(AcceptCredential, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil), &mockRFC0593Provider{})
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, AcceptCredential),
			bytes.NewBufferString(`{"names":[]}`),
			strings.Replace(AcceptCredential, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_DeclineProposal(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil), &mockRFC0593Provider{})
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

func TestOperation_DeclineOffer(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil), &mockRFC0593Provider{})
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, DeclineOffer),
			nil,
			strings.Replace(DeclineOffer, `{piid}`, "1234", 1),
		)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_DeclineRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil), &mockRFC0593Provider{})
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

func TestOperation_DeclineCredential(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		operation, err := New(provider(ctrl, nil), mocknotifier.NewMockNotifier(nil), &mockRFC0593Provider{})
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(
			handlerLookup(t, operation, DeclineCredential),
			nil,
			strings.Replace(DeclineCredential, `{piid}`, "1234", 1),
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

type mockRFC0593Provider struct{}

func (m *mockRFC0593Provider) JSONLDDocumentLoader() ld.DocumentLoader {
	panic("implement me")
}

func (m *mockRFC0593Provider) ProtocolStateStorageProvider() storage.Provider {
	return mem.NewProvider()
}

func (m *mockRFC0593Provider) KMS() kms.KeyManager {
	panic("implement me")
}

func (m *mockRFC0593Provider) Crypto() crypto.Crypto {
	panic("implement me")
}

func (m *mockRFC0593Provider) VDRegistry() vdrapi.Registry {
	panic("implement me")
}

type mockService struct{}

func (m *mockService) HandleInbound(service.DIDCommMsg, service.DIDCommContext) (string, error) {
	return "", nil
}

func (m *mockService) HandleOutbound(service.DIDCommMsg, string, string) (string, error) {
	return "", nil
}

func (m *mockService) RegisterActionEvent(chan<- service.DIDCommAction) error {
	return nil
}

func (m *mockService) UnregisterActionEvent(chan<- service.DIDCommAction) error {
	return nil
}

func (m *mockService) RegisterMsgEvent(chan<- service.StateMsg) error {
	return nil
}

func (m *mockService) UnregisterMsgEvent(chan<- service.StateMsg) error {
	return nil
}

func (m *mockService) Actions() ([]issuecredential.Action, error) {
	return nil, nil
}

func (m *mockService) ActionContinue(string, ...issuecredential.Opt) error {
	return nil
}

func (m *mockService) ActionStop(string, error, ...issuecredential.Opt) error {
	return nil
}

func (m *mockService) AddMiddleware(...issuecredential.Middleware) {}

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
