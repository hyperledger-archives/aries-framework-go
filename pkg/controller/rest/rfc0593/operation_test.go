/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rfc0593_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	client "github.com/hyperledger/aries-framework-go/pkg/client/issuecredential/rfc0593"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest/rfc0593"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

func TestOperation_GetCredentialSpec(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		expected := randomCredSpec(t)
		msg := service.NewDIDCommMsgMap(&issuecredential.OfferCredentialV2{
			Type: issuecredential.OfferCredentialMsgTypeV2,
			Formats: []issuecredential.Format{{
				AttachID: "123",
				Format:   client.ProofVCDetailFormat,
			}},
			OffersAttach: []decorator.Attachment{{
				ID: "123",
				Data: decorator.AttachmentData{
					JSON: expected,
				},
			}},
		})

		o := rfc0593.New(&mockProvider{ctx: agent(t)})

		response, code, err := sendRequestToHandler(
			handlerLookup(t, o, rfc0593.GetCredentialSpec),
			bytes.NewBufferString(fmt.Sprintf(`{"message": %s}`, marshal(t, msg))),
			rfc0593.GetCredentialSpec,
		)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)

		result := &struct {
			Spec *client.CredentialSpec `json:"spec"`
		}{}

		err = json.NewDecoder(response).Decode(result)
		require.NoError(t, err)
		require.Equal(t, expected, result.Spec)
	})
}

func TestOperation_VerifyCredential(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		agent := agent(t)
		spec := randomCredSpec(t)
		vc := newVCWithProof(t, agent, spec)

		o := rfc0593.New(&mockProvider{ctx: agent})

		_, code, err := sendRequestToHandler(
			handlerLookup(t, o, rfc0593.VerifyCredential),
			bytes.NewBufferString(fmt.Sprintf(`{"credential": %s, "spec": %s}`, marshal(t, vc), marshal(t, spec))),
			rfc0593.VerifyCredential,
		)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_IssueCredential(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		expected := newVC(t)
		spec := randomCredSpec(t)
		spec.Template = marshal(t, expected)

		agent := agent(t)
		o := rfc0593.New(&mockProvider{ctx: agent})

		response, code, err := sendRequestToHandler(
			handlerLookup(t, o, rfc0593.IssueCredential),
			bytes.NewBufferString(fmt.Sprintf(`{"spec": %s}`, marshal(t, spec))),
			rfc0593.IssueCredential,
		)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)

		result := &struct {
			Msg *issuecredential.IssueCredentialV2 `json:"issue_credential"`
		}{}

		err = json.NewDecoder(response).Decode(result)
		require.NoError(t, err)

		attachment, err := client.FindAttachment(client.ProofVCFormat, result.Msg.Formats, result.Msg.CredentialsAttach)
		require.NoError(t, err)

		resultVC := parseVC(t, attachment, agent)
		require.Equal(t, expected.ID, resultVC.ID)
	})
}

func parseVC(t *testing.T, a *decorator.Attachment, ctx *context.Provider) *verifiable.Credential {
	t.Helper()

	raw, err := a.Data.Fetch()
	require.NoError(t, err)

	vc, err := verifiable.ParseCredential(
		raw,
		verifiable.WithPublicKeyFetcher(verifiable.NewVDRKeyResolver(ctx.VDRegistry()).PublicKeyFetcher()),
		verifiable.WithJSONLDDocumentLoader(ctx.JSONLDDocumentLoader()),
	)
	require.NoError(t, err)

	return vc
}

func randomCredSpec(t *testing.T) *client.CredentialSpec {
	t.Helper()

	return &client.CredentialSpec{
		Template: marshal(t, newVC(t)),
		Options: &client.CredentialSpecOptions{
			ProofPurpose: "assertionMethod",
			Created:      time.Now().Format(time.RFC3339),
			Domain:       uuid.New().String(),
			Challenge:    uuid.New().String(),
			ProofType:    ed25519signature2018.SignatureType,
		},
	}
}

func newVCWithProof(t *testing.T, ctx *context.Provider, spec *client.CredentialSpec) *verifiable.Credential {
	t.Helper()

	vc, err := verifiable.ParseCredential(
		spec.Template,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(ctx.JSONLDDocumentLoader()),
	)
	require.NoError(t, err)

	created, err := time.Parse(time.RFC3339, spec.Options.Created)
	require.NoError(t, err)

	signer, verMethod := signer(t, ctx)

	err = vc.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
		SignatureType:           spec.Options.ProofType,
		Suite:                   ed25519signature2018.New(suite.WithSigner(signer)),
		SignatureRepresentation: verifiable.SignatureJWS,
		Created:                 &created,
		VerificationMethod:      verMethod,
		Challenge:               spec.Options.Challenge,
		Domain:                  spec.Options.Domain,
		Purpose:                 spec.Options.ProofPurpose,
	}, jsonld.WithDocumentLoader(ctx.JSONLDDocumentLoader()))
	require.NoError(t, err)

	return vc
}

func signer(t *testing.T, ctx *context.Provider) (*suite.CryptoSigner, string) {
	t.Helper()

	keyID, kh, err := ctx.KMS().Create(kms.ED25519Type)
	require.NoError(t, err)

	keyBytes, err := ctx.KMS().ExportPubKeyBytes(keyID)
	require.NoError(t, err)

	s := suite.NewCryptoSigner(ctx.Crypto(), kh)
	_, verMethod := fingerprint.CreateDIDKeyByCode(fingerprint.ED25519PubKeyMultiCodec, keyBytes)

	return s, verMethod
}

func newVC(t *testing.T) *verifiable.Credential {
	t.Helper()

	return &verifiable.Credential{
		Context: []string{verifiable.ContextURI, "https://w3id.org/security/bbs/v1"},
		Types:   []string{verifiable.VCType},
		ID:      uuid.New().URN(),
		Subject: verifiable.Subject{
			ID: uuid.New().URN(),
		},
		Issuer: verifiable.Issuer{
			ID: uuid.New().URN(),
		},
		Issued: util.NewTime(time.Now()),
	}
}

func marshal(t *testing.T, v interface{}) []byte {
	t.Helper()

	raw, err := json.Marshal(v)
	require.NoError(t, err)

	return raw
}

func handlerLookup(t *testing.T, op *rfc0593.Operation, lookup string) rest.Handler {
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

func agent(t *testing.T) *context.Provider {
	t.Helper()

	a, err := aries.New(
		aries.WithProtocolStateStoreProvider(mem.NewProvider()),
		aries.WithStoreProvider(mem.NewProvider()),
	)
	require.NoError(t, err)

	ctx, err := a.Context()
	require.NoError(t, err)

	return ctx
}

type mockProvider struct {
	ctx *context.Provider
}

func (m *mockProvider) JSONLDDocumentLoader() ld.DocumentLoader {
	return m.ctx.JSONLDDocumentLoader()
}

func (m *mockProvider) ProtocolStateStorageProvider() storage.Provider {
	return m.ctx.ProtocolStateStorageProvider()
}

func (m *mockProvider) KMS() kms.KeyManager {
	return m.ctx.KMS()
}

func (m *mockProvider) Crypto() crypto.Crypto {
	return m.ctx.Crypto()
}

func (m *mockProvider) VDRegistry() vdrapi.Registry {
	return m.ctx.VDRegistry()
}
