/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rfc0593_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/client/issuecredential/rfc0593"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
)

func TestMiddleware(t *testing.T) {
	t.Run("saves options from request-credential", func(t *testing.T) {
		store := &mockstorage.MockStore{Store: make(map[string]mockstorage.DBEntry)}
		mw, err := rfc0593.NewMiddleware(&mockProvider{sp: &mockstorage.MockStoreProvider{Store: store}})
		require.NoError(t, err)

		expected := randomCredSpec(t)
		attachID := uuid.New().String()

		thid := uuid.New().String()
		msg := service.NewDIDCommMsgMap(&issuecredential.RequestCredentialV2{
			Type: issuecredential.RequestCredentialMsgTypeV2,
			Formats: []issuecredential.Format{{
				AttachID: attachID,
				Format:   rfc0593.ProofVCDetailFormat,
			}},
			RequestsAttach: []decorator.Attachment{{
				ID: attachID,
				Data: decorator.AttachmentData{
					JSON: expected,
				},
			}},
		})
		msg.SetID(thid)

		nextCalled := false

		next := &mockHandler{
			handleFunc: func(md issuecredential.Metadata) error {
				nextCalled = true

				return nil
			},
		}

		err = mw(next).Handle(&mockMetadata{
			msg: msg,
		})
		require.NoError(t, err)

		raw, err := store.Get(thid)
		require.NoError(t, err)

		result := &rfc0593.CredentialSpecOptions{}

		err = json.Unmarshal(raw, result)
		require.NoError(t, err)
		require.Equal(t, expected.Options, result)
		require.True(t, nextCalled)
	})

	t.Run("forwards to next for other messages", func(t *testing.T) {
		mw, err := rfc0593.NewMiddleware(agent(t))
		require.NoError(t, err)

		msg := service.NewDIDCommMsgMap(&issuecredential.ProposeCredentialV2{
			Type: issuecredential.ProposeCredentialMsgTypeV2,
			Formats: []issuecredential.Format{{
				AttachID: "123",
				Format:   rfc0593.ProofVCDetailFormat,
			}},
			FiltersAttach: []decorator.Attachment{{
				ID: "123",
				Data: decorator.AttachmentData{
					JSON: randomCredSpec(t),
				},
			}},
		})
		require.NoError(t, err)

		nextCalled := false

		next := &mockHandler{
			handleFunc: func(md issuecredential.Metadata) error {
				nextCalled = true

				return nil
			},
		}

		err = mw(next).Handle(&mockMetadata{
			msg: msg,
		})
		require.NoError(t, err)
		require.True(t, nextCalled)
	})

	t.Run("forwards to next is RFC0593 is not applicable", func(t *testing.T) {
		mw, err := rfc0593.NewMiddleware(agent(t))
		require.NoError(t, err)

		msg := service.NewDIDCommMsgMap(&issuecredential.RequestCredentialV2{
			Type: issuecredential.RequestCredentialMsgTypeV2,
			Formats: []issuecredential.Format{{
				AttachID: "123",
				Format:   "SOME_OTHER_FORMAT",
			}},
			RequestsAttach: []decorator.Attachment{{
				ID: "123",
				Data: decorator.AttachmentData{
					JSON: randomCredSpec(t),
				},
			}},
		})
		require.NoError(t, err)

		nextCalled := false

		next := &mockHandler{
			handleFunc: func(md issuecredential.Metadata) error {
				nextCalled = true

				return nil
			},
		}

		err = mw(next).Handle(&mockMetadata{
			msg: msg,
		})
		require.NoError(t, err)
		require.True(t, nextCalled)
	})

	t.Run("error if cannot save to storage", func(t *testing.T) {
		expected := errors.New("test")

		provider := &mockProvider{
			sp: &mockstorage.MockStoreProvider{
				Store: &mockstorage.MockStore{
					ErrPut: expected,
				},
			},
		}
		mw, err := rfc0593.NewMiddleware(provider)
		require.NoError(t, err)

		msg := service.NewDIDCommMsgMap(&issuecredential.RequestCredentialV2{
			Type: issuecredential.RequestCredentialMsgTypeV2,
			Formats: []issuecredential.Format{{
				AttachID: "123",
				Format:   rfc0593.ProofVCDetailFormat,
			}},
			RequestsAttach: []decorator.Attachment{{
				ID: "123",
				Data: decorator.AttachmentData{
					JSON: randomCredSpec(t),
				},
			}},
		})
		msg.SetID(uuid.New().String())

		err = mw(nil).Handle(&mockMetadata{
			msg: msg,
		})
		require.ErrorIs(t, err, expected)
	})

	t.Run("error if cannot open store", func(t *testing.T) {
		expected := errors.New("test")

		provider := &mockProvider{
			sp: &mockstorage.MockStoreProvider{
				ErrOpenStoreHandle: expected,
			},
		}
		_, err := rfc0593.NewMiddleware(provider)
		require.ErrorIs(t, err, expected)
	})
}

func TestRegisterMiddleware(t *testing.T) {
	t.Run("registers middleware", func(t *testing.T) {
		mw, err := rfc0593.NewMiddleware(agent(t))
		require.NoError(t, err)

		registered := false

		provider := &mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				issuecredential.Name: &mockIssueCredentialSvc{
					addMWFunc: func(middleware ...issuecredential.Middleware) {
						registered = true
						require.Len(t, middleware, 1)
					},
				},
			},
		}

		err = rfc0593.RegisterMiddleware(mw, provider)
		require.NoError(t, err)
		require.True(t, registered)
	})

	t.Run("error if cannot lookup service", func(t *testing.T) {
		expected := errors.New("test")

		mw, err := rfc0593.NewMiddleware(agent(t))
		require.NoError(t, err)

		provider := &mockprovider.Provider{
			ServiceErr: expected,
		}

		err = rfc0593.RegisterMiddleware(mw, provider)
		require.ErrorIs(t, err, expected)
	})

	t.Run("error if cannot cast service to API dependency", func(t *testing.T) {
		mw, err := rfc0593.NewMiddleware(agent(t))
		require.NoError(t, err)

		provider := &mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				issuecredential.Name: struct{}{},
			},
		}

		err = rfc0593.RegisterMiddleware(mw, provider)
		require.EqualError(t, err, "unable to cast the issuecredential service to the required interface type")
	})
}

type mockMetadata struct {
	msg service.DIDCommMsg
}

func (m *mockMetadata) Message() service.DIDCommMsg {
	return m.msg
}

func (m *mockMetadata) OfferCredentialV2() *issuecredential.OfferCredentialV2 {
	panic("implement me")
}

func (m *mockMetadata) ProposeCredentialV2() *issuecredential.ProposeCredentialV2 {
	panic("implement me")
}

func (m *mockMetadata) IssueCredentialV2() *issuecredential.IssueCredentialV2 {
	panic("implement me")
}

func (m *mockMetadata) RequestCredentialV2() *issuecredential.RequestCredentialV2 {
	panic("implement me")
}

func (m *mockMetadata) CredentialNames() []string {
	panic("implement me")
}

func (m *mockMetadata) StateName() string {
	panic("implement me")
}

func (m *mockMetadata) Properties() map[string]interface{} {
	panic("implement me")
}

type mockHandler struct {
	handleFunc func(issuecredential.Metadata) error
}

func (m *mockHandler) Handle(md issuecredential.Metadata) error {
	return m.handleFunc(md)
}

type mockIssueCredentialSvc struct {
	addMWFunc func(...issuecredential.Middleware)
}

func (m *mockIssueCredentialSvc) AddMiddleware(middleware ...issuecredential.Middleware) {
	m.addMWFunc(middleware...)
}
