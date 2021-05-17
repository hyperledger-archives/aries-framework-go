/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rfc0593_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/client/issuecredential/rfc0593"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
)

func TestAutoExecute(t *testing.T) {
	t.Run("auto-executes RFC0593", func(t *testing.T) {
		provider := agent(t)
		events := make(chan service.DIDCommAction)
		go rfc0593.AutoExecute(provider, nil)(events)

		testCases := []struct {
			label string
			msg   interface{}
			check func(md *issuecredential.MetaData)
		}{
			{
				label: "handles proposals",
				check: func(md *issuecredential.MetaData) { require.NotEmpty(t, md.OfferCredential()) },
				msg: &issuecredential.ProposeCredential{
					Type: issuecredential.ProposeCredentialMsgType,
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
				},
			},
			{
				label: "handles offers",
				check: func(md *issuecredential.MetaData) { require.NotEmpty(t, md.RequestCredential()) },
				msg: &issuecredential.OfferCredential{
					Type: issuecredential.OfferCredentialMsgType,
					Formats: []issuecredential.Format{{
						AttachID: "123",
						Format:   rfc0593.ProofVCDetailFormat,
					}},
					OffersAttach: []decorator.Attachment{{
						ID: "123",
						Data: decorator.AttachmentData{
							JSON: randomCredSpec(t),
						},
					}},
				},
			},
			{
				label: "handles requests",
				check: func(md *issuecredential.MetaData) { require.NotEmpty(t, md.IssueCredential()) },
				msg: &issuecredential.RequestCredential{
					Type: issuecredential.RequestCredentialMsgType,
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
				},
			},
		}

		for i := range testCases {
			tc := testCases[i]

			t.Run(tc.label, func(t *testing.T) {
				var (
					arg interface{}
					err error
				)

				ready := make(chan struct{})

				go func() {
					events <- service.DIDCommAction{
						ProtocolName: issuecredential.Name,
						Message:      service.NewDIDCommMsgMap(tc.msg),
						Continue: func(a interface{}) {
							arg = a
							ready <- struct{}{}
						},
						Stop: func(e error) {
							err = e
							ready <- struct{}{}
						},
					}
				}()

				select {
				case <-ready:
				case <-time.After(time.Second):
					require.Fail(t, "timeout")
				}

				require.NoError(t, err)
				opt, ok := arg.(issuecredential.Opt)
				require.True(t, ok)

				md := &issuecredential.MetaData{}
				opt(md)

				tc.check(md)
			})
		}
	})

	t.Run("forwards events from other protocols", func(t *testing.T) {
		events := make(chan service.DIDCommAction)
		next := make(chan service.DIDCommAction)

		go rfc0593.AutoExecute(agent(t), next)(events)

		expected := &didexchange.Complete{
			ID:   uuid.New().String(),
			Type: didexchange.CompleteMsgType,
		}

		go func() {
			events <- service.DIDCommAction{
				Message: service.NewDIDCommMsgMap(expected),
			}
		}()

		select {
		case <-time.After(time.Second):
			require.Fail(t, "timeout")
		case event := <-next:
			result := &didexchange.Complete{}

			err := event.Message.Decode(result)
			require.NoError(t, err)

			require.Equal(t, expected, result)
		}
	})

	t.Run("forwards issue-credential events not related to RFC0593", func(t *testing.T) {
		events := make(chan service.DIDCommAction)
		next := make(chan service.DIDCommAction)

		go rfc0593.AutoExecute(agent(t), next)(events)

		expected := &issuecredential.RequestCredential{
			Type:    issuecredential.RequestCredentialMsgType,
			Comment: uuid.New().String(),
			RequestsAttach: []decorator.Attachment{{
				ID: uuid.New().String(),
				Data: decorator.AttachmentData{
					JSON: map[string]interface{}{},
				},
			}},
		}

		go func() {
			events <- service.DIDCommAction{
				Message: service.NewDIDCommMsgMap(expected),
			}
		}()

		select {
		case <-time.After(time.Second):
			require.Fail(t, "timeout")
		case event := <-next:
			result := &issuecredential.RequestCredential{}

			err := event.Message.Decode(result)
			require.NoError(t, err)
			require.Equal(t, expected, result)
		}
	})

	t.Run("stops the protocol in the event of an error", func(t *testing.T) {
		events := make(chan service.DIDCommAction)

		go rfc0593.AutoExecute(agent(t), nil)(events)

		ready := make(chan struct{})

		go func() {
			events <- service.DIDCommAction{
				Message: service.NewDIDCommMsgMap(&issuecredential.RequestCredential{
					Type:    issuecredential.RequestCredentialMsgType,
					Comment: uuid.New().String(),
					Formats: []issuecredential.Format{{
						AttachID: "123",
						Format:   rfc0593.ProofVCDetailFormat,
					}},
					RequestsAttach: []decorator.Attachment{{
						ID: "123",
						Data: decorator.AttachmentData{
							JSON: "INVALID",
						},
					}},
				}),
				Continue: func(interface{}) {
					require.Fail(t, "protocol was continued")
				},
				Stop: func(e error) {
					require.Error(t, e)
					require.Contains(t, e.Error(), "failed to unmarshal attachment contents")
					ready <- struct{}{}
				},
			}
		}()

		select {
		case <-ready:
		case <-time.After(time.Second):
			require.Fail(t, "timeout")
		}
	})
}

func TestReplayProposal(t *testing.T) {
	t.Run("replays the proposed spec as an offer", func(t *testing.T) {
		expected := &rfc0593.CredentialSpec{
			Template: marshal(t, newVC(t)),
			Options: &rfc0593.CredentialSpecOptions{
				ProofPurpose: "assertionMethod",
				Created:      time.Now().Format(time.RFC3339),
				Domain:       uuid.New().String(),
				Challenge:    uuid.New().String(),
				ProofType:    "Ed25519Signature2018",
				Status:       &rfc0593.CredentialStatus{Type: "test"},
			},
		}

		arg, err := rfc0593.ReplayProposal(agent(t), service.NewDIDCommMsgMap(&issuecredential.ProposeCredential{
			Type: issuecredential.ProposeCredentialMsgType,
			Formats: []issuecredential.Format{{
				AttachID: "123",
				Format:   rfc0593.ProofVCDetailFormat,
			}},
			FiltersAttach: []decorator.Attachment{{
				ID: "123",
				Data: decorator.AttachmentData{
					JSON: expected,
				},
			}},
		}))
		require.NoError(t, err)

		opt, ok := arg.(issuecredential.Opt)
		require.True(t, ok)

		md := &issuecredential.MetaData{}
		opt(md)

		require.NotEmpty(t, md.OfferCredential())
		require.Equal(t,
			expected,
			extractPayload(t,
				rfc0593.ProofVCDetailFormat, md.OfferCredential().Formats, md.OfferCredential().OffersAttach),
		)
	})

	t.Run("error if VC is malformed", func(t *testing.T) {
		spec := randomCredSpec(t)
		spec.Template = nil

		_, err := rfc0593.ReplayProposal(agent(t), service.NewDIDCommMsgMap(&issuecredential.ProposeCredential{
			Type: issuecredential.ProposeCredentialMsgType,
			Formats: []issuecredential.Format{{
				AttachID: "123",
				Format:   rfc0593.ProofVCDetailFormat,
			}},
			FiltersAttach: []decorator.Attachment{{
				ID: "123",
				Data: decorator.AttachmentData{
					JSON: spec,
				},
			}},
		}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to parse vc")
	})
}

func TestReplayOffer(t *testing.T) {
	t.Run("replays the offered spec as a request", func(t *testing.T) {
		expected := &rfc0593.CredentialSpec{
			Template: marshal(t, newVC(t)),
			Options: &rfc0593.CredentialSpecOptions{
				ProofPurpose: "assertionMethod",
				Created:      time.Now().Format(time.RFC3339),
				Domain:       uuid.New().String(),
				Challenge:    uuid.New().String(),
				ProofType:    "Ed25519Signature2018",
				Status:       &rfc0593.CredentialStatus{Type: "test"},
			},
		}

		arg, err := rfc0593.ReplayOffer(agent(t), service.NewDIDCommMsgMap(&issuecredential.OfferCredential{
			Type: issuecredential.OfferCredentialMsgType,
			Formats: []issuecredential.Format{{
				AttachID: "123",
				Format:   rfc0593.ProofVCDetailFormat,
			}},
			OffersAttach: []decorator.Attachment{{
				ID: "123",
				Data: decorator.AttachmentData{
					JSON: expected,
				},
			}},
		}))
		require.NoError(t, err)

		opt, ok := arg.(issuecredential.Opt)
		require.True(t, ok)

		md := &issuecredential.MetaData{}
		opt(md)

		require.NotEmpty(t, md.RequestCredential())
		require.Equal(t,
			expected,
			extractPayload(t,
				rfc0593.ProofVCDetailFormat, md.RequestCredential().Formats, md.RequestCredential().RequestsAttach),
		)
	})

	t.Run("error if VC is malformed", func(t *testing.T) {
		spec := randomCredSpec(t)
		spec.Template = nil

		_, err := rfc0593.ReplayOffer(agent(t), service.NewDIDCommMsgMap(&issuecredential.OfferCredential{
			Type: issuecredential.OfferCredentialMsgType,
			Formats: []issuecredential.Format{{
				AttachID: "123",
				Format:   rfc0593.ProofVCDetailFormat,
			}},
			OffersAttach: []decorator.Attachment{{
				ID: "123",
				Data: decorator.AttachmentData{
					JSON: spec,
				},
			}},
		}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to parse vc")
	})
}

func TestIssueCredential(t *testing.T) {
	t.Run("attaches LD proof and produces a request-credential message with the VC attached", func(t *testing.T) {
		t.Run("Ed25519", func(t *testing.T) {
			agent := agent(t)
			unverifiedCredential := newVC(t)
			spec := &rfc0593.CredentialSpec{
				Template: marshal(t, unverifiedCredential),
				Options: &rfc0593.CredentialSpecOptions{
					ProofPurpose: "assertionMethod",
					Created:      time.Now().Format(time.RFC3339),
					Domain:       uuid.New().String(),
					Challenge:    uuid.New().String(),
					ProofType:    "Ed25519Signature2018",
					Status:       &rfc0593.CredentialStatus{Type: "test"},
				},
			}

			arg, err := rfc0593.IssueCredential(agent, service.NewDIDCommMsgMap(&issuecredential.RequestCredential{
				Type: issuecredential.RequestCredentialMsgType,
				Formats: []issuecredential.Format{{
					AttachID: "123",
					Format:   rfc0593.ProofVCDetailFormat,
				}},
				RequestsAttach: []decorator.Attachment{{
					ID: "123",
					Data: decorator.AttachmentData{
						JSON: spec,
					},
				}},
			}))
			require.NoError(t, err)

			opt, ok := arg.(issuecredential.Opt)
			require.True(t, ok)

			md := &issuecredential.MetaData{}
			opt(md)

			require.NotEmpty(t, md.IssueCredential())
			require.NotEmpty(t, md.IssueCredential().CredentialsAttach)

			raw, err := md.IssueCredential().CredentialsAttach[0].Data.Fetch()
			require.NoError(t, err)

			verifiableCredential, err := verifiable.ParseCredential(
				raw,
				verifiable.WithPublicKeyFetcher(verifiable.NewVDRKeyResolver(agent.VDRegistry()).PublicKeyFetcher()),
				verifiable.WithJSONLDDocumentLoader(agent.JSONLDDocumentLoader()),
			)
			require.NoError(t, err)

			require.Equal(t, unverifiedCredential.ID, verifiableCredential.ID)
			require.NotEmpty(t, verifiableCredential.Proofs)
			require.Equal(t, spec.Options.Challenge, verifiableCredential.Proofs[0]["challenge"])
			require.Equal(t, spec.Options.Domain, verifiableCredential.Proofs[0]["domain"])
		})

		t.Run("BbsBlsSignature2020", func(t *testing.T) {
			agent := agent(t)
			unverifiedCredential := newVC(t)

			spec := &rfc0593.CredentialSpec{
				Template: marshal(t, unverifiedCredential),
				Options: &rfc0593.CredentialSpecOptions{
					ProofPurpose: "assertionMethod",
					Created:      time.Now().Format(time.RFC3339),
					Domain:       uuid.New().String(),
					Challenge:    uuid.New().String(),
					ProofType:    "BbsBlsSignature2020",
					Status:       &rfc0593.CredentialStatus{Type: "test"},
				},
			}

			arg, err := rfc0593.IssueCredential(agent, service.NewDIDCommMsgMap(&issuecredential.RequestCredential{
				Type: issuecredential.RequestCredentialMsgType,
				Formats: []issuecredential.Format{{
					AttachID: "123",
					Format:   rfc0593.ProofVCDetailFormat,
				}},
				RequestsAttach: []decorator.Attachment{{
					ID: "123",
					Data: decorator.AttachmentData{
						JSON: spec,
					},
				}},
			}))
			require.NoError(t, err)

			opt, ok := arg.(issuecredential.Opt)
			require.True(t, ok)

			md := &issuecredential.MetaData{}
			opt(md)

			require.NotEmpty(t, md.IssueCredential())
			require.NotEmpty(t, md.IssueCredential().CredentialsAttach)

			raw, err := md.IssueCredential().CredentialsAttach[0].Data.Fetch()
			require.NoError(t, err)

			verifiableCredential, err := verifiable.ParseCredential(
				raw,
				verifiable.WithPublicKeyFetcher(verifiable.NewVDRKeyResolver(agent.VDRegistry()).PublicKeyFetcher()),
				verifiable.WithJSONLDDocumentLoader(agent.JSONLDDocumentLoader()),
			)
			require.NoError(t, err)

			require.Equal(t, unverifiedCredential.ID, verifiableCredential.ID)
			require.NotEmpty(t, verifiableCredential.Proofs)
			require.Equal(t, spec.Options.Challenge, verifiableCredential.Proofs[0]["challenge"])
			require.Equal(t, spec.Options.Domain, verifiableCredential.Proofs[0]["domain"])
		})
	})

	t.Run("error if VC is malformed", func(t *testing.T) {
		spec := randomCredSpec(t)
		spec.Template = nil

		_, err := rfc0593.IssueCredential(agent(t), service.NewDIDCommMsgMap(&issuecredential.RequestCredential{
			Type: issuecredential.RequestCredentialMsgType,
			Formats: []issuecredential.Format{{
				AttachID: "123",
				Format:   rfc0593.ProofVCDetailFormat,
			}},
			RequestsAttach: []decorator.Attachment{{
				ID: "123",
				Data: decorator.AttachmentData{
					JSON: spec,
				},
			}},
		}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to parse vc")
	})

	t.Run("error on unsupported proofType", func(t *testing.T) {
		spec := randomCredSpec(t)
		spec.Options.ProofType = "UNSUPPORTED"

		_, err := rfc0593.IssueCredential(agent(t), service.NewDIDCommMsgMap(&issuecredential.RequestCredential{
			Type: issuecredential.RequestCredentialMsgType,
			Formats: []issuecredential.Format{{
				AttachID: "123",
				Format:   rfc0593.ProofVCDetailFormat,
			}},
			RequestsAttach: []decorator.Attachment{{
				ID: "123",
				Data: decorator.AttachmentData{
					JSON: spec,
				},
			}},
		}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported proof type")
	})

	t.Run("error if cannot add LD proof", func(t *testing.T) {
		expected := errors.New("test")
		spec := randomCredSpec(t)
		ctx := agent(t)
		provider := &mockProvider{
			loader: ctx.JSONLDDocumentLoader(),
			km:     ctx.KMS(),
			cr:     &mockcrypto.Crypto{SignErr: expected},
		}

		_, err := rfc0593.IssueCredential(provider, service.NewDIDCommMsgMap(&issuecredential.RequestCredential{
			Type: issuecredential.RequestCredentialMsgType,
			Formats: []issuecredential.Format{{
				AttachID: "123",
				Format:   rfc0593.ProofVCDetailFormat,
			}},
			RequestsAttach: []decorator.Attachment{{
				ID: "123",
				Data: decorator.AttachmentData{
					JSON: spec,
				},
			}},
		}))
		require.ErrorIs(t, err, expected)
	})
}

func marshal(t *testing.T, v interface{}) []byte {
	t.Helper()

	raw, err := json.Marshal(v)
	require.NoError(t, err)

	return raw
}

func agent(t *testing.T) *context.Provider {
	t.Helper()

	a, err := aries.New(
		aries.WithStoreProvider(mem.NewProvider()),
		aries.WithProtocolStateStoreProvider(mem.NewProvider()),
	)
	require.NoError(t, err)

	t.Cleanup(func() {
		err = a.Close()
		require.NoError(t, err)
	})

	ctx, err := a.Context()
	require.NoError(t, err)

	return ctx
}

func extractPayload(t *testing.T,
	formatID string, formats []issuecredential.Format, attachments []decorator.Attachment) *rfc0593.CredentialSpec {
	t.Helper()

	var attachID string

	for i := range formats {
		if formats[i].Format == formatID {
			attachID = formats[i].AttachID

			break
		}
	}

	require.NotEmpty(t, attachID)

	var a *decorator.Attachment

	for i := range attachments {
		if attachments[i].ID == attachID {
			a = &attachments[i]

			break
		}
	}

	require.NotNil(t, a)
	require.NotZero(t, a.Data)

	raw, err := a.Data.Fetch()
	require.NoError(t, err)

	spec := &rfc0593.CredentialSpec{}

	err = json.Unmarshal(raw, spec)
	require.NoError(t, err)

	return spec
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

func randomCredSpec(t *testing.T) *rfc0593.CredentialSpec {
	t.Helper()

	return &rfc0593.CredentialSpec{
		Template: marshal(t, newVC(t)),
		Options: &rfc0593.CredentialSpecOptions{
			ProofPurpose: "assertionMethod",
			Created:      time.Now().Format(time.RFC3339),
			Domain:       uuid.New().String(),
			Challenge:    uuid.New().String(),
			ProofType:    "Ed25519Signature2018",
		},
	}
}

type mockProvider struct {
	loader ld.DocumentLoader
	km     kms.KeyManager
	cr     crypto.Crypto
}

func (m *mockProvider) JSONLDDocumentLoader() ld.DocumentLoader {
	return m.loader
}

func (m *mockProvider) KMS() kms.KeyManager {
	return m.km
}

func (m *mockProvider) Crypto() crypto.Crypto {
	return m.cr
}
