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
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

func TestAutoExecute(t *testing.T) { // nolint:gocyclo
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
				check: func(md *issuecredential.MetaData) { require.NotEmpty(t, md.OfferCredentialV2()) },
				msg: &issuecredential.ProposeCredentialV2{
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
				},
			},
			{
				label: "handles offers",
				check: func(md *issuecredential.MetaData) { require.NotEmpty(t, md.RequestCredentialV2()) },
				msg: &issuecredential.OfferCredentialV2{
					Type: issuecredential.OfferCredentialMsgTypeV2,
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
				check: func(md *issuecredential.MetaData) { require.NotEmpty(t, md.IssueCredentialV2()) },
				msg: &issuecredential.RequestCredentialV2{
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
				msg := service.NewDIDCommMsgMap(tc.msg)
				msg.SetID(uuid.New().String())

				go func() {
					events <- service.DIDCommAction{
						ProtocolName: issuecredential.Name,
						Message:      msg,
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

		expected := &issuecredential.RequestCredentialV2{
			Type:    issuecredential.RequestCredentialMsgTypeV2,
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
			result := &issuecredential.RequestCredentialV2{}

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
				Message: service.NewDIDCommMsgMap(&issuecredential.RequestCredentialV2{
					Type:    issuecredential.RequestCredentialMsgTypeV2,
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

	t.Run("stops the protocol if the DB cannot be opened", func(t *testing.T) {
		events := make(chan service.DIDCommAction)

		agent := agent(t, withProtoStateStorageProvider(&mockstorage.MockStoreProvider{
			Store:         &mockstorage.MockStore{Store: make(map[string]mockstorage.DBEntry)},
			FailNamespace: rfc0593.StoreName,
		}))

		go rfc0593.AutoExecute(agent, nil)(events)

		ready := make(chan struct{})

		go func() {
			events <- service.DIDCommAction{
				Message: service.NewDIDCommMsgMap(&issuecredential.RequestCredentialV2{
					Type:    issuecredential.RequestCredentialMsgTypeV2,
					Comment: uuid.New().String(),
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
				}),
				Continue: func(interface{}) {
					require.Fail(t, "protocol was continued")
				},
				Stop: func(e error) {
					require.Error(t, e)
					require.Contains(t, e.Error(), "failed to open store")
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

		arg, options, err := rfc0593.ReplayProposal(agent(t), service.NewDIDCommMsgMap(&issuecredential.ProposeCredentialV2{
			Type: issuecredential.ProposeCredentialMsgTypeV2,
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
		require.Equal(t, expected.Options, options)

		opt, ok := arg.(issuecredential.Opt)
		require.True(t, ok)

		md := &issuecredential.MetaData{}
		opt(md)

		require.NotEmpty(t, md.OfferCredentialV2())
		require.Equal(t,
			expected,
			extractPayload(t,
				rfc0593.ProofVCDetailFormat, md.OfferCredentialV2().Formats, md.OfferCredentialV2().OffersAttach),
		)
	})

	t.Run("error if VC is malformed", func(t *testing.T) {
		spec := randomCredSpec(t)
		spec.Template = nil

		_, _, err := rfc0593.ReplayProposal(agent(t), service.NewDIDCommMsgMap(&issuecredential.ProposeCredentialV2{
			Type: issuecredential.ProposeCredentialMsgTypeV2,
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

		arg, options, err := rfc0593.ReplayOffer(agent(t), service.NewDIDCommMsgMap(&issuecredential.OfferCredentialV2{
			Type: issuecredential.OfferCredentialMsgTypeV2,
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
		require.Equal(t, expected.Options, options)

		opt, ok := arg.(issuecredential.Opt)
		require.True(t, ok)

		md := &issuecredential.MetaData{}
		opt(md)

		require.NotEmpty(t, md.RequestCredentialV2())
		require.Equal(t,
			expected,
			extractPayload(t,
				rfc0593.ProofVCDetailFormat, md.RequestCredentialV2().Formats, md.RequestCredentialV2().RequestsAttach),
		)
	})

	t.Run("error if VC is malformed", func(t *testing.T) {
		spec := randomCredSpec(t)
		spec.Template = nil

		_, _, err := rfc0593.ReplayOffer(agent(t), service.NewDIDCommMsgMap(&issuecredential.OfferCredentialV2{
			Type: issuecredential.OfferCredentialMsgTypeV2,
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

			arg, options, err := rfc0593.IssueCredential(agent, service.NewDIDCommMsgMap(&issuecredential.RequestCredentialV2{
				Type: issuecredential.RequestCredentialMsgTypeV2,
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
			require.Equal(t, spec.Options, options)

			opt, ok := arg.(issuecredential.Opt)
			require.True(t, ok)

			md := &issuecredential.MetaData{}
			opt(md)

			require.NotEmpty(t, md.IssueCredentialV2())
			require.NotEmpty(t, md.IssueCredentialV2().CredentialsAttach)

			raw, err := md.IssueCredentialV2().CredentialsAttach[0].Data.Fetch()
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

			arg, options, err := rfc0593.IssueCredential(agent, service.NewDIDCommMsgMap(&issuecredential.RequestCredentialV2{
				Type: issuecredential.RequestCredentialMsgTypeV2,
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
			require.Equal(t, spec.Options, options)

			opt, ok := arg.(issuecredential.Opt)
			require.True(t, ok)

			md := &issuecredential.MetaData{}
			opt(md)

			require.NotEmpty(t, md.IssueCredentialV2())
			require.NotEmpty(t, md.IssueCredentialV2().CredentialsAttach)

			raw, err := md.IssueCredentialV2().CredentialsAttach[0].Data.Fetch()
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

		_, _, err := rfc0593.IssueCredential(agent(t), service.NewDIDCommMsgMap(&issuecredential.RequestCredentialV2{
			Type: issuecredential.RequestCredentialMsgTypeV2,
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

		_, _, err := rfc0593.IssueCredential(agent(t), service.NewDIDCommMsgMap(&issuecredential.RequestCredentialV2{
			Type: issuecredential.RequestCredentialMsgTypeV2,
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
			sp:     mem.NewProvider(),
		}

		_, _, err := rfc0593.IssueCredential(provider, service.NewDIDCommMsgMap(&issuecredential.RequestCredentialV2{
			Type: issuecredential.RequestCredentialMsgTypeV2,
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

func TestVerifyCredential(t *testing.T) {
	t.Run("verifies the credential", func(t *testing.T) {
		agent := agent(t)
		spec := randomCredSpec(t)
		name := uuid.New().String()
		attachID := uuid.New().String()
		msg := service.NewDIDCommMsgMap(&issuecredential.IssueCredentialV2{
			Type: issuecredential.IssueCredentialMsgTypeV2,
			Formats: []issuecredential.Format{{
				AttachID: attachID,
				Format:   rfc0593.ProofVCFormat,
			}},
			CredentialsAttach: []decorator.Attachment{{
				ID: attachID,
				Data: decorator.AttachmentData{
					JSON: newVCWithProof(t, agent, spec),
				},
			}},
		})
		msg.SetID(uuid.New().String())

		arg, err := rfc0593.VerifyCredential(agent, spec.Options, name, msg)
		require.NoError(t, err)

		opt, ok := arg.(issuecredential.Opt)
		require.True(t, ok)

		md := &issuecredential.MetaData{}
		opt(md)

		require.Len(t, md.CredentialNames(), 1)
		require.Equal(t, name, md.CredentialNames()[0])
	})

	t.Run("fails if credential has no proof", func(t *testing.T) {
		// TODO - enable when ParseCredential is fixed: https://github.com/hyperledger/aries-framework-go/issues/2799
		t.Skip()
		agent := agent(t)
		attachID := uuid.New().String()
		msg := service.NewDIDCommMsgMap(&issuecredential.IssueCredentialV2{
			Type: issuecredential.IssueCredentialMsgTypeV2,
			Formats: []issuecredential.Format{{
				AttachID: attachID,
				Format:   rfc0593.ProofVCFormat,
			}},
			CredentialsAttach: []decorator.Attachment{{
				ID: attachID,
				Data: decorator.AttachmentData{
					JSON: newVC(t),
				},
			}},
		})
		msg.SetID(uuid.New().String())

		_, err := rfc0593.VerifyCredential(agent, nil, uuid.New().String(), msg)
		require.NoError(t, err)
	})
}

func marshal(t *testing.T, v interface{}) []byte {
	t.Helper()

	raw, err := json.Marshal(v)
	require.NoError(t, err)

	return raw
}

type options struct {
	protoStateStorageProvider storage.Provider
}

type option func(*options)

func withProtoStateStorageProvider(p storage.Provider) option {
	return func(o *options) {
		o.protoStateStorageProvider = p
	}
}

func agent(t *testing.T, o ...option) rfc0593.Provider {
	t.Helper()

	opts := &options{
		protoStateStorageProvider: mem.NewProvider(),
	}

	for i := range o {
		o[i](opts)
	}

	a, err := aries.New(
		aries.WithStoreProvider(mem.NewProvider()),
		aries.WithProtocolStateStoreProvider(opts.protoStateStorageProvider),
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

func newVCWithProof(t *testing.T, agent rfc0593.Provider, spec *rfc0593.CredentialSpec) *verifiable.Credential {
	t.Helper()

	keyID, kh, err := agent.KMS().Create(kms.ED25519Type)
	require.NoError(t, err)

	keyBytes, err := agent.KMS().ExportPubKeyBytes(keyID)
	require.NoError(t, err)

	_, verificationMethod := fingerprint.CreateDIDKeyByCode(fingerprint.ED25519PubKeyMultiCodec, keyBytes)

	suiteSigner := suite.NewCryptoSigner(agent.Crypto(), kh)

	vc, err := verifiable.ParseCredential(
		spec.Template,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(agent.JSONLDDocumentLoader()),
	)
	require.NoError(t, err)

	created, err := time.Parse(time.RFC3339, spec.Options.Created)
	require.NoError(t, err)

	err = vc.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
		SignatureType:           spec.Options.ProofType,
		Suite:                   ed25519signature2018.New(suite.WithSigner(suiteSigner)),
		SignatureRepresentation: verifiable.SignatureJWS,
		Created:                 &created,
		VerificationMethod:      verificationMethod,
		Challenge:               spec.Options.Challenge,
		Domain:                  spec.Options.Domain,
		Purpose:                 spec.Options.ProofPurpose,
	}, jsonld.WithDocumentLoader(agent.JSONLDDocumentLoader()))
	require.NoError(t, err)

	return vc
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
			ProofType:    ed25519signature2018.SignatureType,
		},
	}
}

type mockProvider struct {
	loader ld.DocumentLoader
	km     kms.KeyManager
	cr     crypto.Crypto
	sp     storage.Provider
	vdr    vdr.Registry
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

func (m *mockProvider) ProtocolStateStorageProvider() storage.Provider {
	return m.sp
}

func (m *mockProvider) VDRegistry() vdr.Registry {
	return m.vdr
}
