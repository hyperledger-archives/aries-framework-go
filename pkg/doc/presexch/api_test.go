/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presexch_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	jld "github.com/hyperledger/aries-framework-go/pkg/doc/jsonld"
	. "github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
)

func TestPresentationDefinition_Match(t *testing.T) {
	t.Run("match one credential", func(t *testing.T) {
		uri := randomURI()
		expected := newVC([]string{uri})
		defs := &PresentationDefinition{
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: uri,
				}},
			}},
		}

		matched, err := defs.Match(newVP(t,
			&PresentationSubmission{DescriptorMap: []*InputDescriptorMapping{{
				ID:   defs.InputDescriptors[0].ID,
				Path: "$.verifiableCredential[0]",
			}}},
			expected,
		), WithCredentialOptions(verifiable.WithJSONLDDocumentLoader(jsonldContextLoader(t, uri))))
		require.NoError(t, err)
		require.Len(t, matched, 1)
		result, ok := matched[defs.InputDescriptors[0].ID]
		require.True(t, ok)
		require.Equal(t, expected.ID, result.ID)
	})

	t.Run("match one signed credential", func(t *testing.T) {
		uri := randomURI()
		contextLoader := jsonldContextLoader(t, uri)
		agent := newAgent(t)
		expected := newSignedVC(t, agent, []string{uri}, contextLoader)
		defs := &PresentationDefinition{
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: uri,
				}},
			}},
		}

		matched, err := defs.Match(
			newVP(t,
				&PresentationSubmission{DescriptorMap: []*InputDescriptorMapping{{
					ID:   defs.InputDescriptors[0].ID,
					Path: "$.verifiableCredential[0]",
				}}},
				expected,
			),
			WithCredentialOptions(
				verifiable.WithJSONLDDocumentLoader(contextLoader),
				verifiable.WithPublicKeyFetcher(verifiable.NewVDRKeyResolver(agent.VDRegistry()).PublicKeyFetcher()),
			),
		)
		require.NoError(t, err)
		require.Len(t, matched, 1)
		result, ok := matched[defs.InputDescriptors[0].ID]
		require.True(t, ok)
		require.Equal(t, expected.ID, result.ID)
	})

	t.Run("error if vp does not have the right context", func(t *testing.T) {
		uri := randomURI()
		defs := &PresentationDefinition{
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: uri,
				}},
			}},
		}

		vp := newVP(t,
			&PresentationSubmission{DescriptorMap: []*InputDescriptorMapping{{
				ID:   defs.InputDescriptors[0].ID,
				Path: "$.verifiableCredential[0]",
			}}},
			newVC([]string{uri}),
		)

		vp.Context = []string{"https://www.w3.org/2018/credentials/v1"}

		_, err := defs.Match(vp, WithCredentialOptions(verifiable.WithJSONLDDocumentLoader(jsonldContextLoader(t, uri))))
		require.Error(t, err)
	})

	t.Run("error if vp does not have the right type", func(t *testing.T) {
		uri := randomURI()
		defs := &PresentationDefinition{
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: uri,
				}},
			}},
		}

		vp := newVP(t,
			&PresentationSubmission{DescriptorMap: []*InputDescriptorMapping{{
				ID:   defs.InputDescriptors[0].ID,
				Path: "$.verifiableCredential[0]",
			}}},
			newVC([]string{uri}),
		)

		vp.Type = []string{"VerifiablePresentation"}

		_, err := defs.Match(vp, WithCredentialOptions(verifiable.WithJSONLDDocumentLoader(jsonldContextLoader(t, uri))))
		require.Error(t, err)
	})

	t.Run("error if descriptor_map has an invalid ID", func(t *testing.T) {
		uri := randomURI()
		defs := &PresentationDefinition{
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: uri,
				}},
			}},
		}

		_, err := defs.Match(newVP(t,
			&PresentationSubmission{DescriptorMap: []*InputDescriptorMapping{{
				ID:   "INVALID",
				Path: "$.verifiableCredential[0]",
			}}},
			newVC([]string{uri}),
		), WithCredentialOptions(verifiable.WithJSONLDDocumentLoader(jsonldContextLoader(t, uri))))
		require.Error(t, err)
	})

	t.Run("error if jsonpath in descriptor_map points to a nonexistent element", func(t *testing.T) {
		uri := randomURI()
		defs := &PresentationDefinition{
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: uri,
				}},
			}},
		}

		_, err := defs.Match(newVP(t,
			&PresentationSubmission{DescriptorMap: []*InputDescriptorMapping{{
				ID:   defs.InputDescriptors[0].ID,
				Path: "$.verifiableCredential[1]",
			}}}, nil,
		), WithCredentialOptions(verifiable.WithJSONLDDocumentLoader(jsonldContextLoader(t, uri))))
		require.Error(t, err)
	})

	t.Run("error if cannot parse credential", func(t *testing.T) {
		uri := randomURI()
		defs := &PresentationDefinition{
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: uri,
				}},
			}},
		}

		_, err := defs.Match(newVP(t,
			&PresentationSubmission{DescriptorMap: []*InputDescriptorMapping{{
				ID:   defs.InputDescriptors[0].ID,
				Path: "$.verifiableCredential[0]",
			}}}, newVC([]string{uri}),
		))
		require.Error(t, err)
	})

	t.Run("error if embedded credential has a type different than the input descriptor schema uri", func(t *testing.T) {
		uri := randomURI()
		defs := &PresentationDefinition{
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: uri,
				}},
			}},
		}

		diffURI := randomURI()
		require.NotEqual(t, uri, diffURI)

		_, err := defs.Match(newVP(t,
			&PresentationSubmission{DescriptorMap: []*InputDescriptorMapping{{
				ID:   defs.InputDescriptors[0].ID,
				Path: "$.verifiableCredential[0]",
			}}},
			newVC([]string{diffURI}),
		), WithCredentialOptions(verifiable.WithJSONLDDocumentLoader(jsonldContextLoader(t, diffURI))))
		require.Error(t, err)
	})

	t.Run("error when missing required credential", func(t *testing.T) {
		uriOne := randomURI()
		uriTwo := randomURI()
		defs := &PresentationDefinition{
			InputDescriptors: []*InputDescriptor{
				{
					ID: uuid.New().String(),
					Schema: []*Schema{{
						URI: uriOne,
					}},
				},
				{
					ID: uuid.New().String(),
					Schema: []*Schema{{
						URI: uriTwo,
					}},
				},
			},
		}

		_, err := defs.Match(newVP(t,
			&PresentationSubmission{DescriptorMap: []*InputDescriptorMapping{{
				ID:   defs.InputDescriptors[0].ID,
				Path: "$.verifiableCredential[0]",
			}}},
			newVC([]string{uriOne}),
		), WithCredentialOptions(verifiable.WithJSONLDDocumentLoader(jsonldContextLoader(t, uriOne))))
		require.Error(t, err)
	})

	t.Run("error if embedded credential has a type different than the input descriptor schema uri", func(t *testing.T) {
		uri := randomURI()
		defs := &PresentationDefinition{
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: uri,
				}},
			}},
		}

		_, err := defs.Match(newVP(t,
			nil,
			newVC([]string{uri}),
		), WithCredentialOptions(verifiable.WithJSONLDDocumentLoader(jsonldContextLoader(t, uri))))
		require.Error(t, err)
	})

	t.Run("error if descriptor_map has an invalid ID", func(t *testing.T) {
		uri := randomURI()
		defs := &PresentationDefinition{
			InputDescriptors: []*InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*Schema{{
					URI: uri,
				}},
			}},
		}

		_, err := defs.Match(newVP(t,
			&PresentationSubmission{},
			newVC([]string{uri}),
		), WithCredentialOptions(verifiable.WithJSONLDDocumentLoader(jsonldContextLoader(t, uri))))
		require.Error(t, err)
	})
}

func TestE2E(t *testing.T) {
	// verifier sends their presentation definitions to the holder
	verifierDefinitions := &PresentationDefinition{
		InputDescriptors: []*InputDescriptor{{
			ID: uuid.New().String(),
			Schema: []*Schema{{
				URI: randomURI(),
			}},
		}},
	}

	// holder builds their presentation submission against the verifier's definitions
	holderCredential := newVC([]string{verifierDefinitions.InputDescriptors[0].Schema[0].URI})
	vp := newVP(t,
		&PresentationSubmission{DescriptorMap: []*InputDescriptorMapping{{
			ID:   verifierDefinitions.InputDescriptors[0].ID,
			Path: "$.verifiableCredential[0]",
		}}},
		holderCredential,
	)

	// holder sends VP over the wire to the verifier
	vpBytes := marshal(t, vp)

	// load json-ld context
	loader := jsonldContextLoader(t, verifierDefinitions.InputDescriptors[0].Schema[0].URI)

	// verifier parses the vp
	receivedVP, err := verifiable.ParsePresentation(vpBytes,
		verifiable.WithPresDisabledProofCheck(),
		verifiable.WithPresJSONLDDocumentLoader(loader))
	require.NoError(t, err)

	// verifier matches the received VP against their definitions
	matched, err := verifierDefinitions.Match(
		receivedVP,
		WithCredentialOptions(verifiable.WithJSONLDDocumentLoader(loader)))
	require.NoError(t, err)
	require.Len(t, matched, 1)
	result, ok := matched[verifierDefinitions.InputDescriptors[0].ID]
	require.True(t, ok)
	require.Equal(t, holderCredential.ID, result.ID)
}

func newVC(ctx []string) *verifiable.Credential {
	vc := &verifiable.Credential{
		Context: []string{verifiable.ContextURI},
		Types:   []string{verifiable.VCType},
		ID:      "http://test.credential.com/123",
		Issuer:  verifiable.Issuer{ID: "http://test.issuer.com"},
		Issued: &util.TimeWithTrailingZeroMsec{
			Time: time.Now(),
		},
		Subject: map[string]interface{}{
			"id": uuid.New().String(),
		},
	}

	if ctx != nil {
		vc.Context = append(vc.Context, ctx...)
	}

	return vc
}

func newSignedVC(t *testing.T,
	agent *context.Provider, ctx []string, ctxLoader ld.DocumentLoader) *verifiable.Credential {
	t.Helper()

	vc := newVC(ctx)

	keyID, kh, err := agent.KMS().Create(kms.ED25519Type)
	require.NoError(t, err)

	signer := suite.NewCryptoSigner(agent.Crypto(), kh)
	now := time.Now()

	pubKey, err := agent.KMS().ExportPubKeyBytes(keyID)
	require.NoError(t, err)

	_, verMethod := fingerprint.CreateDIDKeyByCode(fingerprint.ED25519PubKeyMultiCodec, pubKey)

	err = vc.AddLinkedDataProof(
		&verifiable.LinkedDataProofContext{
			SignatureType:           ed25519signature2018.SignatureType,
			Suite:                   ed25519signature2018.New(suite.WithSigner(signer)),
			SignatureRepresentation: verifiable.SignatureJWS,
			Created:                 &now,
			VerificationMethod:      verMethod,
			Purpose:                 "assertionMethod",
		},
		jsonld.WithDocumentLoader(ctxLoader),
	)
	require.NoError(t, err)

	return vc
}

func newVP(t *testing.T, submission *PresentationSubmission, vcs ...*verifiable.Credential) *verifiable.Presentation {
	vp, err := verifiable.NewPresentation(verifiable.WithCredentials(vcs...))
	require.NoError(t, err)

	vp.Context = append(vp.Context, "https://identity.foundation/presentation-exchange/submission/v1")
	vp.Type = append(vp.Type, "PresentationSubmission")

	if submission != nil {
		vp.CustomFields = make(map[string]interface{})
		vp.CustomFields["presentation_submission"] = toMap(t, submission)
	}

	return vp
}

func toMap(t *testing.T, v interface{}) map[string]interface{} {
	bits, err := json.Marshal(v)
	require.NoError(t, err)

	m := make(map[string]interface{})

	err = json.Unmarshal(bits, &m)
	require.NoError(t, err)

	return m
}

func marshal(t *testing.T, v interface{}) []byte {
	bits, err := json.Marshal(v)
	require.NoError(t, err)

	return bits
}

func randomURI() string {
	return fmt.Sprintf("https://my.test.context.jsonld/%s", uuid.New().String())
}

func jsonldContextLoader(t *testing.T, contextURL string) *jld.CachingDocumentLoader {
	const jsonLDContext = `{
    "@context":{
      "@version":1.1,
      "@protected":true,
      "name":"http://schema.org/name",
      "ex":"https://example.org/examples#",
      "xsd":"http://www.w3.org/2001/XMLSchema#"
   }
}`

	reader, err := ld.DocumentFromReader(strings.NewReader(jsonLDContext))
	require.NoError(t, err)

	loader := CachingJSONLDLoader()

	loader.AddDocument(contextURL, reader)

	return loader
}

func newAgent(t *testing.T) *context.Provider {
	t.Helper()

	a, err := aries.New(aries.WithStoreProvider(mem.NewProvider()))
	require.NoError(t, err)

	ctx, err := a.Context()
	require.NoError(t, err)

	return ctx
}
