/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	_ "embed" //nolint:gci // required for go:embed
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext"
	mockldstore "github.com/hyperledger/aries-framework-go/pkg/mock/ld"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
)

// nolint:gochecknoglobals // embedded test contexts
var (
	//go:embed contexts/credentials-examples_v1.jsonld
	credentialExamples []byte
	//go:embed contexts/examples_v1.jsonld
	vcExamples []byte
	//go:embed contexts/odrl.jsonld
	odrl []byte
	//go:embed contexts/citizenship_v1.jsonld
	citizenship []byte
	//go:embed contexts/governance.jsonld
	governance []byte
	//go:embed contexts/lds-jws2020-v1.jsonld
	jws2020 []byte
)

// DocumentLoader returns a document loader with preloaded test contexts.
func DocumentLoader(t *testing.T) *ld.DocumentLoader {
	t.Helper()

	ldStore := &mockLDStoreProvider{
		ContextStore:        mockldstore.NewMockContextStore(),
		RemoteProviderStore: mockldstore.NewMockRemoteProviderStore(),
	}

	loader, err := ld.NewDocumentLoader(ldStore,
		ld.WithExtraContexts(
			ldcontext.Document{
				URL:     "https://www.w3.org/2018/credentials/examples/v1",
				Content: credentialExamples,
			},
			ldcontext.Document{
				URL:     "https://trustbloc.github.io/context/vc/examples-v1.jsonld",
				Content: vcExamples,
			},
			ldcontext.Document{
				URL:     "https://www.w3.org/ns/odrl.jsonld",
				Content: odrl,
			},
			ldcontext.Document{
				URL:         "https://w3id.org/citizenship/v1",
				DocumentURL: "https://w3c-ccg.github.io/citizenship-vocab/contexts/citizenship-v1.jsonld",
				Content:     citizenship,
			},
			ldcontext.Document{
				URL:     "https://trustbloc.github.io/context/governance/context.jsonld",
				Content: governance,
			},
			ldcontext.Document{
				URL:     "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json",
				Content: jws2020,
			},
		),
	)
	require.NoError(t, err)

	return loader
}

type mockLDStoreProvider struct {
	ContextStore        ldstore.ContextStore
	RemoteProviderStore ldstore.RemoteProviderStore
}

func (p *mockLDStoreProvider) JSONLDContextStore() ldstore.ContextStore {
	return p.ContextStore
}

func (p *mockLDStoreProvider) JSONLDRemoteProviderStore() ldstore.RemoteProviderStore {
	return p.RemoteProviderStore
}
