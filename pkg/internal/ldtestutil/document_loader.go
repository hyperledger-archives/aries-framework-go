/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ldtestutil

import (
	_ "embed" //nolint:gci // required for go:embed
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext"
	ldprocessor "github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	mockldstore "github.com/hyperledger/aries-framework-go/pkg/mock/ld"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
)

// nolint:gochecknoglobals // required for go:embed
var (
	//go:embed contexts/third_party/w3c-ccg.github.io/citizenship_v1.jsonld
	citizenship []byte
	//go:embed contexts/third_party/w3.org/odrl.jsonld
	odrl []byte
	//go:embed contexts/third_party/w3.org/credentials-examples_v1.jsonld
	credentialExamples []byte
	//go:embed contexts/third_party/trustbloc.github.io/trustbloc-examples_v1.jsonld
	vcExamples []byte
	//go:embed contexts/third_party/trustbloc.github.io/trustbloc-authorization-credential_v1.jsonld
	authCred []byte
)

var testContexts = []ldcontext.Document{ //nolint:gochecknoglobals // embedded test contexts
	{
		URL:         "https://w3id.org/citizenship/v1",
		DocumentURL: "https://w3c-ccg.github.io/citizenship-vocab/contexts/citizenship-v1.jsonld",
		Content:     citizenship,
	},
	{
		URL:     "https://www.w3.org/ns/odrl.jsonld",
		Content: odrl,
	},
	{
		URL:     "https://www.w3.org/2018/credentials/examples/v1",
		Content: credentialExamples,
	},
	{
		URL:     "https://trustbloc.github.io/context/vc/examples-v1.jsonld",
		Content: vcExamples,
	},
	{
		URL:     "https://trustbloc.github.io/context/vc/authorization-credential-v1.jsonld",
		Content: authCred,
	},
}

// WithDocumentLoader returns an option with a custom JSON-LD document loader preloaded with embedded contexts.
func WithDocumentLoader(t *testing.T) ldprocessor.ProcessorOpts {
	t.Helper()

	loader, err := createTestDocumentLoader()
	require.NoError(t, err)

	return ldprocessor.WithDocumentLoader(loader)
}

// DocumentLoader returns JSON-LD document loader preloaded with embedded contexts and provided extra contexts.
func DocumentLoader(extraContexts ...ldcontext.Document) (*ld.DocumentLoader, error) {
	return createTestDocumentLoader(extraContexts...)
}

// Contexts returns test JSON-LD contexts.
func Contexts() []ldcontext.Document {
	return testContexts
}

type mockProvider struct {
	ContextStore        ldstore.ContextStore
	RemoteProviderStore ldstore.RemoteProviderStore
}

func (m *mockProvider) JSONLDContextStore() ldstore.ContextStore {
	return m.ContextStore
}

func (m *mockProvider) JSONLDRemoteProviderStore() ldstore.RemoteProviderStore {
	return m.RemoteProviderStore
}

func createTestDocumentLoader(extraContexts ...ldcontext.Document) (*ld.DocumentLoader, error) {
	contexts := append(testContexts, extraContexts...)

	p := &mockProvider{
		ContextStore:        mockldstore.NewMockContextStore(),
		RemoteProviderStore: mockldstore.NewMockRemoteProviderStore(),
	}

	loader, err := ld.NewDocumentLoader(p, ld.WithExtraContexts(contexts...))
	if err != nil {
		return nil, fmt.Errorf("create document loader: %w", err)
	}

	return loader, nil
}
