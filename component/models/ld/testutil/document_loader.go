/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package testutil

import (
	_ "embed" //nolint:gci // required for go:embed
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	ldcontext "github.com/hyperledger/aries-framework-go/component/models/ld/context"
	"github.com/hyperledger/aries-framework-go/component/models/ld/documentloader"
	mockldstore "github.com/hyperledger/aries-framework-go/component/models/ld/mock"
	"github.com/hyperledger/aries-framework-go/component/models/ld/processor"
	ldstore "github.com/hyperledger/aries-framework-go/component/models/ld/store"
)

// nolint:gochecknoglobals // required for go:embed
var (
	//go:embed contexts/third_party/w3c-ccg.github.io/citizenship_v1.jsonld
	citizenship []byte
	//go:embed contexts/third_party/w3c-ccg.github.io/revocation-list-2021.jsonld
	revocationList2021 []byte
	//go:embed contexts/third_party/w3.org/odrl.jsonld
	odrl []byte
	//go:embed contexts/third_party/w3.org/credentials-examples_v1.jsonld
	credentialExamples []byte
	//go:embed contexts/third_party/trustbloc.github.io/trustbloc-examples_v1.jsonld
	vcExamples []byte
	//go:embed contexts/third_party/trustbloc.github.io/trustbloc-authorization-credential_v1.jsonld
	authCred []byte
	//go:embed contexts/third_party/w3id.org/data-integrity-v1.jsonld
	dataIntegrity []byte
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
	{
		URL:         "https://w3c-ccg.github.io/vc-revocation-list-2021/contexts/v1.jsonld",
		DocumentURL: "https://raw.githubusercontent.com/w3c-ccg/vc-status-list-2021/343b8b59cddba4525e1ef355356ae760fc75904e/contexts/v1.jsonld", //nolint:lll
		Content:     revocationList2021,
	},
	{
		URL:     "https://w3id.org/security/data-integrity/v1",
		Content: dataIntegrity,
	},
}

// WithDocumentLoader returns an option with a custom JSON-LD document loader preloaded with embedded contexts.
func WithDocumentLoader(t *testing.T) processor.Opts {
	t.Helper()

	loader, err := createTestDocumentLoader()
	require.NoError(t, err)

	return processor.WithDocumentLoader(loader)
}

// DocumentLoader returns JSON-LD document loader preloaded with embedded contexts and provided extra contexts.
func DocumentLoader(extraContexts ...ldcontext.Document) (*documentloader.DocumentLoader, error) {
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

func createTestDocumentLoader(extraContexts ...ldcontext.Document) (*documentloader.DocumentLoader, error) {
	contexts := append(testContexts, extraContexts...)

	p := &mockProvider{
		ContextStore:        mockldstore.NewMockContextStore(),
		RemoteProviderStore: mockldstore.NewMockRemoteProviderStore(),
	}

	loader, err := documentloader.NewDocumentLoader(p, documentloader.WithExtraContexts(contexts...))
	if err != nil {
		return nil, fmt.Errorf("create document loader: %w", err)
	}

	return loader, nil
}
