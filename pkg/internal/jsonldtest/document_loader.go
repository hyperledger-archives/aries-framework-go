/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jsonldtest

import (
	_ "embed" //nolint:gci // required for go:embed
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jsonld"
	jld "github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
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
)

var testContexts = []jsonld.ContextDocument{ //nolint:gochecknoglobals // embedded test contexts
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
}

// WithDocumentLoader returns an option with a custom JSON-LD document loader preloaded with embedded contexts.
func WithDocumentLoader(t *testing.T) jld.ProcessorOpts {
	t.Helper()

	loader, err := createTestDocumentLoader()
	require.NoError(t, err)

	return jld.WithDocumentLoader(loader)
}

// DocumentLoader returns JSON-LD document loader preloaded with embedded contexts and provided extra contexts.
func DocumentLoader(extraContexts ...jsonld.ContextDocument) (*jsonld.DocumentLoader, error) {
	return createTestDocumentLoader(extraContexts...)
}

func createTestDocumentLoader(extraContexts ...jsonld.ContextDocument) (*jsonld.DocumentLoader, error) {
	contexts := append(testContexts, extraContexts...)

	loader, err := jsonld.NewDocumentLoader(mem.NewProvider(),
		jsonld.WithExtraContexts(contexts...),
	)
	if err != nil {
		return nil, fmt.Errorf("create document loader: %w", err)
	}

	return loader, nil
}

// Contexts returns test JSON-LD contexts.
func Contexts() []jsonld.ContextDocument {
	return testContexts
}
