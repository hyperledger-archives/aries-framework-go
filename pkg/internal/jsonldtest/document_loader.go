/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jsonldtest

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jsonld"
	jld "github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
)

// WithDocumentLoader returns an option with a custom JSON-LD document loader preloaded with embedded contexts.
func WithDocumentLoader(t *testing.T) jld.ProcessorOpts {
	t.Helper()

	loader, err := jsonld.NewDocumentLoader(mockstorage.NewMockStoreProvider(),
		jsonld.WithContextFS(jsonld.EmbedFS),
		jsonld.WithContexts(jsonld.EmbedContexts...),
	)
	require.NoError(t, err)

	return jld.WithDocumentLoader(loader)
}

// DocumentLoader returns JSON-LD document loader preloaded with embedded contexts and provided extra contexts.
func DocumentLoader(extraContexts ...jsonld.ContextDocument) (*jsonld.DocumentLoader, error) {
	loader, err := jsonld.NewDocumentLoader(mockstorage.NewMockStoreProvider(),
		jsonld.WithContextFS(jsonld.EmbedFS),
		jsonld.WithContexts(append(jsonld.EmbedContexts, extraContexts...)...),
	)
	if err != nil {
		return nil, err
	}

	return loader, nil
}
