/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ldtestutil

import (
	"testing"

	ldcontext "github.com/hyperledger/aries-framework-go/component/models/ld/context"
	"github.com/hyperledger/aries-framework-go/component/models/ld/documentloader"
	"github.com/hyperledger/aries-framework-go/component/models/ld/processor"
	"github.com/hyperledger/aries-framework-go/component/models/ld/testutil"
)

// WithDocumentLoader returns an option with a custom JSON-LD document loader preloaded with embedded contexts.
func WithDocumentLoader(t *testing.T) processor.Opts {
	return testutil.WithDocumentLoader(t)
}

// DocumentLoader returns JSON-LD document loader preloaded with embedded contexts and provided extra contexts.
func DocumentLoader(extraContexts ...ldcontext.Document) (*documentloader.DocumentLoader, error) {
	return testutil.DocumentLoader(extraContexts...)
}

// Contexts returns test JSON-LD contexts.
func Contexts() []ldcontext.Document {
	return testutil.Contexts()
}
