/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presexch

import (
	_ "embed"
	"fmt"
	"testing"

	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"

	ldcontext "github.com/hyperledger/aries-framework-go/component/models/ld/context"
	ldtestutil "github.com/hyperledger/aries-framework-go/component/models/ld/testutil"
	"github.com/hyperledger/aries-framework-go/component/models/verifiable"
)

type mockLoader struct {
	ctxDoc ld.RemoteDocument
	err    error
}

// nolint:gochecknoglobals // required for go:embed
var (
	//go:embed testdata/contexts/mdl-v1.jsonld
	mDLv1JSONLD []byte
	//go:embed testdata/contexts/mdl-broken.jsonld
	mDLBroken []byte
)

func (ml *mockLoader) LoadDocument(url string) (*ld.RemoteDocument, error) {
	return &ml.ctxDoc, ml.err
}

func TestGetContext(t *testing.T) {
	t.Run("fail to load ctx", func(t *testing.T) {
		errLoader := mockLoader{err: fmt.Errorf("context load error")}

		ctxOut, err := getContext("foo", &errLoader)
		require.Error(t, err)
		require.Nil(t, ctxOut)
		require.Contains(t, err.Error(), "context load error")
	})

	t.Run("data wrong format", func(t *testing.T) {
		badTypeLoader := mockLoader{ctxDoc: ld.RemoteDocument{Document: "foo"}}

		ctxOut, err := getContext("foo", &badTypeLoader)
		require.Error(t, err)
		require.Nil(t, ctxOut)
		require.Contains(t, err.Error(), "expects jsonld document")
	})

	t.Run("missing @context field", func(t *testing.T) {
		missingCtxLoader := mockLoader{ctxDoc: ld.RemoteDocument{Document: map[string]interface{}{
			"foo": "bar",
		}}}

		ctxOut, err := getContext("foo", &missingCtxLoader)
		require.Error(t, err)
		require.Nil(t, ctxOut)
		require.Contains(t, err.Error(), "@context field not found")
	})
}

func Test_mDLNestedCtx(t *testing.T) {
	schemas := []*Schema{{
		URI: "https://example.org/examples#mDL",
	}}

	creds := []*verifiable.Credential{
		{
			Context: []string{
				verifiable.ContextURI,
				"https://trustbloc.github.io/context/vc/examples/mdl-v1.jsonld",
			},
			Types: []string{verifiable.VCType, "mDL"},
		},
	}

	t.Run("success", func(t *testing.T) {
		docLoader, err := ldtestutil.DocumentLoader(ldcontext.Document{
			URL:     "https://trustbloc.github.io/context/vc/examples/mdl-v1.jsonld",
			Content: mDLv1JSONLD,
		})

		require.NoError(t, err)

		matched := filterSchema(schemas, creds, docLoader)
		require.Len(t, matched, 1)
	})

	t.Run("failure: fail to parse child ctx", func(t *testing.T) {
		docLoader, err := ldtestutil.DocumentLoader(ldcontext.Document{
			URL:     "https://trustbloc.github.io/context/vc/examples/mdl-v1.jsonld",
			Content: mDLBroken,
		})
		require.NoError(t, err)

		matched := filterSchema(schemas, creds, docLoader)
		require.Len(t, matched, 0)
	})
}
