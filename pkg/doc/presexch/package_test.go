/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presexch

import (
	"fmt"
	"testing"

	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"
)

type mockLoader struct {
	ctxDoc ld.RemoteDocument
	err    error
}

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
