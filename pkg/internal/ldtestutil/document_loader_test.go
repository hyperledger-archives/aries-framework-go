/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ldtestutil_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/internal/ldtestutil"
)

func TestWithDocumentLoader(t *testing.T) {
	opt := ldtestutil.WithDocumentLoader(t)
	require.NotNil(t, opt)
}

func TestDocumentLoader(t *testing.T) {
	loader, err := ldtestutil.DocumentLoader()
	require.NotNil(t, loader)
	require.NoError(t, err)
}
