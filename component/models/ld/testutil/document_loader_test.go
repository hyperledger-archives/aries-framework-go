/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package testutil_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/models/ld/testutil"
)

func TestWithDocumentLoader(t *testing.T) {
	opt := testutil.WithDocumentLoader(t)
	require.NotNil(t, opt)
}

func TestDocumentLoader(t *testing.T) {
	loader, err := testutil.DocumentLoader()
	require.NotNil(t, loader)
	require.NoError(t, err)
}
