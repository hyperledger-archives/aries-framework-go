/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jsonld

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewVerifier(t *testing.T) {
	loader := NewDefaultCachingDocumentLoader()
	_, err := loader.LoadDocument("https://www.w3.org/2018/credentials/v1")
	require.Error(t, err, "network should be disabled")

	rLoader := NewCachingDocumentLoaderWithRemote()
	require.NotEmpty(t, rLoader)
}
