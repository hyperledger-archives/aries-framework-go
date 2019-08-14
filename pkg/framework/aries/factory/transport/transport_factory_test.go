/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package transport

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewProviderFactory(t *testing.T) {
	f := NewProviderFactory()
	require.Empty(t, f.CreateOutboundTransport())
}
