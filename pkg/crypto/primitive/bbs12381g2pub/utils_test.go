/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_pokPayload(t *testing.T) {
	payload := newPoKPayload(4, []int{0, 2})
	require.Equal(t, 3, payload.lenInBytes())

	bytes := payload.toBytes()
	require.Len(t, bytes, 3)

	payloadParsed, err := parsePoKPayload(bytes)
	require.NoError(t, err)
	require.Equal(t, payload, payloadParsed)

	payloadParsed, err = parsePoKPayload([]byte{})
	require.Error(t, err)
	require.Nil(t, payloadParsed)
}
